package advisory

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// StoredRecord is one feed record as the store returns it.
type StoredRecord struct {
	Source string
	Record osv.VulnEntry
}

// RecordStore looks up the records of the given feeds that have an affected
// entry for any of the package keys.
type RecordStore interface {
	LookupAdvisoryRecords(ctx context.Context, sources, keys []string) ([]StoredRecord, error)
}

// Finding is one (PURL, flaw) pair after feeds and osv.dev were combined.
type Finding struct {
	PURL string
	// Entry is the record the row is built from: the osv.dev entry when
	// osv.dev knows the flaw (it carries severity and summary), else the
	// feed record. Its Aliases already include the feed's ids.
	Entry osv.VulnEntry
	// Source is OSVSource or the name of the feed that decided the finding.
	Source string
	// Status is "" for a plain osv.dev finding, else a Status* value.
	Status string
	// FixedVersion is the feed's fixed version; "" keeps the entry's.
	FixedVersion string
	Components   []Component
	// FeedOnly marks a finding osv.dev did not report: Entry is the feed
	// record, which usually lacks severity (see Enrich).
	FeedOnly bool
}

// Matcher combines osv.dev results with the configured feeds.
type Matcher struct {
	sources []Source
	store   RecordStore
}

// NewMatcher returns a matcher, or nil when no feed is configured — callers
// then keep osv.dev's results unchanged.
func NewMatcher(sources []Source, store RecordStore) *Matcher {
	if len(sources) == 0 || store == nil {
		return nil
	}
	return &Matcher{sources: sources, store: store}
}

// Sources returns the configured feeds.
func (m *Matcher) Sources() []Source { return m.sources }

// verdict is what one feed record says about one PURL.
type verdict struct {
	source     string
	authority  int
	record     osv.VulnEntry
	ids        map[string]struct{}
	status     string
	fixed      string
	components []Component
}

// Match returns the findings for purls. hits are osv.dev's hydrated entries
// per PURL. Rules, per PURL:
//
//   - A feed authoritative for the PURL (longest matching prefix) decides
//     every flaw it has a record of: an open status yields one finding, built
//     on osv.dev's entry for the same flaw if there is one; "fixed" and
//     "not_affected" drop osv.dev's match (a backport osv.dev cannot see).
//     A "not_affected" verdict is still returned, so the caller can record
//     it as a VEX statement authored by the feed.
//   - A feed that is not authoritative only adds: an open record becomes a
//     finding (merged into osv.dev's if osv.dev has the same flaw), a closed
//     one is ignored.
//   - osv.dev hits no feed spoke about are returned unchanged.
func (m *Matcher) Match(ctx context.Context, purls []string, hits map[string][]osv.VulnEntry) ([]Finding, error) {
	byKey, err := m.recordsByKey(ctx, purls)
	if err != nil {
		return nil, err
	}

	var out []Finding
	seen := map[string]struct{}{}
	for _, p := range purls {
		if _, dup := seen[p]; dup || p == "" {
			continue
		}
		seen[p] = struct{}{}
		pp, ok := parsePURL(p)
		var verdicts []verdict
		if ok {
			verdicts = m.verdicts(pp, p, byKey[pp.key])
		}
		out = append(out, combine(p, verdicts, hits[p])...)
	}
	return out, nil
}

// recordsByKey loads the live records of every configured feed that name
// one of the PURLs' packages, indexed by package key.
func (m *Matcher) recordsByKey(ctx context.Context, purls []string) (map[string][]StoredRecord, error) {
	keys := map[string]struct{}{}
	for _, p := range purls {
		if k := PackageKey(p); k != "" {
			keys[k] = struct{}{}
		}
	}
	byKey := map[string][]StoredRecord{}
	if len(keys) == 0 {
		return byKey, nil
	}
	names := make([]string, len(m.sources))
	for i, s := range m.sources {
		names[i] = s.Name
	}
	keyList := make([]string, 0, len(keys))
	for k := range keys {
		keyList = append(keyList, k)
	}
	sort.Strings(keyList)
	records, err := m.store.LookupAdvisoryRecords(ctx, names, keyList)
	if err != nil {
		return nil, fmt.Errorf("looking up advisory records: %w", err)
	}
	for _, r := range records {
		if r.Record.Withdrawn != "" {
			continue
		}
		for _, k := range PackageKeys(r.Record) {
			byKey[k] = append(byKey[k], r)
		}
	}
	return byKey, nil
}

// StoredFinding is a finding already in the vulnerabilities table.
type StoredFinding struct {
	PURL    string
	VulnID  string
	Aliases []string
}

// Closure is an authoritative feed's verdict that closes a stored finding:
// StatusFixed (the fix is in this version) or StatusNotAffected.
type Closure struct {
	StoredFinding
	Source   string
	Status   string
	Modified string // the deciding record's modified time, for the VEX statement
}

// Reconcile re-evaluates findings that are already stored against today's
// feed records. The insert path only ever adds rows, so without this a
// finding stored before a feed published its backport — or its
// "not affected" verdict — would stay open until a full re-scan. Only a
// feed authoritative for the PURL can close a finding, exactly as on insert.
func (m *Matcher) Reconcile(ctx context.Context, stored []StoredFinding) ([]Closure, error) {
	purls := make([]string, 0, len(stored))
	for _, f := range stored {
		purls = append(purls, f.PURL)
	}
	byKey, err := m.recordsByKey(ctx, purls)
	if err != nil {
		return nil, err
	}
	verdictsFor := map[string][]verdict{}
	var out []Closure
	for _, f := range stored {
		vs, done := verdictsFor[f.PURL]
		if !done {
			if pp, ok := parsePURL(f.PURL); ok {
				vs = m.verdicts(pp, f.PURL, byKey[pp.key])
			}
			verdictsFor[f.PURL] = vs
		}
		ids := identity(osv.VulnEntry{ID: f.VulnID, Aliases: f.Aliases})
		// verdicts are ordered authority first, so the first one about this
		// flaw is the one that decides it.
		for _, v := range vs {
			if v.authority == 0 || !intersects(v.ids, ids) {
				continue
			}
			if !IsOpen(v.status) {
				out = append(out, Closure{StoredFinding: f, Source: v.source, Status: v.status, Modified: v.record.Modified})
			}
			break
		}
	}
	return out, nil
}

// NotAffectedStatement is the VEX statement that records a not_affected
// closure for one SBOM's copy of the finding.
func (c Closure) NotAffectedStatement(v models.Vulnerability) (models.VEXStatement, bool) {
	f := Finding{PURL: c.PURL, Entry: osv.VulnEntry{ID: c.VulnID, Modified: c.Modified}, Source: c.Source, Status: c.Status}
	return f.NotAffectedStatement(v)
}

func (m *Matcher) sourceByName(name string) (Source, bool) {
	for _, s := range m.sources {
		if s.Name == name {
			return s, true
		}
	}
	return Source{}, false
}

// verdicts evaluates every record of the PURL's package, authoritative feeds
// first (longest prefix, then configuration order).
func (m *Matcher) verdicts(pp purl, raw string, recs []StoredRecord) []verdict {
	order := map[string]int{}
	for i, s := range m.sources {
		order[s.Name] = i
	}
	var out []verdict
	for _, r := range recs {
		src, ok := m.sourceByName(r.Source)
		if !ok {
			continue
		}
		v, ok := evaluate(r.Record, pp)
		if !ok {
			continue
		}
		v.source = r.Source
		v.authority = src.authority(raw)
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].authority != out[j].authority {
			return out[i].authority > out[j].authority
		}
		if order[out[i].source] != order[out[j].source] {
			return order[out[i].source] < order[out[j].source]
		}
		return out[i].record.ID < out[j].record.ID
	})
	return out
}

// evaluate reads what record e says about package p. ok is false when the
// record has no entry for p that can be evaluated.
func evaluate(e osv.VulnEntry, p purl) (verdict, bool) {
	v := verdict{record: e, ids: identity(e)}
	found := false
	for _, a := range e.Affected {
		key, release := affectedKey(a.Package.PURL, a.Package.Ecosystem, a.Package.Name)
		if key != p.key || !releaseMatches(p, release) {
			continue
		}
		comps := components(a)
		declared := declaredStatus(a, comps, p)
		hit, ok := inRange(a, p)
		noBounds := len(a.Ranges) == 0 && len(a.Versions) == 0
		var status string
		switch {
		case declared == StatusNotAffected:
			status = StatusNotAffected
		case noBounds && declared != "":
			// A status without ranges applies to every version.
			status = declared
		case !ok:
			continue
		case !hit:
			status = StatusFixed
		case declared == "" || declared == StatusFixed:
			// "fixed" with this version still in range: a fix exists,
			// this package does not have it yet.
			status = StatusAffected
		default:
			status = declared
		}
		// Several entries for one package: an open one wins, so a finding
		// is never closed by a sibling entry for another release.
		if !found || (IsOpen(status) && !IsOpen(v.status)) {
			v.status, v.fixed, v.components = status, fixedIn(a), comps
		}
		found = true
	}
	return v, found
}

// combine merges the feed verdicts and osv.dev hits of one PURL.
func combine(p string, verdicts []verdict, hits []osv.VulnEntry) []Finding {
	hitIDs := make([]map[string]struct{}, len(hits))
	for i, h := range hits {
		hitIDs[i] = identity(h)
	}
	consumed := make([]bool, len(hits))
	var decided []map[string]struct{}
	var out []Finding

	for _, v := range verdicts {
		already := false
		for _, d := range decided {
			if intersects(d, v.ids) {
				already = true
				break
			}
		}
		if already {
			continue
		}
		authoritative := v.authority > 0
		if !IsOpen(v.status) && !authoritative {
			continue
		}
		decided = append(decided, v.ids)

		match := -1
		for i := range hits {
			if !consumed[i] && intersects(hitIDs[i], v.ids) {
				consumed[i] = true
				if match < 0 {
					match = i
				}
			}
		}
		if v.status == StatusFixed {
			continue // backported: osv.dev's upstream match is dropped
		}
		f := Finding{
			PURL:         p,
			Source:       v.source,
			Status:       v.status,
			FixedVersion: v.fixed,
			Components:   v.components,
		}
		if match >= 0 {
			f.Entry = hits[match]
			f.Entry.Aliases = mergeAliases(f.Entry, v.record)
		} else {
			f.Entry = v.record
			f.Entry.Aliases = mergeAliases(v.record, osv.VulnEntry{})
			f.FeedOnly = true
		}
		out = append(out, f)
	}
	for i, h := range hits {
		if !consumed[i] {
			out = append(out, Finding{PURL: p, Entry: h, Source: OSVSource})
		}
	}
	return out
}

// mergeAliases returns base's aliases plus every id the feed record is known
// under, without base's own id. Feed records list the CVE under related, so
// it is folded in here: VEX matching and the CVE column read aliases only.
func mergeAliases(base, feed osv.VulnEntry) []string {
	set := map[string]struct{}{}
	var out []string
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || strings.EqualFold(id, base.ID) {
			return
		}
		k := strings.ToUpper(id)
		if _, ok := set[k]; ok {
			return
		}
		set[k] = struct{}{}
		out = append(out, id)
	}
	for _, id := range base.Aliases {
		add(id)
	}
	for _, id := range base.Related {
		add(id)
	}
	if feed.ID != "" {
		add(feed.ID)
		for _, id := range feed.Aliases {
			add(id)
		}
		for _, id := range feed.Related {
			add(id)
		}
	}
	sort.Strings(out)
	return out
}

// Enrich fills severity and summary of feed-only findings from osv.dev:
// feed records rarely carry a CVSS score, and without one every finding
// would classify as LOW. lookup returns hydrated osv.dev entries by id; ids
// it does not return leave the finding as the feed published it.
func Enrich(ctx context.Context, findings []Finding, lookup func(ctx context.Context, ids []string) (map[string]*osv.VulnEntry, error)) error {
	var want []string
	seen := map[string]struct{}{}
	for _, f := range findings {
		if !f.FeedOnly || len(f.Entry.Severity) > 0 {
			continue
		}
		for _, id := range enrichCandidates(f.Entry) {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				want = append(want, id)
			}
		}
	}
	if len(want) == 0 {
		return nil
	}
	got, err := lookup(ctx, want)
	if err != nil {
		return err
	}
	for i := range findings {
		f := &findings[i]
		if !f.FeedOnly || len(f.Entry.Severity) > 0 {
			continue
		}
		for _, id := range enrichCandidates(f.Entry) {
			e := got[id]
			if e == nil || len(e.Severity) == 0 && e.DatabaseSpecific["severity"] == nil {
				continue
			}
			f.Entry.Severity = e.Severity
			if f.Entry.DatabaseSpecific == nil {
				f.Entry.DatabaseSpecific = map[string]interface{}{}
			}
			if sev, ok := e.DatabaseSpecific["severity"]; ok {
				f.Entry.DatabaseSpecific["severity"] = sev
			}
			if f.Entry.Summary == "" {
				f.Entry.Summary = e.Summary
			}
			break
		}
	}
	return nil
}

// enrichCandidates lists the ids osv.dev can be asked about for a feed
// record: its own id first (a feed may publish a record under the CVE
// itself, with no aliases), then its aliases.
func enrichCandidates(e osv.VulnEntry) []string {
	var out []string
	for _, id := range append([]string{e.ID}, e.Aliases...) {
		if enrichable(id) {
			out = append(out, id)
		}
	}
	return out
}

// enrichable reports whether osv.dev can be asked for an id: CVE and GHSA
// records exist there for every ecosystem.
func enrichable(id string) bool {
	u := strings.ToUpper(id)
	return strings.HasPrefix(u, "CVE-") || strings.HasPrefix(u, "GHSA-")
}
