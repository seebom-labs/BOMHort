package advisory

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

type memStore struct {
	recs []StoredRecord
	err  error
	keys []string
}

func (m *memStore) LookupAdvisoryRecords(_ context.Context, sources, keys []string) ([]StoredRecord, error) {
	m.keys = keys
	if m.err != nil {
		return nil, m.err
	}
	want := map[string]bool{}
	for _, s := range sources {
		want[s] = true
	}
	var out []StoredRecord
	for _, r := range m.recs {
		if !want[r.Source] {
			continue
		}
		for _, k := range PackageKeys(r.Record) {
			for _, q := range keys {
				if k == q {
					out = append(out, r)
					goto next
				}
			}
		}
	next:
	}
	return out, nil
}

// wolfiRecord is a feed record in the shape the Chainguard/Wolfi feed
// publishes: its own id, the CVE under related, an ECOSYSTEM range.
func wolfiRecord(id, cve, pkg, fixed string) osv.VulnEntry {
	return osv.VulnEntry{
		ID:      id,
		Related: []string{cve},
		Affected: []osv.Affected{{
			Package: osv.AffectedPackage{Ecosystem: "Wolfi", Name: pkg, PURL: "pkg:apk/wolfi/" + pkg},
			Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: fixed}}}},
		}},
	}
}

func upstreamHit(id, cve string) osv.VulnEntry {
	return osv.VulnEntry{
		ID:       id,
		Aliases:  []string{cve},
		Summary:  "upstream summary",
		Severity: []osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}
}

var wolfi = Source{Name: "wolfi", Index: "https://feed.example/osv/all.json", Prefixes: []string{"pkg:apk/wolfi"}}

// The acceptance case: osv.dev matches the upstream range, the distro has
// backported the fix into -r2. The finding is closed, not open.
func TestMatchBackportedFixDropsUpstreamMatch(t *testing.T) {
	purl := "pkg:apk/wolfi/openssl@3.1.4-r2?arch=x86_64"
	store := &memStore{recs: []StoredRecord{{Source: "wolfi", Record: wolfiRecord("CGA-aaaa", "CVE-2026-0001", "openssl", "3.1.4-r2")}}}
	m := NewMatcher([]Source{wolfi}, store)

	got, err := m.Match(context.Background(), []string{purl}, map[string][]osv.VulnEntry{
		purl: {upstreamHit("GHSA-up", "CVE-2026-0001")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("findings = %+v, want none: the fix is backported", got)
	}
	if !reflect.DeepEqual(store.keys, []string{"apk/wolfi/openssl"}) {
		t.Errorf("looked up keys %v", store.keys)
	}
}

// Same feed, an older revision: the finding stays open and is attributed to
// the feed, built on osv.dev's entry (severity) with the feed's fixed version.
func TestMatchUnfixedRevisionKeepsFindingFromFeed(t *testing.T) {
	purl := "pkg:apk/wolfi/openssl@3.1.4-r1"
	store := &memStore{recs: []StoredRecord{{Source: "wolfi", Record: wolfiRecord("CGA-aaaa", "CVE-2026-0001", "openssl", "3.1.4-r2")}}}
	got, err := NewMatcher([]Source{wolfi}, store).Match(context.Background(), []string{purl}, map[string][]osv.VulnEntry{
		purl: {upstreamHit("GHSA-up", "CVE-2026-0001")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want one", got)
	}
	f := got[0]
	if f.Source != "wolfi" || f.Status != StatusAffected || f.Entry.ID != "GHSA-up" || f.FeedOnly {
		t.Errorf("finding = %+v", f)
	}
	if !reflect.DeepEqual(f.Entry.Aliases, []string{"CGA-aaaa", "CVE-2026-0001"}) {
		t.Errorf("aliases = %v", f.Entry.Aliases)
	}
	v := f.Vulnerability(uuid.New(), "img.json", 1)
	if v.FixedVersion != "3.1.4-r2" || v.AdvisorySource != "wolfi" || v.AdvisoryStatus != StatusAffected || v.Severity != "CRITICAL" {
		t.Errorf("row = source %q status %q fixed %q severity %q", v.AdvisorySource, v.AdvisoryStatus, v.FixedVersion, v.Severity)
	}
}

// A flaw only the distro feed knows about becomes a finding under the feed id.
func TestMatchFeedOnlyFinding(t *testing.T) {
	purl := "pkg:apk/wolfi/busybox@1.36.1-r5"
	store := &memStore{recs: []StoredRecord{{Source: "wolfi", Record: wolfiRecord("CGA-bbbb", "CVE-2026-0002", "busybox", "1.36.1-r7")}}}
	got, err := NewMatcher([]Source{wolfi}, store).Match(context.Background(), []string{purl}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Entry.ID != "CGA-bbbb" || !got[0].FeedOnly || got[0].Status != StatusAffected {
		t.Fatalf("findings = %+v", got)
	}

	// Enrich borrows osv.dev's severity through the related CVE.
	err = Enrich(context.Background(), got, func(_ context.Context, ids []string) (map[string]*osv.VulnEntry, error) {
		if !reflect.DeepEqual(ids, []string{"CVE-2026-0002"}) {
			t.Errorf("enrich asked for %v", ids)
		}
		e := upstreamHit("CVE-2026-0002", "")
		return map[string]*osv.VulnEntry{"CVE-2026-0002": &e}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[0].Entry.Severity) == 0 || got[0].Entry.Summary != "upstream summary" {
		t.Errorf("not enriched: %+v", got[0].Entry)
	}
}

// PURLs outside every feed's prefix and package keep osv.dev's result as is.
func TestMatchLeavesOtherPackagesToOSV(t *testing.T) {
	purl := "pkg:npm/lodash@4.17.20"
	hit := upstreamHit("GHSA-npm", "CVE-2020-8203")
	got, err := NewMatcher([]Source{wolfi}, &memStore{}).Match(context.Background(), []string{purl}, map[string][]osv.VulnEntry{purl: {hit}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Source != OSVSource || got[0].Status != "" || got[0].Entry.ID != "GHSA-npm" {
		t.Fatalf("findings = %+v", got)
	}
}

// The status vocabulary: an explicit vendor status is carried, not_affected
// wins over the range, and components are kept.
func TestMatchStatusVocabulary(t *testing.T) {
	rec := func(status string) osv.VulnEntry {
		return osv.VulnEntry{
			ID:      "VEN-1",
			Aliases: []string{"CVE-2026-0003"},
			Affected: []osv.Affected{{
				Package: osv.AffectedPackage{PURL: "pkg:apk/vendor/libxml2"},
				Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "2.13.0-r0"}}}},
				EcosystemSpecific: map[string]interface{}{
					"status": status,
					"components": []interface{}{map[string]interface{}{
						"purl": "pkg:apk/vendor/libxml2", "location": "/usr/lib/libxml2.so.2", "architecture": "aarch64",
					}},
				},
			}},
		}
	}
	vendor := Source{Name: "vendor", Index: "s3://feeds/vendor/all.json", Prefixes: []string{"pkg:apk/vendor"}}
	purl := "pkg:apk/vendor/libxml2@2.12.0-r0"
	cases := map[string]string{
		"pending upstream fix": StatusPendingUpstreamFix,
		"Fix Not Planned":      StatusFixNotPlanned,
		"under_investigation":  StatusUnderInvestigation,
		"not affected":         StatusNotAffected,
		"fixed":                StatusAffected, // a fix exists, this version lacks it
		"affected":             StatusAffected,
		"something new":        StatusAffected,
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			store := &memStore{recs: []StoredRecord{{Source: "vendor", Record: rec(in)}}}
			got, err := NewMatcher([]Source{vendor}, store).Match(context.Background(), []string{purl},
				map[string][]osv.VulnEntry{purl: {upstreamHit("GHSA-x", "CVE-2026-0003")}})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Status != want {
				t.Fatalf("findings = %+v, want status %s", got, want)
			}
			if got[0].Components[0].Location != "/usr/lib/libxml2.so.2" || got[0].Components[0].Architecture != "aarch64" {
				t.Errorf("components = %+v", got[0].Components)
			}
			v := got[0].Vulnerability(uuid.New(), "x.json", 1)
			if !strings.Contains(v.ComponentLocation, `"location":"/usr/lib/libxml2.so.2"`) {
				t.Errorf("component_location = %s", v.ComponentLocation)
			}
			st, ok := got[0].NotAffectedStatement(v)
			if ok != (want == StatusNotAffected) {
				t.Fatalf("VEX statement emitted = %v for %s", ok, want)
			}
			if ok && (st.Status != models.VEXStatusNotAffected || st.Author != "vendor" || st.VulnID != "GHSA-x" || st.SBOMID != v.SBOMID.String()) {
				t.Errorf("statement = %+v", st)
			}
		})
	}
}

// A feed without prefixes only adds findings: its "fixed" verdict must not
// drop osv.dev's match, but its open record merges into it.
func TestMatchNonAuthoritativeFeedOnlyAdds(t *testing.T) {
	private := Source{Name: "private", Index: "file:///feeds/all.json"}
	purl := "pkg:apk/wolfi/openssl@3.1.4-r2"
	hit := upstreamHit("GHSA-up", "CVE-2026-0001")

	fixedStore := &memStore{recs: []StoredRecord{{Source: "private", Record: wolfiRecord("PRIV-1", "CVE-2026-0001", "openssl", "3.1.4-r2")}}}
	got, _ := NewMatcher([]Source{private}, fixedStore).Match(context.Background(), []string{purl}, map[string][]osv.VulnEntry{purl: {hit}})
	if len(got) != 1 || got[0].Source != OSVSource {
		t.Fatalf("non-authoritative fixed verdict changed the finding: %+v", got)
	}

	openStore := &memStore{recs: []StoredRecord{{Source: "private", Record: wolfiRecord("PRIV-1", "CVE-2026-0001", "openssl", "3.1.4-r9")}}}
	got, _ = NewMatcher([]Source{private}, openStore).Match(context.Background(), []string{purl}, map[string][]osv.VulnEntry{purl: {hit}})
	if len(got) != 1 || got[0].Source != "private" || got[0].Entry.ID != "GHSA-up" {
		t.Fatalf("open private record not merged into the osv.dev finding: %+v", got)
	}
}

// When two feeds speak about the same flaw, the authoritative one decides.
func TestMatchAuthoritativeFeedWins(t *testing.T) {
	private := Source{Name: "private", Index: "file:///feeds/all.json"}
	purl := "pkg:apk/wolfi/openssl@3.1.4-r2"
	store := &memStore{recs: []StoredRecord{
		{Source: "private", Record: wolfiRecord("PRIV-1", "CVE-2026-0001", "openssl", "3.1.4-r9")},
		{Source: "wolfi", Record: wolfiRecord("CGA-aaaa", "CVE-2026-0001", "openssl", "3.1.4-r2")},
	}}
	got, _ := NewMatcher([]Source{private, wolfi}, store).Match(context.Background(), []string{purl}, nil)
	if len(got) != 0 {
		t.Fatalf("findings = %+v, want the authoritative fixed verdict to win", got)
	}
}

// Withdrawn records and records the comparator cannot evaluate are ignored.
func TestMatchIgnoresWithdrawnAndUnevaluable(t *testing.T) {
	purl := "pkg:apk/wolfi/openssl@3.1.4-r1"
	withdrawn := wolfiRecord("CGA-w", "CVE-2026-0009", "openssl", "3.1.4-r2")
	withdrawn.Withdrawn = "2026-10-01T00:00:00Z"
	garbage := wolfiRecord("CGA-g", "CVE-2026-0010", "openssl", "not a version")
	store := &memStore{recs: []StoredRecord{{Source: "wolfi", Record: withdrawn}, {Source: "wolfi", Record: garbage}}}
	got, _ := NewMatcher([]Source{wolfi}, store).Match(context.Background(), []string{purl}, map[string][]osv.VulnEntry{
		purl: {upstreamHit("GHSA-w", "CVE-2026-0009")},
	})
	if len(got) != 1 || got[0].Source != OSVSource {
		t.Fatalf("findings = %+v, want osv.dev's finding unchanged", got)
	}
}

// A distro release in the ecosystem must agree with the PURL's distro.
func TestMatchRespectsDistroRelease(t *testing.T) {
	rec := osv.VulnEntry{ID: "ALPINE-1", Aliases: []string{"CVE-2026-0004"}, Affected: []osv.Affected{{
		Package: osv.AffectedPackage{Ecosystem: "Alpine:v3.18", Name: "zlib"},
		Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.3-r0"}}}},
	}}}
	alpine := Source{Name: "alpine", Index: "https://feed.example/alpine/all.json", Prefixes: []string{"pkg:apk/alpine"}}
	store := &memStore{recs: []StoredRecord{{Source: "alpine", Record: rec}}}
	m := NewMatcher([]Source{alpine}, store)

	in := "pkg:apk/alpine/zlib@1.2.13-r0?distro=alpine-3.18.4"
	if got, _ := m.Match(context.Background(), []string{in}, nil); len(got) != 1 {
		t.Errorf("3.18 package: findings = %+v, want one", got)
	}
	other := "pkg:apk/alpine/zlib@1.2.13-r0?distro=alpine-3.19.1"
	if got, _ := m.Match(context.Background(), []string{other}, nil); len(got) != 0 {
		t.Errorf("3.19 package matched a 3.18 record: %+v", got)
	}
}

func TestMatchPropagatesStoreErrors(t *testing.T) {
	_, err := NewMatcher([]Source{wolfi}, &memStore{err: errors.New("boom")}).Match(context.Background(), []string{"pkg:apk/wolfi/a@1-r0"}, nil)
	if err == nil {
		t.Fatal("store error swallowed")
	}
}

func TestNewMatcherWithoutSources(t *testing.T) {
	if NewMatcher(nil, &memStore{}) != nil {
		t.Fatal("matcher without sources should be nil")
	}
}

func TestEvalRange(t *testing.T) {
	ev := func(evs ...osv.Event) []osv.Event { return evs }
	cases := []struct {
		name   string
		events []osv.Event
		v      string
		want   bool
	}{
		{"before fix", ev(osv.Event{Introduced: "0"}, osv.Event{Fixed: "1.2-r3"}), "1.2-r2", true},
		{"at fix", ev(osv.Event{Introduced: "0"}, osv.Event{Fixed: "1.2-r3"}), "1.2-r3", false},
		{"before introduced", ev(osv.Event{Introduced: "2.0-r0"}, osv.Event{Fixed: "2.1-r0"}), "1.9-r0", false},
		{"last affected", ev(osv.Event{Introduced: "0"}, osv.Event{LastAffected: "1.5-r0"}), "1.5-r0", true},
		{"after last affected", ev(osv.Event{Introduced: "0"}, osv.Event{LastAffected: "1.5-r0"}), "1.5-r1", false},
		{"two windows, second", ev(osv.Event{Introduced: "0"}, osv.Event{Fixed: "1.0-r0"}, osv.Event{Introduced: "2.0-r0"}, osv.Event{Fixed: "2.2-r0"}), "2.1-r0", true},
		{"two windows, gap", ev(osv.Event{Introduced: "0"}, osv.Event{Fixed: "1.0-r0"}, osv.Event{Introduced: "2.0-r0"}, osv.Event{Fixed: "2.2-r0"}), "1.5-r0", false},
	}
	for _, c := range cases {
		got, ok := evalRange(c.events, c.v, compareAPK)
		if !ok || got != c.want {
			t.Errorf("%s: got %v (ok %v), want %v", c.name, got, ok, c.want)
		}
	}
}

// A feed record published under the CVE itself, with no aliases, is still
// enriched: its own id is a lookup candidate.
func TestEnrichUsesTheRecordID(t *testing.T) {
	findings := []Finding{{
		PURL:     "pkg:apk/wolfi/zlib@1.3-r0",
		Entry:    osv.VulnEntry{ID: "CVE-2026-0042"},
		Source:   "wolfi",
		FeedOnly: true,
	}}
	err := Enrich(context.Background(), findings, func(_ context.Context, ids []string) (map[string]*osv.VulnEntry, error) {
		if !reflect.DeepEqual(ids, []string{"CVE-2026-0042"}) {
			t.Errorf("enrich asked for %v", ids)
		}
		e := upstreamHit("CVE-2026-0042", "")
		return map[string]*osv.VulnEntry{"CVE-2026-0042": &e}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	v := findings[0].Vulnerability(uuid.New(), "x.json", 1)
	if v.Severity != "CRITICAL" {
		t.Fatalf("severity = %q, want osv.dev's CRITICAL instead of the LOW fallback", v.Severity)
	}
}

// Stored findings are closed by today's authoritative verdicts: a published
// backport closes as fixed, a not_affected verdict closes as not_affected,
// and a finding the feed still reports as open, or knows nothing about, stays.
func TestReconcileClosesStoredFindings(t *testing.T) {
	fixedRec := wolfiRecord("CGA-fix", "CVE-2026-0001", "openssl", "3.1.4-r2")
	naRec := wolfiRecord("CGA-na", "CVE-2026-0002", "openssl", "3.1.4-r9")
	naRec.Affected[0].EcosystemSpecific = map[string]interface{}{"status": "not affected"}
	openRec := wolfiRecord("CGA-open", "CVE-2026-0003", "openssl", "3.1.4-r9")
	store := &memStore{recs: []StoredRecord{{Source: "wolfi", Record: fixedRec}, {Source: "wolfi", Record: naRec}, {Source: "wolfi", Record: openRec}}}

	purl := "pkg:apk/wolfi/openssl@3.1.4-r2?arch=x86_64"
	stored := []StoredFinding{
		{PURL: purl, VulnID: "GHSA-up1", Aliases: []string{"CVE-2026-0001"}},   // osv.dev row, now backported
		{PURL: purl, VulnID: "CGA-na"},                                         // stored under the feed id
		{PURL: purl, VulnID: "GHSA-up3", Aliases: []string{"CVE-2026-0003"}},   // still open per feed
		{PURL: purl, VulnID: "GHSA-other", Aliases: []string{"CVE-2026-9999"}}, // feed has no record
	}
	got, err := NewMatcher([]Source{wolfi}, store).Reconcile(context.Background(), stored)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"GHSA-up1": StatusFixed, "CGA-na": StatusNotAffected}
	if len(got) != len(want) {
		t.Fatalf("closures = %+v", got)
	}
	for _, c := range got {
		if want[c.VulnID] != c.Status || c.Source != "wolfi" {
			t.Errorf("closure = %+v", c)
		}
	}
}

// A feed that is not authoritative for the PURL closes nothing.
func TestReconcileNeedsAuthority(t *testing.T) {
	private := Source{Name: "private", Index: "file:///feeds/all.json"}
	store := &memStore{recs: []StoredRecord{{Source: "private", Record: wolfiRecord("P-1", "CVE-2026-0001", "openssl", "3.1.4-r2")}}}
	got, err := NewMatcher([]Source{private}, store).Reconcile(context.Background(), []StoredFinding{
		{PURL: "pkg:apk/wolfi/openssl@3.1.4-r2", VulnID: "GHSA-up1", Aliases: []string{"CVE-2026-0001"}},
	})
	if err != nil || len(got) != 0 {
		t.Fatalf("closures = %+v, err %v", got, err)
	}
}
