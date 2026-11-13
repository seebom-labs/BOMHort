package advisory

import (
	"sort"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

// Status vocabulary of a feed finding (advisory_status). The open states
// are findings; StatusFixed and StatusNotAffected are verdicts that close
// one. The snake_case spelling matches OpenVEX where the two overlap.
const (
	StatusAffected           = "affected"
	StatusUnderInvestigation = "under_investigation"
	StatusPendingUpstreamFix = "pending_upstream_fix"
	StatusFixNotPlanned      = "fix_not_planned"
	StatusNotAffected        = "not_affected"
	StatusFixed              = "fixed"
)

// Statuses lists the advisory_status values in the order the docs and the
// UI present them.
var Statuses = []string{
	StatusAffected, StatusUnderInvestigation, StatusPendingUpstreamFix,
	StatusFixNotPlanned, StatusNotAffected, StatusFixed,
}

// normalizeStatus maps a feed's free-text status ("pending upstream fix",
// "Fix Not Planned", "not_affected", "wont-fix") to the vocabulary above.
// An unrecognised status is "" and the range evaluation decides.
func normalizeStatus(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.NewReplacer("_", " ", "-", " ").Replace(s)
	s = strings.Join(strings.Fields(s), " ")
	switch s {
	case "affected", "vulnerable":
		return StatusAffected
	case "under investigation", "investigating", "triage":
		return StatusUnderInvestigation
	case "pending upstream fix", "pending upstream", "awaiting upstream fix":
		return StatusPendingUpstreamFix
	case "fix not planned", "wont fix", "won't fix", "will not fix", "not planned":
		return StatusFixNotPlanned
	case "not affected", "not vulnerable", "false positive":
		return StatusNotAffected
	case "fixed", "resolved", "patched":
		return StatusFixed
	}
	return ""
}

// IsOpen reports whether a status leaves the finding open.
func IsOpen(status string) bool {
	return status != StatusFixed && status != StatusNotAffected
}

// Component is where in an image a vulnerable file sits, as a feed reports
// it in affected[].ecosystem_specific.components[].
type Component struct {
	PURL         string `json:"purl,omitempty"`
	Location     string `json:"location,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Status       string `json:"status,omitempty"`
}

func str(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// components reads ecosystem_specific.components[] (or the same list under
// database_specific).
func components(a osv.Affected) []Component {
	var out []Component
	for _, m := range []map[string]interface{}{a.EcosystemSpecific, a.DatabaseSpecific} {
		list, _ := m["components"].([]interface{})
		for _, item := range list {
			c, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			comp := Component{
				PURL:         str(c, "purl"),
				Location:     str(c, "location", "path"),
				Architecture: str(c, "architecture", "arch"),
				Status:       normalizeStatus(str(c, "status")),
			}
			if comp != (Component{}) {
				out = append(out, comp)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return out
}

// declaredStatus is the status the feed states for p: a component entry for
// the same package wins over the affected-level status.
func declaredStatus(a osv.Affected, comps []Component, p purl) string {
	for _, c := range comps {
		if cp, ok := parsePURL(c.PURL); ok && cp.key == p.key && c.Status != "" {
			return c.Status
		}
	}
	for _, m := range []map[string]interface{}{a.EcosystemSpecific, a.DatabaseSpecific} {
		if s := normalizeStatus(str(m, "status")); s != "" {
			return s
		}
	}
	return ""
}

// inRange evaluates whether version is affected by entry a, following the
// OSV evaluation algorithm. ok is false when the entry cannot be evaluated
// for this package (unknown range type, no comparator, unparsable version):
// the caller then leaves the decision to osv.dev.
func inRange(a osv.Affected, p purl) (affected, ok bool) {
	for _, v := range a.Versions {
		if v == p.version {
			return true, true
		}
	}
	evaluated := len(a.Versions) > 0
	for _, r := range a.Ranges {
		var cmp compareFunc
		switch strings.ToUpper(r.Type) {
		case "SEMVER":
			cmp = compareSemver
		case "ECOSYSTEM":
			cmp = comparatorFor(p.typ)
		}
		if cmp == nil || p.version == "" {
			continue
		}
		hit, rok := evalRange(r.Events, p.version, cmp)
		if !rok {
			continue
		}
		evaluated = true
		if hit {
			return true, true
		}
	}
	return false, evaluated
}

type event struct {
	kind    int // 0 introduced, 1 fixed, 2 last_affected, 3 limit
	version string
}

// evalRange applies the events of one range to v.
func evalRange(events []osv.Event, v string, cmp compareFunc) (affected, ok bool) {
	var evs []event
	for _, e := range events {
		switch {
		case e.Introduced != "":
			evs = append(evs, event{0, e.Introduced})
		case e.Fixed != "":
			evs = append(evs, event{1, e.Fixed})
		case e.LastAffected != "":
			evs = append(evs, event{2, e.LastAffected})
		case e.Limit != "":
			evs = append(evs, event{3, e.Limit})
		}
	}
	less := func(a, b string) (int, bool) {
		if a == "0" || b == "0" {
			switch {
			case a == b:
				return 0, true
			case a == "0":
				return -1, true
			default:
				return 1, true
			}
		}
		return cmp(a, b)
	}
	sortOK := true
	sort.SliceStable(evs, func(i, j int) bool {
		c, ok := less(evs[i].version, evs[j].version)
		if !ok {
			sortOK = false
		}
		return c < 0
	})
	if !sortOK {
		return false, false
	}
	for _, e := range evs {
		c, ok := less(v, e.version)
		if !ok {
			return false, false
		}
		switch e.kind {
		case 0:
			if c >= 0 {
				affected = true
			}
		case 1:
			if c >= 0 {
				affected = false
			}
		case 2:
			if c > 0 {
				affected = false
			}
		case 3:
			if c >= 0 {
				affected = false
			}
		}
	}
	return affected, true
}

// fixedIn returns the first fixed version an affected entry names.
func fixedIn(a osv.Affected) string {
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				return e.Fixed
			}
		}
	}
	return ""
}

// identity is every id a record is known under: its id, aliases and related
// ids. Two records describe the same flaw when their identities intersect.
func identity(e osv.VulnEntry) map[string]struct{} {
	ids := make(map[string]struct{}, 1+len(e.Aliases)+len(e.Related))
	for _, id := range append(append([]string{e.ID}, e.Aliases...), e.Related...) {
		if id = strings.TrimSpace(id); id != "" {
			ids[strings.ToUpper(id)] = struct{}{}
		}
	}
	return ids
}

func intersects(a, b map[string]struct{}) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for k := range a {
		if _, ok := b[k]; ok {
			return true
		}
	}
	return false
}

// PackageKeys returns the package keys a record has affected entries for —
// what the advisory_records table is searched by.
func PackageKeys(e osv.VulnEntry) []string {
	seen := map[string]struct{}{}
	var keys []string
	for _, a := range e.Affected {
		k, _ := affectedKey(a.Package.PURL, a.Package.Ecosystem, a.Package.Name)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// PackageKey returns the key a PURL is looked up by ("" if not a PURL).
func PackageKey(p string) string {
	pp, ok := parsePURL(p)
	if !ok {
		return ""
	}
	return pp.key
}
