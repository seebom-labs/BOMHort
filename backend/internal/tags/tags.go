// Package tags normalises the free-form grouping labels attached to an SBOM.
//
// Tags (#357) group projects along an axis orthogonal to the ownership triple:
// "sandbox-applications", "graduated", "team-platform". They deliberately say
// nothing about where a workload runs, which is what makes them usable on
// catalogue-style instances that have no cluster at all.
//
// Tags group projects, they do not replace them: an SBOM tagged
// "sandbox-applications" keeps its own project, so a project with three SBOMs
// stays one project and merely gains a grouping label.
//
// Every entry point (TAGS env, per-bucket config, ?tags= upload parameter,
// PATCH) funnels through Normalize here, so a tag typed with stray whitespace
// or different casing in one place still matches the same tag elsewhere —
// otherwise "Sandbox-Applications" and "sandbox-applications" would silently
// become two groups and every filter would return half the data.
package tags

import (
	"sort"
	"strings"
)

// MaxLen caps a single tag. Tags are labels, not descriptions; the limit stops
// an accidental paste from becoming an unusable filter value.
const MaxLen = 64

// MaxCount caps how many tags one SBOM may carry. Generous enough for real
// grouping schemes, low enough that a malformed upload cannot balloon a row.
const MaxCount = 32

// Normalize cleans a raw tag list: trims whitespace, lowercases, drops empties
// and duplicates, truncates over-long entries and sorts the result.
//
// Sorting is what makes the output comparable — two uploads listing the same
// tags in different orders must produce equal rows, or dedup and tests turn
// order-sensitive for no reason.
//
// Returns nil (not an empty slice) for no tags, so an untagged SBOM stores a
// clean empty array rather than [""].
func Normalize(raw []string) []string {
	if len(raw) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))

	for _, t := range raw {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" {
			continue
		}
		if len(t) > MaxLen {
			t = t[:MaxLen]
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
		if len(out) == MaxCount {
			break
		}
	}

	if len(out) == 0 {
		return nil
	}

	sort.Strings(out)
	return out
}

// Parse splits a comma-separated tag string (the TAGS env var and the ?tags=
// upload parameter both use this form) and normalises it.
func Parse(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return Normalize(strings.Split(s, ","))
}

// Merge combines tag lists into one normalised set.
//
// Tags are additive across configuration levels rather than an override chain,
// unlike namespace/project: a bucket labelling its contents
// "sandbox-applications" does not contradict an instance-wide "cncf" label, so
// keeping both is the only answer that preserves operator intent.
func Merge(lists ...[]string) []string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	return Normalize(all)
}
