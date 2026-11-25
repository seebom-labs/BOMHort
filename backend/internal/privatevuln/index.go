package privatevuln

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

// idPattern matches the API gateway's vulnIDPattern so every loaded private
// advisory ID can be queried on detail and affected-projects routes.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// publicOSVPrefixes lists upstream public OSV database namespaces that a
// private advisory must never shadow or overwrite.
var publicOSVPrefixes = []string{
	"CVE-",
	"GHSA-",
	"PYSEC-",
	"GO-",
	"RUSTSEC-",
	"MAL-",
	"DSA-",
	"DLA-",
	"DTSA-",
	"USN-",
	"CGA-",
	"RHSA-",
	"RHBA-",
	"RHEA-",
	"ALSA-",
	"ALBA-",
	"ALEA-",
	"ELSA-",
	"RLSA-",
	"ALAS-",
	"MGASA-",
	"SUSE-SU-",
	"OPENSUSE-SU-",
	"OSV-",
	"BIT-",
	"CURL-CVE-",
	"PSF-",
	"RSEC-",
	"GSD-",
	"ASB-A-",
	"PUB-",
	"HSEC-",
	"OESA-",
	"UBUNTU-CVE-",
	"DEBIAN-CVE-",
	"ALPINE-CVE-",
}

// Index provides fast in-memory lookup of private vulnerability advisories
// against PURLs.
type Index struct {
	// Entries is all valid private advisories in file order.
	Entries []osv.VulnEntry
	// ActiveEntries excludes withdrawn advisories.
	ActiveEntries []osv.VulnEntry
	// byKey maps a package key ("type/namespace/name") to the affected targets.
	byKey map[string][]entryTarget
}

type entryTarget struct {
	entry    osv.VulnEntry
	affected osv.Affected
	release  string
}

func validateAdvisoryID(id string) error {
	if id == "" {
		return fmt.Errorf("missing id")
	}
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid id %q (must match ^[A-Za-z0-9._-]{1,100}$)", id)
	}
	upper := strings.ToUpper(id)
	for _, prefix := range publicOSVPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return fmt.Errorf("id %q cannot use public OSV prefix %s", id, prefix)
		}
	}
	return nil
}

// Parse decodes and indexes an OSV-format private vulnerabilities document.
// The document may be a JSON array of OSV VulnEntry objects or a JSON object
// with a "vulnerabilities" array.
//
// Validation enforces ^[A-Za-z0-9._-]{1,100}$ and rejects public OSV prefixes
// (CVE-, GHSA-, PYSEC-, GO-, RUSTSEC-, MAL-, DSA-, etc.).
func Parse(data []byte, name string) (*Index, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return &Index{byKey: make(map[string][]entryTarget)}, nil
	}

	var entries []osv.VulnEntry
	if trimmed[0] == '{' {
		var wrapper struct {
			Version         string          `json:"version"`
			Vulnerabilities []osv.VulnEntry `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(trimmed, &wrapper); err != nil {
			return nil, fmt.Errorf("failed to parse private vulnerabilities file %s: %w", name, err)
		}
		entries = wrapper.Vulnerabilities
	} else {
		if err := json.Unmarshal(trimmed, &entries); err != nil {
			return nil, fmt.Errorf("failed to parse private vulnerabilities file %s: %w", name, err)
		}
	}

	idx := &Index{
		Entries: entries,
		byKey:   make(map[string][]entryTarget),
	}

	for _, entry := range entries {
		id := strings.TrimSpace(entry.ID)
		if err := validateAdvisoryID(id); err != nil {
			return nil, fmt.Errorf("private vulnerability in %s: %w", name, err)
		}
		entry.ID = id

		// Withdrawn advisories are no longer active findings.
		if strings.TrimSpace(entry.Withdrawn) != "" {
			continue
		}
		idx.ActiveEntries = append(idx.ActiveEntries, entry)

		if len(entry.Affected) == 0 {
			log.Printf("WARNING: private vulnerability %s in %s has no affected entries and will never match", id, name)
			continue
		}

		for _, a := range entry.Affected {
			key, release := advisory.AffectedKey(a.Package.PURL, a.Package.Ecosystem, a.Package.Name)
			if key == "" {
				log.Printf("WARNING: private vulnerability %s in %s has unresolvable affected package (ecosystem=%q name=%q purl=%q)",
					id, name, a.Package.Ecosystem, a.Package.Name, a.Package.PURL)
				continue
			}
			warnUnvalidatableRanges(id, name, key, a)
			idx.byKey[key] = append(idx.byKey[key], entryTarget{
				entry:    entry,
				affected: a,
				release:  release,
			})
		}
	}

	return idx, nil
}

func warnUnvalidatableRanges(id, file, key string, a osv.Affected) {
	if len(a.Versions) == 0 && len(a.Ranges) == 0 {
		log.Printf("WARNING: private vulnerability %s (%s) in %s has no versions or ranges and will never match", id, key, file)
		return
	}
	purlType, _, _ := strings.Cut(key, "/")
	for _, r := range a.Ranges {
		rt := strings.ToUpper(r.Type)
		var cmp advisory.CompareFunc
		switch rt {
		case "SEMVER":
			cmp = comparePrivateSemver
		case "ECOSYSTEM":
			cmp = comparatorForType(purlType)
		default:
			log.Printf("WARNING: private vulnerability %s (%s) in %s uses unsupported range type %q and will not be evaluated", id, key, file, r.Type)
			continue
		}
		if len(r.Events) == 0 {
			log.Printf("WARNING: private vulnerability %s (%s) in %s has %s range with no events", id, key, file, rt)
			continue
		}
		for _, ev := range r.Events {
			for _, ver := range []string{ev.Introduced, ev.Fixed, ev.LastAffected, ev.Limit} {
				if ver == "" || ver == "0" {
					continue
				}
				if _, ok := cmp(ver, ver); !ok {
					log.Printf("WARNING: private vulnerability %s (%s) in %s has range event %q that cannot be parsed under %s", id, key, file, ver, rt)
					break
				}
			}
		}
	}
}

// Match evaluates purls against indexed private vulnerability advisories.
// It returns matching findings tagged with Source = "private".
func (idx *Index) Match(purls []string) []advisory.Finding {
	if idx == nil || len(idx.byKey) == 0 || len(purls) == 0 {
		return nil
	}

	var findings []advisory.Finding
	seen := make(map[string]struct{})

	for _, purlStr := range purls {
		p, ok := advisory.ParsePURL(purlStr)
		if !ok {
			continue
		}
		targets, ok := idx.byKey[p.Key()]
		if !ok {
			continue
		}

		for _, target := range targets {
			if !advisory.ReleaseMatches(p, target.release) {
				continue
			}
			hit, evaluated := matchAffected(target.affected, p)
			if !evaluated {
				log.Printf("WARNING: private vulnerability %s could not evaluate package %s", target.entry.ID, purlStr)
				continue
			}
			if !hit {
				continue
			}

			key := target.entry.ID + "\x00" + purlStr
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			findings = append(findings, advisory.Finding{
				PURL:         purlStr,
				Entry:        target.entry,
				Source:       "private",
				Status:       advisory.StatusAffected,
				FixedVersion: advisory.FixedIn(target.affected),
				FeedOnly:     true,
			})
		}
	}

	return findings
}

func comparatorForType(purlType string) advisory.CompareFunc {
	if cmp := advisory.ComparatorFor(purlType); cmp != nil {
		return cmp
	}
	return comparePrivateSemver
}

// matchAffected evaluates a against p using exact versions, distro comparators,
// lenient SemVer for SEMVER and non-distro ECOSYSTEM ranges, and unbounded
// matches for versionless PURLs when events only contain {"introduced":"0"}.
func matchAffected(a osv.Affected, p advisory.PURL) (hit, evaluated bool) {
	ver := p.Version()
	if ver != "" {
		for _, v := range a.Versions {
			if v == ver {
				return true, true
			}
		}
	}
	evaluated = len(a.Versions) > 0 && ver != ""

	for _, r := range a.Ranges {
		if ver == "" {
			if isUnboundedAllVersions(r.Events) {
				return true, true
			}
			continue
		}
		var cmp advisory.CompareFunc
		switch strings.ToUpper(r.Type) {
		case "SEMVER":
			cmp = comparePrivateSemver
		case "ECOSYSTEM":
			cmp = comparatorForType(p.Type())
		}
		if cmp == nil {
			continue
		}
		matched, ok := advisory.EvalRange(r.Events, ver, cmp)
		if !ok {
			continue
		}
		evaluated = true
		if matched {
			return true, true
		}
	}
	return false, evaluated
}

func isUnboundedAllVersions(events []osv.Event) bool {
	hasZeroIntro := false
	for _, e := range events {
		if e.Fixed != "" || e.LastAffected != "" || e.Limit != "" {
			return false
		}
		if e.Introduced == "0" {
			hasZeroIntro = true
		} else if e.Introduced != "" {
			return false
		}
	}
	return hasZeroIntro
}

// comparePrivateSemver tries strict SemVer 2.0 ordering first and falls back to
// lenient dotted/alphanumeric comparison for real-world versions such as
// 1.5.0.Final, 2.32.0rc1, or 1.5.0.1.
func comparePrivateSemver(a, b string) (int, bool) {
	if c, ok := advisory.CompareSemver(a, b); ok {
		return c, true
	}
	pa, ok1 := parseLenientSemver(a)
	pb, ok2 := parseLenientSemver(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return cmpLenientSemver(pa, pb), true
}

type lenientVersion struct {
	nums    []uint64
	preRank int // -1 pre-release (alpha/beta/rc/pre/dev/snapshot/m), 0 normal/final release
	tag     string
}

func parseLenientSemver(raw string) (lenientVersion, bool) {
	var out lenientVersion
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if v == "" || v[0] < '0' || v[0] > '9' {
		return out, false
	}

	var prePart string
	if i := strings.IndexByte(v, '-'); i >= 0 {
		prePart = v[i+1:]
		v = v[:i]
	}

	parts := strings.Split(v, ".")
	for idx, seg := range parts {
		if seg == "" {
			return out, false
		}
		nEnd := 0
		for nEnd < len(seg) && seg[nEnd] >= '0' && seg[nEnd] <= '9' {
			nEnd++
		}
		if nEnd > 0 {
			num, err := strconv.ParseUint(seg[:nEnd], 10, 64)
			if err != nil {
				return out, false
			}
			out.nums = append(out.nums, num)
			if nEnd < len(seg) {
				rem := strings.Join(append([]string{seg[nEnd:]}, parts[idx+1:]...), ".")
				if prePart != "" {
					prePart = rem + "-" + prePart
				} else {
					prePart = rem
				}
				break
			}
		} else {
			rem := strings.Join(parts[idx:], ".")
			if prePart != "" {
				prePart = rem + "-" + prePart
			} else {
				prePart = rem
			}
			break
		}
	}

	if len(out.nums) == 0 {
		return out, false
	}

	if prePart != "" {
		low := strings.ToLower(prePart)
		switch {
		case isFinalTag(low):
			out.preRank = 0
		case isPreReleaseTag(low):
			out.preRank = -1
			out.tag = low
		default:
			out.preRank = -1
			out.tag = low
		}
	}
	return out, true
}

func isFinalTag(s string) bool {
	return s == "final" || s == "release" || s == "ga"
}

func isPreReleaseTag(s string) bool {
	for _, p := range []string{"rc", "alpha", "beta", "pre", "dev", "snapshot", "a", "b", "m"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func cmpLenientSemver(a, b lenientVersion) int {
	n := len(a.nums)
	if len(b.nums) > n {
		n = len(b.nums)
	}
	for i := 0; i < n; i++ {
		var va, vb uint64
		if i < len(a.nums) {
			va = a.nums[i]
		}
		if i < len(b.nums) {
			vb = b.nums[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	if a.preRank != b.preRank {
		if a.preRank < b.preRank {
			return -1
		}
		return 1
	}
	return compareTagTokens(a.tag, b.tag)
}

func compareTagTokens(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return -1
	}
	if b == "" {
		return 1
	}
	return strings.Compare(a, b)
}
