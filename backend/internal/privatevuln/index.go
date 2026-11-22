package privatevuln

import (
	"bytes"
	"fmt"
	"strings"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

// Index provides fast in-memory lookup of private vulnerability advisories
// against PURLs.
type Index struct {
	// Entries is all valid private advisories in file order.
	Entries []osv.VulnEntry
	// byKey maps a package key ("type/namespace/name") to the affected targets.
	byKey map[string][]entryTarget
}

type entryTarget struct {
	entry    osv.VulnEntry
	affected osv.Affected
	release  string
}

// Parse decodes and indexes an OSV-format private vulnerabilities document.
// The document may be a JSON array of OSV VulnEntry objects or a JSON object
// with a "vulnerabilities" array.
//
// Validation ensures IDs are non-empty and org-prefixed (e.g. BOMHORT-...,
// ORG-...) and never use public CVE- or GHSA- prefixes.
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
		if id == "" {
			return nil, fmt.Errorf("private vulnerability entry in %s is missing id", name)
		}
		upper := strings.ToUpper(id)
		if strings.HasPrefix(upper, "CVE-") || strings.HasPrefix(upper, "GHSA-") {
			return nil, fmt.Errorf("private vulnerability %q in %s cannot use public CVE- or GHSA- prefix", id, name)
		}

		// Withdrawn advisories are no longer active findings.
		if strings.TrimSpace(entry.Withdrawn) != "" {
			continue
		}

		for _, a := range entry.Affected {
			key, release := advisory.AffectedKey(a.Package.PURL, a.Package.Ecosystem, a.Package.Name)
			if key == "" {
				continue
			}
			idx.byKey[key] = append(idx.byKey[key], entryTarget{
				entry:    entry,
				affected: a,
				release:  release,
			})
		}
	}

	return idx, nil
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
			hit, evaluated := advisory.InRange(target.affected, p)
			if !evaluated || !hit {
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
