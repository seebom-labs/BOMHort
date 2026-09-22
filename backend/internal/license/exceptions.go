package license

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	json "github.com/goccy/go-json"
)

// ExceptionsFile represents operator-managed license exceptions.
// No organization-specific approvals are implied by this format.
type ExceptionsFile struct {
	Version           string             `json:"version"`
	LastUpdated       string             `json:"lastUpdated"`
	Description       string             `json:"description,omitempty"`
	BlanketExceptions []BlanketException `json:"blanketExceptions"`
	Exceptions        []Exception        `json:"exceptions"`
}

// BlanketException exempts an entire license from violations regardless of package.
type BlanketException struct {
	ID           string `json:"id"`
	License      string `json:"license"`
	Status       string `json:"status"` // see statusIsApproved
	ApprovedDate string `json:"approvedDate"`
	Scope        string `json:"scope,omitempty"`
	Results      string `json:"results,omitempty"`    // link to approval discussion
	IssueURL     string `json:"issueUrl,omitempty"`   // same, as published by some registries
	PackageURL   string `json:"packageUrl,omitempty"` // upstream project page
	Comment      string `json:"comment,omitempty"`
}

// Exception exempts a specific package+license combination.
type Exception struct {
	ID           string `json:"id"`
	Package      string `json:"package"`           // package name, exact or path-segment suffix
	License      string `json:"license"`           // SPDX license ID
	Project      string `json:"project,omitempty"` // exact SBOM document name; empty, * or "all … projects" means all
	Status       string `json:"status"`            // see statusIsApproved
	ApprovedDate string `json:"approvedDate"`
	Scope        string `json:"scope,omitempty"`
	Results      string `json:"results,omitempty"`    // link to approval discussion
	IssueURL     string `json:"issueUrl,omitempty"`   // same, as published by some registries
	PackageURL   string `json:"packageUrl,omitempty"` // upstream project page
	Comment      string `json:"comment,omitempty"`
}

// statusIsApproved reports whether a status grants an exemption.
//
// Decoding is strict (DisallowUnknownFields), but statuses are not: published
// exception registries use their own vocabulary for "this was approved", and
// an unrecognised value must never silently turn into an approval. So the
// approving values are enumerated and everything else — "denied",
// "not-eligible", "revoked", a typo — leaves the entry unindexed.
//
//	approved    the canonical value
//	allowlisted approved in bulk under a standing allowlist policy, rather
//	            than case by case; identical in effect
//
// A permissive-license marker such as "apache-2.0" is deliberately absent: a
// permissive license never raises a violation, so indexing those entries would
// add rules that can only ever be no-ops.
func statusIsApproved(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "approved", "allowlisted":
		return true
	default:
		return false
	}
}

// ExceptionIndex is a pre-computed lookup for fast exception matching.
type ExceptionIndex struct {
	// blanketLicenses are licenses globally exempted (exact match on SPDX ID).
	blanketLicenses map[string]*BlanketException
	// packageLicense maps "package\x00license" → Exception for specific package+license pairs.
	packageLicense map[string][]*Exception
	// packageAny maps "package" → Exception for packages exempted regardless of license.
	packageAny map[string][]*Exception
	// ordered rules make suffix matching deterministic (file order).
	packageRules []*Exception

	Raw *ExceptionsFile
}

// LoadExceptions reads and indexes a license-exceptions.json file.
func LoadExceptions(path string) (*ExceptionIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read exceptions file %s: %w", path, err)
	}

	var ef *ExceptionsFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&ef); err != nil {
		return nil, fmt.Errorf("failed to parse exceptions file %s: %w", path, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("exceptions file %s must contain exactly one JSON object", path)
	}
	if ef == nil || ef.BlanketExceptions == nil || ef.Exceptions == nil {
		return nil, fmt.Errorf("exceptions file %s must contain blanketExceptions and exceptions arrays (use [] for none)", path)
	}

	return BuildIndex(ef), nil
}

// LoadExceptionsWithFallback tries the primary path first, then falls back to
// additional paths only when a file is absent. A valid empty file is authoritative;
// an unreadable or invalid primary must never enable approvals from a fallback.
func LoadExceptionsWithFallback(paths ...string) (*ExceptionIndex, error) {
	var lastErr error
	for _, p := range paths {
		if p == "" {
			continue
		}
		idx, err := LoadExceptions(p)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			lastErr = err
			continue
		}
		return idx, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no valid exceptions file paths provided")
	}
	return nil, lastErr
}

// BuildIndex creates an ExceptionIndex from an ExceptionsFile.
func BuildIndex(ef *ExceptionsFile) *ExceptionIndex {
	idx := &ExceptionIndex{
		blanketLicenses: make(map[string]*BlanketException),
		packageLicense:  make(map[string][]*Exception),
		packageAny:      make(map[string][]*Exception),
		Raw:             ef,
	}

	for i := range ef.BlanketExceptions {
		be := &ef.BlanketExceptions[i]
		if statusIsApproved(be.Status) {
			for _, lic := range splitLicenses(be.License) {
				idx.blanketLicenses[lic] = be
			}
		}
	}

	for i := range ef.Exceptions {
		exc := &ef.Exceptions[i]
		if !statusIsApproved(exc.Status) {
			continue
		}

		if exc.License != "" && exc.Package != "" {
			for _, lic := range splitLicenses(exc.License) {
				key := exc.Package + "\x00" + lic
				idx.packageLicense[key] = append(idx.packageLicense[key], exc)
			}
		} else if exc.Package != "" {
			idx.packageAny[exc.Package] = append(idx.packageAny[exc.Package], exc)
		}
		if exc.Package != "" {
			idx.packageRules = append(idx.packageRules, exc)
		}
	}

	return idx
}

// splitLicenses splits compound license expressions into individual SPDX IDs.
// Handles comma-separated ("GPL-2.0-only, GPL-2.0-or-later"),
// OR-separated ("MPL-2.0 OR LGPL-3.0-or-later"),
// and AND-separated ("MPL-2.0 AND BSD-3-Clause") expressions.
func splitLicenses(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	// Try comma-separated first (e.g. "GPL-2.0-only, GPL-2.0-or-later").
	if strings.Contains(expr, ",") {
		parts := strings.Split(expr, ",")
		var result []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
		if len(result) > 0 {
			return result
		}
	}

	// Try SPDX operators: " OR " and " AND ".
	for _, sep := range []string{" OR ", " AND "} {
		if strings.Contains(expr, sep) {
			parts := strings.Split(expr, sep)
			var result []string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					result = append(result, p)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}

	return []string{expr}
}

// IsExempt checks if a package+license combination is covered by an exception.
// Returns the matching exception reason or empty string if not exempt.
// project is the SBOM document name. Omitting it never matches a scoped rule.
func (idx *ExceptionIndex) IsExempt(packageName, licenseID string, project ...string) (exempt bool, reason string) {
	if idx == nil {
		return false, ""
	}

	// 1. Check blanket license exceptions (exact match first).
	if be, ok := idx.blanketLicenses[licenseID]; ok {
		return true, fmt.Sprintf("Blanket exception: %s – %s", be.ID, be.Comment)
	}

	// 1b. Check blanket license exceptions (prefix match for SPDX modifiers).
	// e.g. "MPL-2.0-no-copyleft-exception" should match blanket "MPL-2.0".
	// Prefer the longest matching base, independent of map iteration order.
	for end := strings.LastIndex(licenseID, "-"); end > 0; end = strings.LastIndex(licenseID[:end], "-") {
		if be, ok := idx.blanketLicenses[licenseID[:end]]; ok {
			return true, fmt.Sprintf("Blanket exception: %s (via %s) – %s", be.ID, licenseID[:end], be.Comment)
		}
	}

	// 2. Check specific package+license (exact match).
	key := packageName + "\x00" + licenseID
	for _, exc := range idx.packageLicense[key] {
		if matchesProject(exc.Project, project) {
			return true, fmt.Sprintf("Exception: %s – %s", exc.ID, exc.Comment)
		}
	}

	// 2b. Allow qualified names to match a complete path suffix, not arbitrary
	// substrings (e.g. foo/bar must not exempt foo/bar-evil or notfoo/bar).
	for _, exc := range idx.packageRules {
		if !strings.HasSuffix(packageName, "/"+exc.Package) || !matchesProject(exc.Project, project) {
			continue
		}
		for _, lic := range splitLicenses(exc.License) {
			if lic == licenseID {
				return true, fmt.Sprintf("Exception: %s – %s", exc.ID, exc.Comment)
			}
		}
	}

	// 3. Check package-only exceptions (any license, exact match).
	for _, exc := range idx.packageAny[packageName] {
		if matchesProject(exc.Project, project) {
			return true, fmt.Sprintf("Exception: %s – %s", exc.ID, exc.Comment)
		}
	}

	// 3b. Package-only exceptions with path-segment suffix matching.
	for _, exc := range idx.packageRules {
		if exc.License == "" && strings.HasSuffix(packageName, "/"+exc.Package) && matchesProject(exc.Project, project) {
			return true, fmt.Sprintf("Exception: %s – %s", exc.ID, exc.Comment)
		}
	}

	return false, ""
}

// matchesProject reports whether an exception's project scope covers the SBOM
// currently being checked. projects[0] is the SBOM document name.
//
// Besides "" and "*", a scope phrased as "all <something> projects" is treated
// as a wildcard. Registries maintained by a foundation or a platform team
// routinely spell their global scope that way ("All Projects", "All CNCF
// Projects", "All Internal Projects"), and comparing that phrase literally
// against a document name silently matches nothing — the exception is present,
// looks approved in the UI, and exempts not a single finding.
//
// The wildcard only ever widens the *project* scope. Package and license
// still have to match, so a rule cannot become a blanket exemption this way.
//
// A named scope is still compared exactly: document names are identifiers, and
// "Alpha" must not exempt findings in "alpha".
func matchesProject(scope string, projects []string) bool {
	scope = strings.TrimSpace(scope)
	if scope == "" || scope == "*" || isAllProjectsPhrase(scope) {
		return true
	}
	return len(projects) > 0 && scope == projects[0]
}

// isAllProjectsPhrase matches "all projects" with an optional qualifier in
// between, case-insensitively. The qualifier must be a single word, so an
// actual project named "All Things Open Projects Working Group" is not
// mistaken for a wildcard.
func isAllProjectsPhrase(scope string) bool {
	fields := strings.Fields(strings.ToLower(scope))
	if len(fields) < 2 || len(fields) > 3 {
		return false
	}
	return fields[0] == "all" && fields[len(fields)-1] == "projects"
}
