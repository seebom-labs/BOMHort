package license

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	json "github.com/goccy/go-json"
)

// goTempNameRe matches Go temporary module directory names that may have
// slipped through the SPDX parser cleanup (e.g. "tmp.ej9m9OiO2V").
var goTempNameRe = regexp.MustCompile(`^tmp\.[a-zA-Z0-9]{6,}$`)

// Category represents a license compliance category.
type Category string

const (
	CategoryPermissive Category = "permissive"
	CategoryCopyleft   Category = "copyleft"
	// CategoryUnapproved is a declared license the policy does not list. It is
	// not necessarily copyleft, but nobody approved it, so it is a violation.
	CategoryUnapproved Category = "unapproved"
	// CategoryUnknown means the SBOM carries no usable license information
	// (NOASSERTION, NONE, empty) or the expression cannot be parsed.
	CategoryUnknown Category = "unknown"
)

// PolicyFile represents the license-policy.json structure.
type PolicyFile struct {
	Description string   `json:"description,omitempty"`
	Permissive  []string `json:"permissive"`
	Copyleft    []string `json:"copyleft"`
	// ExpressionMode selects how compound SPDX expressions are folded into a
	// category: "strict" (default), "permissive-wins" or "off". The
	// LICENSE_EXPRESSION_MODE environment variable overrides this field.
	ExpressionMode string `json:"expressionMode,omitempty"`
}

// Policy holds the loaded license classification maps.
type Policy struct {
	permissive map[string]bool
	copyleft   map[string]bool
	mode       ExpressionMode
}

// built-in defaults based on the CNCF Allowed Third-Party License Policy:
// https://github.com/cncf/foundation/blob/main/policies-guidance/allowed-third-party-license-policy.md
// Apache-2.0 (CNCF project license) + the CNCF Allowlist are permissive.
// Everything else requires a CNCF Governing Board exception.
var defaultPermissive = []string{
	"Apache-2.0",
	"MIT", "MIT-0",
	"0BSD", "BSD-2-Clause", "BSD-2-Clause-FreeBSD", "BSD-3-Clause",
	"ISC",
	"PSF-2.0", "Python-2.0", "Python-2.0.1",
	"PostgreSQL",
	"UPL-1.0", "X11", "Zlib",
	"OpenSSL", "OpenSSL-standalone", "SSLeay-standalone",
}

var defaultCopyleft = []string{
	"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later",
	"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
	"AGPL-3.0-only", "AGPL-3.0-or-later", "MPL-2.0",
	"EPL-1.0", "EPL-2.0", "EUPL-1.2", "CPAL-1.0",
}

// global active policy, protected by a mutex for hot-reload safety.
var (
	activePolicy *Policy
	policyMu     sync.RWMutex
)

func init() {
	// Start with defaults.
	activePolicy = buildPolicy(defaultPermissive, defaultCopyleft, DefaultExpressionMode)
}

func buildPolicy(permissive, copyleft []string, mode ExpressionMode) *Policy {
	p := &Policy{
		permissive: make(map[string]bool, len(permissive)),
		copyleft:   make(map[string]bool, len(copyleft)),
		mode:       mode,
	}
	for _, id := range permissive {
		p.permissive[id] = true
	}
	for _, id := range copyleft {
		p.copyleft[id] = true
	}
	return p
}

// LoadPolicy reads a license-policy.json file and replaces the active policy.
// Returns the number of permissive and copyleft licenses loaded.
func LoadPolicy(path string) (int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return 0, 0, fmt.Errorf("failed to parse policy file %s: %w", path, err)
	}

	mode, err := ParseExpressionMode(pf.ExpressionMode)
	if err != nil {
		return 0, 0, fmt.Errorf("policy file %s: %w", path, err)
	}

	p := buildPolicy(pf.Permissive, pf.Copyleft, mode)

	policyMu.Lock()
	activePolicy = p
	policyMu.Unlock()

	return len(pf.Permissive), len(pf.Copyleft), nil
}

// SetExpressionMode replaces the expression mode of the active policy. Call
// it after LoadPolicy so an environment override (LICENSE_EXPRESSION_MODE)
// wins over the file, and so it also applies when the file failed to load
// and the built-in defaults are in use.
func SetExpressionMode(mode ExpressionMode) {
	policyMu.Lock()
	defer policyMu.Unlock()
	next := *activePolicy
	next.mode = mode
	activePolicy = &next
}

// GetExpressionMode returns the mode the active policy evaluates with.
func GetExpressionMode() ExpressionMode {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return activePolicy.mode
}

// GetPolicy returns the current active policy (for API serialization).
func GetPolicy() *PolicyFile {
	policyMu.RLock()
	defer policyMu.RUnlock()

	pf := &PolicyFile{ExpressionMode: string(activePolicy.mode)}
	for id := range activePolicy.permissive {
		pf.Permissive = append(pf.Permissive, id)
	}
	for id := range activePolicy.copyleft {
		pf.Copyleft = append(pf.Copyleft, id)
	}
	return pf
}

// Categorize returns the compliance category for an SPDX license identifier
// or expression. A bare identifier is matched exactly, then by SPDX modifier
// prefix. A compound expression ("A AND B", "A OR B", "A WITH E", with
// parentheses) is evaluated operand by operand under the active
// ExpressionMode — unless the policy lists the whole expression verbatim, in
// which case that entry wins, or the mode is "off".
//
// A declared license the policy does not list is CategoryUnapproved; only a
// missing license (NOASSERTION, NONE, empty) or an unparseable expression is
// CategoryUnknown.
func Categorize(licenseID string) Category {
	id := Normalize(strings.TrimSpace(licenseID))

	if isNoLicenseInfo(id) {
		return CategoryUnknown
	}

	policyMu.RLock()
	p := activePolicy
	policyMu.RUnlock()

	// A verbatim policy entry for the whole string always wins. This is also
	// the complete behaviour when expression evaluation is off.
	if cat := p.categorizeSingle(id); cat != CategoryUnknown {
		return cat
	}
	if p.mode == ExpressionModeOff {
		return CategoryUnapproved
	}

	if !hasOperator(tokenize(id)) {
		// Single identifier that the plain lookup missed; lookupLeaf still
		// handles the deprecated "+" spelling.
		return lookupLeaf(id, p.categorizeSingle)
	}
	tree, err := parseExpression(id)
	if err != nil {
		// Malformed expression: nothing sensible to fold, keep it unknown so
		// it is flagged for review rather than silently accepted.
		return CategoryUnknown
	}
	return tree.evaluate(p.mode, p.categorizeSingle)
}

// categorizeSingle classifies one identifier against the policy lists.
// CategoryUnknown here means "not listed"; callers decide whether that is
// unapproved or a missing license.
func (p *Policy) categorizeSingle(id string) Category {
	// Exact match first.
	if p.permissive[id] {
		return CategoryPermissive
	}
	if p.copyleft[id] {
		return CategoryCopyleft
	}

	// Prefix match for SPDX modifiers (e.g. "MPL-2.0-no-copyleft-exception" → "MPL-2.0").
	for base := range p.permissive {
		if strings.HasPrefix(id, base+"-") {
			return CategoryPermissive
		}
	}
	for base := range p.copyleft {
		if strings.HasPrefix(id, base+"-") {
			return CategoryCopyleft
		}
	}

	return CategoryUnknown
}

// Result holds the compliance check result for one SBOM.
type Result struct {
	LicenseID            string
	Category             Category
	PackageCount         uint32
	NonCompliantPackages []string
	ExemptedPackages     []string // packages covered by exceptions
	ExemptionReason      string   // reason if entire license is exempted
}

// Check analyzes a list of packages and their licenses and produces compliance results.
// Uses no exceptions – all non-permissive packages are flagged.
func Check(packageNames, packageLicenses []string) []Result {
	return CheckWithExceptions(packageNames, packageLicenses, nil)
}

// CheckWithExceptions analyzes packages/licenses with optional exception rules.
// Exempted packages are tracked separately and don't count as non-compliant.
// project is the exact SBOM document name for project-scoped rules.
func CheckWithExceptions(packageNames, packageLicenses []string, exceptions *ExceptionIndex, project ...string) []Result {
	type licenseAgg struct {
		count         uint32
		packages      []string
		exempted      []string
		category      Category
		blanketExempt bool
		exemptionNote string
	}

	agg := make(map[string]*licenseAgg)

	for i, lic := range packageLicenses {
		name := ""
		if i < len(packageNames) {
			name = packageNames[i]
		}

		// Skip Go temporary build directory names (e.g. "tmp.ej9m9OiO2V") –
		// these are artifacts of CI/CD builds captured by SBOM generators and
		// not real package identifiers.
		if goTempNameRe.MatchString(name) {
			continue
		}

		cat := Categorize(lic)

		entry, ok := agg[lic]
		if !ok {
			entry = &licenseAgg{category: cat}
			agg[lic] = entry

			// Check blanket exception for this license.
			if exceptions != nil {
				if exempt, reason := exceptions.IsExempt("", lic); exempt {
					entry.blanketExempt = true
					entry.exemptionNote = reason
				}
			}
		}
		entry.count++

		// Determine if this package is exempted or non-compliant.
		if entry.blanketExempt {
			// Blanket exception covers ALL packages for this license.
			entry.exempted = append(entry.exempted, name)
		} else if cat == CategoryPermissive {
			// Permissive licenses are always compliant – don't track packages.
		} else if exceptions != nil {
			// Copyleft, unapproved or unknown: check per-package exception.
			if exempt, _ := exceptions.IsExempt(name, lic, project...); exempt {
				entry.exempted = append(entry.exempted, name)
			} else {
				entry.packages = append(entry.packages, name)
			}
		} else {
			// No exceptions loaded: all non-permissive packages are non-compliant.
			entry.packages = append(entry.packages, name)
		}
	}

	results := make([]Result, 0, len(agg))
	for licID, entry := range agg {
		results = append(results, Result{
			LicenseID:            licID,
			Category:             entry.category,
			PackageCount:         entry.count,
			NonCompliantPackages: entry.packages,
			ExemptedPackages:     entry.exempted,
			ExemptionReason:      entry.exemptionNote,
		})
	}

	return results
}
