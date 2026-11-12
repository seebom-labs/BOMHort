package sbom

import (
	"sort"
	"strings"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// Quality flag identifiers indicating reasons for score deductions (#537).
// Stored as LowCardinality(String) in ClickHouse.
const (
	FlagNoRootComponent        = "no-root-component"
	FlagMissingAuthor          = "missing-author"
	FlagMissingTimestamp       = "missing-timestamp"
	FlagFutureTimestamp        = "future-timestamp"
	FlagStaleDocument          = "stale-document"
	FlagMissingSupplier        = "missing-supplier"
	FlagMissingComponentName   = "missing-component-name"
	FlagMissingVersion         = "missing-version"
	FlagNoPURLs                = "no-purls"
	FlagLowPURLCoverage        = "low-purl-coverage"
	FlagNoDependencyGraph      = "no-dependency-graph"
	FlagNoLicenses             = "no-licenses"
	FlagLowLicenseCoverage     = "low-license-coverage"
	FlagUnsupportedSpecVersion = "unsupported-spec-version"
)

// AllQualityFlags contains the full set of known deduction flags in alphabetical order.
var AllQualityFlags = []string{
	FlagFutureTimestamp,
	FlagLowLicenseCoverage,
	FlagLowPURLCoverage,
	FlagMissingAuthor,
	FlagMissingComponentName,
	FlagMissingSupplier,
	FlagMissingTimestamp,
	FlagMissingVersion,
	FlagNoDependencyGraph,
	FlagNoLicenses,
	FlagNoPURLs,
	FlagNoRootComponent,
	FlagStaleDocument,
	FlagUnsupportedSpecVersion,
}

// EvaluateQuality evaluates the completeness and standards compliance of an SBOM
// document against NTIA / BSI TR-03183 minimum elements and data quality criteria.
// It returns a quality score (0-100) and an array of descriptive deduction flags.
func EvaluateQuality(sbom *models.SBOM, pkgs *models.SBOMPackages) (uint8, []string) {
	return EvaluateQualityAt(sbom, pkgs, time.Now())
}

// EvaluateQualityAt evaluates quality relative to a given reference time (useful for deterministic tests).
func EvaluateQualityAt(sbom *models.SBOM, pkgs *models.SBOMPackages, now time.Time) (uint8, []string) {
	var score int
	var flags []string

	// 1. Root Component (5 points)
	hasRoot := (pkgs != nil && (len(pkgs.RootIndices) > 0 || len(pkgs.DirectIndices) > 0)) || (sbom != nil && sbom.RootPURL != "")
	if hasRoot {
		score += 5
	} else {
		flags = append(flags, FlagNoRootComponent)
	}

	// 2. Author / Creator Tools (10 points)
	if sbom != nil && len(sbom.CreatorTools) > 0 {
		score += 10
	} else {
		flags = append(flags, FlagMissingAuthor)
	}

	// 3. Timestamp (10 points)
	if sbom == nil || sbom.CreationDate.IsZero() {
		flags = append(flags, FlagMissingTimestamp)
	} else {
		if sbom.CreationDate.After(now.Add(24 * time.Hour)) {
			score += 5
			flags = append(flags, FlagFutureTimestamp)
		} else if now.Sub(sbom.CreationDate) > 730*24*time.Hour {
			score += 5
			flags = append(flags, FlagStaleDocument)
		} else {
			score += 10
		}
	}

	// 4. Supplier Information (10 points)
	if sbom != nil && strings.TrimSpace(sbom.Supplier) != "" && !strings.EqualFold(sbom.Supplier, "NOASSERTION") {
		score += 10
	} else {
		flags = append(flags, FlagMissingSupplier)
	}

	// 5. Component Name (10 points)
	pkgCount := 0
	if pkgs != nil {
		pkgCount = len(pkgs.PackageNames)
	}

	hasDocName := sbom != nil && strings.TrimSpace(sbom.DocumentName) != ""
	namedPkgCount := 0
	if pkgs != nil {
		for _, name := range pkgs.PackageNames {
			if strings.TrimSpace(name) != "" {
				namedPkgCount++
			}
		}
	}

	if hasDocName && (pkgCount == 0 || (namedPkgCount*100)/pkgCount >= 90) {
		score += 10
	} else {
		flags = append(flags, FlagMissingComponentName)
	}

	// 6. Component Version (10 points)
	hasDocVer := sbom != nil && strings.TrimSpace(sbom.DocumentVersion) != ""
	versionedPkgCount := 0
	if pkgs != nil {
		for _, ver := range pkgs.PackageVersions {
			if strings.TrimSpace(ver) != "" && !strings.EqualFold(ver, "NOASSERTION") {
				versionedPkgCount++
			}
		}
	}

	if hasDocVer && (pkgCount == 0 || (versionedPkgCount*100)/pkgCount >= 80) {
		score += 10
	} else {
		flags = append(flags, FlagMissingVersion)
	}

	// 7. Unique Identifiers: PURL Coverage (15 points)
	if pkgCount == 0 {
		score += 15
	} else {
		purlCount := 0
		for _, purl := range pkgs.PackagePURLs {
			if strings.HasPrefix(purl, "pkg:") {
				purlCount++
			}
		}
		purlPct := (purlCount * 100) / pkgCount
		if purlPct >= 80 {
			score += 15
		} else if purlPct >= 50 {
			score += 10
			flags = append(flags, FlagLowPURLCoverage)
		} else if purlPct > 0 {
			score += 5
			flags = append(flags, FlagLowPURLCoverage)
		} else {
			flags = append(flags, FlagNoPURLs)
		}
	}

	// 8. Dependency Graph / Relationships (15 points)
	// Single-package SBOMs describing just the root need no external edges.
	if pkgCount <= 1 {
		score += 15
	} else if pkgs != nil && len(pkgs.RelTypes) > 0 {
		score += 15
	} else {
		flags = append(flags, FlagNoDependencyGraph)
	}

	// 9. License Coverage (15 points)
	if pkgCount == 0 {
		score += 15
	} else {
		licCount := 0
		for _, lic := range pkgs.PackageLicenses {
			trimmed := strings.TrimSpace(lic)
			if trimmed != "" && !strings.EqualFold(trimmed, "NOASSERTION") && !strings.EqualFold(trimmed, "NONE") {
				licCount++
			}
		}
		licPct := (licCount * 100) / pkgCount
		if licPct >= 80 {
			score += 15
		} else if licPct >= 50 {
			score += 10
		} else if licPct > 0 {
			score += 5
			flags = append(flags, FlagLowLicenseCoverage)
		} else {
			flags = append(flags, FlagNoLicenses)
		}
	}

	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	sort.Strings(flags)
	return uint8(score), flags
}
