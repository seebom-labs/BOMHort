package evaluate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/internal/osvutil"
	"github.com/seebom-labs/bomhort/backend/internal/sbom"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

var (
	// ErrPURLCapExceeded is returned when the number of PURLs in an SBOM
	// exceeds the configured per-request threshold.
	ErrPURLCapExceeded = errors.New("purl cap exceeded")

	// ErrInvalidFailOn is returned when an unsupported threshold is passed to fail_on.
	ErrInvalidFailOn = errors.New("invalid fail_on parameter")
)

// OSVClient abstracts the OSV client methods needed for vulnerability evaluation.
type OSVClient interface {
	QueryBatch(ctx context.Context, purls []string) (*osv.BatchResponse, error)
	HydrateVulns(ctx context.Context, vulnIDs []string) (map[string]*osv.VulnEntry, error)
}

// Options configures the evaluation run.
type Options struct {
	SourceFile        string
	SHA256Hash        string
	MaxPURLs          int
	SkipOSV           bool
	FailOn            string
	OSVClient         OSVClient
	GitHubLookup      GitHubLookup
	RegistryResolvers []RegistryResolver
	Exceptions        func() *license.ExceptionIndex
}

// Result holds all artifacts produced by an evaluation.
type Result struct {
	SBOM              models.SBOM
	Packages          models.SBOMPackages
	Vulnerabilities   []models.Vulnerability
	Findings          []dto.VulnerabilityListItem
	LicenseCompliance []dto.SBOMLicenseBreakdownItem
	LicenseModels     []models.LicenseCompliance
	LicenseSources    []string
	ResolvedBy        map[string]int
	Summary           dto.ScanSummary
	PolicyResult      string
	PolicyReason      string
}

// Evaluate evaluates an SBOM in-memory: it parses the document, resolves
// unknown licenses from package registries/GitHub, queries OSV for
// vulnerabilities, checks license compliance against configured policies and
// exceptions, and aggregates summary statistics without writing to ClickHouse.
func Evaluate(ctx context.Context, r io.Reader, opts Options) (*Result, error) {
	parsed, err := sbom.Parse(r, opts.SourceFile, opts.SHA256Hash)
	if err != nil {
		return nil, err
	}
	return EvaluateParsed(ctx, parsed, opts)
}

// EvaluateParsed evaluates an already parsed SBOM structure.
func EvaluateParsed(ctx context.Context, parsed *sbom.ParseResult, opts Options) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 1. Count distinct PURLs and enforce cap if configured.
	uniquePURLs := make(map[string]struct{})
	for _, p := range parsed.Packages.PackagePURLs {
		if p != "" {
			uniquePURLs[p] = struct{}{}
		}
	}
	if opts.MaxPURLs > 0 && len(uniquePURLs) > opts.MaxPURLs {
		return nil, fmt.Errorf("%w: SBOM contains %d unique PURLs, exceeding limit of %d", ErrPURLCapExceeded, len(uniquePURLs), opts.MaxPURLs)
	}

	// 2. Resolve unknown licenses.
	sources, resolvedBy, err := ResolvePackageLicenses(ctx, opts.GitHubLookup, opts.RegistryResolvers,
		parsed.Packages.PackagePURLs, parsed.Packages.PackageLicenses, parsed.Packages.RootIndices)
	if err != nil {
		return nil, err
	}
	parsed.Packages.PackageLicenseSources = sources

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 3. Query OSV for vulnerabilities.
	var vulns []models.Vulnerability
	var findings []dto.VulnerabilityListItem
	if !opts.SkipOSV && opts.OSVClient != nil && len(uniquePURLs) > 0 {
		purls := make([]string, 0, len(uniquePURLs))
		for p := range uniquePURLs {
			purls = append(purls, p)
		}
		sort.Strings(purls)

		type vulnPURL struct {
			id   string
			purl string
		}
		var discovered []vulnPURL

		const chunkSize = 1000
		for i := 0; i < len(purls); i += chunkSize {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			end := i + chunkSize
			if end > len(purls) {
				end = len(purls)
			}
			chunk := purls[i:end]

			resp, qErr := opts.OSVClient.QueryBatch(ctx, chunk)
			if qErr != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				log.Printf("WARNING: OSV query failed for chunk %d-%d: %v", i, end, qErr)
				continue
			}

			for j, qr := range resp.Results {
				if len(qr.Vulns) == 0 {
					continue
				}
				purl := chunk[j]
				for _, v := range qr.Vulns {
					discovered = append(discovered, vulnPURL{id: v.ID, purl: purl})
				}
			}
		}

		if len(discovered) > 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			uniqueIDs := make([]string, 0)
			seen := make(map[string]struct{})
			for _, d := range discovered {
				if _, ok := seen[d.id]; !ok {
					seen[d.id] = struct{}{}
					uniqueIDs = append(uniqueIDs, d.id)
				}
			}

			hydrated, hErr := opts.OSVClient.HydrateVulns(ctx, uniqueIDs)
			if hErr != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				log.Printf("WARNING: OSV hydration failed: %v", hErr)
			}

			for _, d := range discovered {
				h, ok := hydrated[d.id]
				if !ok {
					continue
				}
				minDepth := depgraph.MinDepthForPURL(parsed.Packages.PackagePURLs, parsed.Packages.PackageDepths, d.purl)
				v := osvutil.BuildVulnerability(*h, parsed.SBOM.SBOMID, opts.SourceFile, d.purl, minDepth)
				vulns = append(vulns, v)

				normAliases := normalizeAliases(v.VulnID, v.Aliases)
				cveID := osvutil.CVEID(v.VulnID, normAliases)
				scope, depthPtr := scopeFields(v.DependencyDepth)
				findings = append(findings, dto.VulnerabilityListItem{
					VulnID:          v.VulnID,
					CVEID:           cveID,
					Aliases:         normAliases,
					Severity:        v.Severity,
					PURL:            v.PURL,
					Summary:         v.Summary,
					FixedVersion:    v.FixedVersion,
					SourceFile:      v.SourceFile,
					DiscoveredAt:    v.DiscoveredAt.Format(time.RFC3339),
					DependencyScope: scope,
					DependencyDepth: depthPtr,
				})
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 4. Check license compliance.
	licNames, licLicenses := ExcludeIndices(parsed.Packages.PackageNames, parsed.Packages.PackageLicenses, LicenseCheckSkips(parsed.Packages.RootIndices, parsed.Packages.PackagePURLs))
	var excIdx *license.ExceptionIndex
	if opts.Exceptions != nil {
		excIdx = opts.Exceptions()
	}
	licResults := license.CheckWithExceptions(licNames, licLicenses, excIdx, parsed.SBOM.DocumentName)

	var licModels []models.LicenseCompliance
	var licBreakdown []dto.SBOMLicenseBreakdownItem

	pkgScopes := make(map[string]string, len(parsed.Packages.PackageNames))
	pkgsByLic := make(map[string][]string)
	for i, name := range parsed.Packages.PackageNames {
		if name == "" {
			continue
		}
		pkgScopes[name] = depgraph.ScopeOf(parsed.Packages.PackageDepths, i)
		if i < len(parsed.Packages.PackageLicenses) {
			lic := parsed.Packages.PackageLicenses[i]
			pkgsByLic[lic] = append(pkgsByLic[lic], name)
		}
	}

	for _, lr := range licResults {
		nonCompliant := lr.NonCompliantPackages
		if nonCompliant == nil {
			nonCompliant = []string{}
		}
		exempted := lr.ExemptedPackages
		if exempted == nil {
			exempted = []string{}
		}

		licModels = append(licModels, models.LicenseCompliance{
			CheckedAt:            time.Now(),
			SBOMID:               parsed.SBOM.SBOMID,
			SourceFile:           opts.SourceFile,
			LicenseID:            lr.LicenseID,
			Category:             string(lr.Category),
			PackageCount:         lr.PackageCount,
			NonCompliantPackages: nonCompliant,
			ExemptedPackages:     exempted,
			ExemptionReason:      lr.ExemptionReason,
		})

		breakdownPkgs := nonCompliant
		if len(breakdownPkgs) == 0 && lr.Category == license.CategoryPermissive {
			breakdownPkgs = pkgsByLic[lr.LicenseID]
		}
		if breakdownPkgs == nil {
			breakdownPkgs = []string{}
		}

		itemScopes := make(map[string]string)
		for _, pkg := range breakdownPkgs {
			if s, ok := pkgScopes[pkg]; ok {
				itemScopes[pkg] = s
			}
		}
		for _, pkg := range exempted {
			if s, ok := pkgScopes[pkg]; ok {
				itemScopes[pkg] = s
			}
		}

		item := dto.SBOMLicenseBreakdownItem{
			LicenseID:        lr.LicenseID,
			Category:         string(lr.Category),
			PackageCount:     lr.PackageCount,
			Packages:         breakdownPkgs,
			ExemptedPackages: exempted,
			ExemptionReason:  lr.ExemptionReason,
			PackageScopes:    itemScopes,
		}
		licBreakdown = append(licBreakdown, item)
	}

	// 5. Aggregate Summary.
	summary := dto.ScanSummary{
		PackageCount:   uint64(len(parsed.Packages.PackageNames)),
		VulnCount:      uint64(len(vulns)),
		ScopeBreakdown: make(map[string]dto.SeverityCounts),
	}
	for _, v := range vulns {
		sev := strings.ToUpper(v.Severity)
		switch sev {
		case "CRITICAL":
			summary.CriticalVulns++
		case "HIGH":
			summary.HighVulns++
		case "MEDIUM":
			summary.MediumVulns++
		case "LOW":
			summary.LowVulns++
		}
		scope := depgraph.Scope(v.DependencyDepth)
		sc := summary.ScopeBreakdown[scope]
		sc.Add(sev, 1)
		summary.ScopeBreakdown[scope] = sc
	}
	for _, lr := range licResults {
		if lr.Category != license.CategoryPermissive {
			summary.LicenseViolations += uint64(len(lr.NonCompliantPackages))
		}
		summary.LicenseExemptions += uint64(len(lr.ExemptedPackages))
	}

	// 6. Evaluate Policy.
	policyResult, policyReason, err := EvaluatePolicy(opts.FailOn, summary)
	if err != nil {
		return nil, err
	}

	if findings == nil {
		findings = []dto.VulnerabilityListItem{}
	}
	if licBreakdown == nil {
		licBreakdown = []dto.SBOMLicenseBreakdownItem{}
	}

	return &Result{
		SBOM:              parsed.SBOM,
		Packages:          parsed.Packages,
		Vulnerabilities:   vulns,
		Findings:          findings,
		LicenseCompliance: licBreakdown,
		LicenseModels:     licModels,
		LicenseSources:    sources,
		ResolvedBy:        resolvedBy,
		Summary:           summary,
		PolicyResult:      policyResult,
		PolicyReason:      policyReason,
	}, nil
}

// EvaluatePolicy checks the scan summary against the fail_on threshold.
func EvaluatePolicy(failOn string, summary dto.ScanSummary) (result, reason string, err error) {
	failOn = strings.TrimSpace(failOn)
	if failOn == "" || strings.EqualFold(failOn, "none") {
		return "pass", "", nil
	}

	parts := strings.Split(failOn, ",")
	var failures []string

	for _, p := range parts {
		threshold := strings.ToLower(strings.TrimSpace(p))
		switch threshold {
		case "":
			continue
		case "critical":
			if summary.CriticalVulns > 0 {
				failures = append(failures, fmt.Sprintf("%d critical vulnerability findings", summary.CriticalVulns))
			}
		case "high":
			count := summary.CriticalVulns + summary.HighVulns
			if count > 0 {
				failures = append(failures, fmt.Sprintf("%d high or critical vulnerability findings", count))
			}
		case "medium":
			count := summary.CriticalVulns + summary.HighVulns + summary.MediumVulns
			if count > 0 {
				failures = append(failures, fmt.Sprintf("%d medium or higher vulnerability findings", count))
			}
		case "low":
			if summary.VulnCount > 0 {
				failures = append(failures, fmt.Sprintf("%d vulnerability findings", summary.VulnCount))
			}
		case "license":
			if summary.LicenseViolations > 0 {
				failures = append(failures, fmt.Sprintf("%d non-compliant license violations", summary.LicenseViolations))
			}
		default:
			return "", "", fmt.Errorf("%w: unknown threshold %q, expected critical, high, medium, low, or license", ErrInvalidFailOn, p)
		}
	}

	if len(failures) > 0 {
		return "fail", "policy failure: " + strings.Join(failures, "; "), nil
	}
	return "pass", "", nil
}

func scopeFields(depth uint16) (string, *uint16) {
	if depth == depgraph.Unknown {
		return depgraph.ScopeUnknown, nil
	}
	d := depth
	return depgraph.Scope(depth), &d
}

func normalizeAliases(vulnID string, aliases []string) []string {
	if len(aliases) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(aliases))
	out := make([]string, 0, len(aliases))
	for _, a := range aliases {
		a = strings.TrimSpace(a)
		if a == "" || a == vulnID {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
