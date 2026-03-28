package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/seebom/backend/internal/license"
	"github.com/seebom-labs/seebom/backend/pkg/dto"
)

// QuerySBOMVulnerabilities fetches vulnerabilities for a specific SBOM with VEX status.
func (c *Client) QuerySBOMVulnerabilities(ctx context.Context, sbomID string) ([]dto.VulnerabilityListItem, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			v.vuln_id, v.severity, v.purl, v.summary,
			v.fixed_version, v.source_file, v.discovered_at,
			ifNull(vx.status, '') AS vex_status
		FROM (SELECT * FROM vulnerabilities FINAL) AS v
		LEFT JOIN (
			SELECT vuln_id, product_purl, status
			FROM vex_statements FINAL
		) AS vx ON vx.vuln_id = v.vuln_id AND vx.product_purl = v.purl
		WHERE v.sbom_id = ?
		ORDER BY v.severity ASC, v.discovered_at DESC
	`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulns for sbom %s: %w", sbomID, err)
	}
	defer rows.Close()

	var items []dto.VulnerabilityListItem
	for rows.Next() {
		var item dto.VulnerabilityListItem
		var discoveredAt time.Time
		if err := rows.Scan(
			&item.VulnID, &item.Severity, &item.PURL,
			&item.Summary, &item.FixedVersion, &item.SourceFile,
			&discoveredAt, &item.VEXStatus,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vuln row: %w", err)
		}
		item.DiscoveredAt = discoveredAt.Format(time.RFC3339)
		items = append(items, item)
	}
	if items == nil {
		items = []dto.VulnerabilityListItem{}
	}
	return items, nil
}

// QuerySBOMLicenses fetches the license breakdown for a specific SBOM.
func (c *Client) QuerySBOMLicenses(ctx context.Context, sbomID string) ([]dto.SBOMLicenseBreakdownItem, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT license_id, category, package_count, non_compliant_packages,
		       exempted_packages, exemption_reason
		FROM license_compliance FINAL
		WHERE sbom_id = ?
		ORDER BY package_count DESC
	`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query licenses for sbom %s: %w", sbomID, err)
	}
	defer rows.Close()

	var items []dto.SBOMLicenseBreakdownItem
	for rows.Next() {
		var item dto.SBOMLicenseBreakdownItem
		var exempted []string
		var reason string
		if err := rows.Scan(&item.LicenseID, &item.Category, &item.PackageCount, &item.Packages, &exempted, &reason); err != nil {
			return nil, fmt.Errorf("failed to scan license row: %w", err)
		}
		if len(exempted) > 0 {
			item.ExemptedPackages = exempted
			item.ExemptionReason = reason
		}
		items = append(items, item)
	}
	if items == nil {
		items = []dto.SBOMLicenseBreakdownItem{}
	}
	return items, nil
}

// QuerySBOMDetail fetches detailed info for a single SBOM with severity breakdown.
func (c *Client) QuerySBOMDetail(ctx context.Context, sbomID string) (*dto.SBOMDetail, error) {
	var detail dto.SBOMDetail
	var ingestedAt time.Time

	err := c.Conn.QueryRow(ctx, `
		SELECT
			s.sbom_id, s.source_file, s.spdx_version, s.document_name, s.ingested_at,
			ifNull(p.pkg_count, 0) AS package_count
		FROM (SELECT * FROM sboms FINAL) AS s
		LEFT JOIN (
			SELECT sbom_id, length(package_names) AS pkg_count
			FROM sbom_packages FINAL
		) AS p ON s.sbom_id = p.sbom_id
		WHERE s.sbom_id = ?
		LIMIT 1
	`, sbomID).Scan(
		&detail.SBOMID, &detail.SourceFile, &detail.SPDXVersion,
		&detail.DocumentName, &ingestedAt, &detail.PackageCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query sbom detail for %s: %w", sbomID, err)
	}
	detail.IngestedAt = ingestedAt.Format(time.RFC3339)

	// Severity breakdown for this SBOM.
	sevRows, err := c.Conn.Query(ctx,
		"SELECT severity, count() AS cnt FROM vulnerabilities FINAL WHERE sbom_id = ? GROUP BY severity", sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query severity for sbom %s: %w", sbomID, err)
	}
	defer sevRows.Close()

	for sevRows.Next() {
		var sev string
		var cnt uint64
		if err := sevRows.Scan(&sev, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan severity: %w", err)
		}
		detail.VulnCount += cnt
		switch sev {
		case "CRITICAL":
			detail.CriticalVulns = cnt
		case "HIGH":
			detail.HighVulns = cnt
		case "MEDIUM":
			detail.MediumVulns = cnt
		case "LOW":
			detail.LowVulns = cnt
		}
	}

	return &detail, nil
}

// QueryProjectsWithLicenseViolations finds all SBOMs that have copyleft or unknown licenses,
// excluding any licenses/packages covered by exceptions.
func (c *Client) QueryProjectsWithLicenseViolations(ctx context.Context, exceptions *license.ExceptionIndex) ([]dto.ProjectLicenseViolation, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			lc.sbom_id,
			lc.source_file,
			ifNull(s.document_name, lc.source_file) AS document_name,
			lc.license_id,
			lc.category,
			lc.package_count,
			lc.non_compliant_packages
		FROM (SELECT * FROM license_compliance FINAL) AS lc
		LEFT JOIN (SELECT * FROM sboms FINAL) AS s ON s.sbom_id = lc.sbom_id
		WHERE lc.category IN ('copyleft', 'unknown')
		ORDER BY lc.sbom_id, lc.license_id
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query license violations: %w", err)
	}
	defer rows.Close()

	type sbomAgg struct {
		sbomID       string
		sourceFile   string
		documentName string
		copyleft     uint64
		unknown      uint64
		licenses     []string
		packages     []string
	}

	agg := make(map[string]*sbomAgg)
	var order []string

	for rows.Next() {
		var sbomID, sourceFile, documentName, licenseID, category string
		var packageCount uint32
		var packages []string
		if err := rows.Scan(&sbomID, &sourceFile, &documentName, &licenseID, &category, &packageCount, &packages); err != nil {
			return nil, fmt.Errorf("failed to scan violation row: %w", err)
		}

		// Check blanket license exception.
		if exceptions != nil {
			if exempt, _ := exceptions.IsExempt("", licenseID); exempt {
				continue // Entire license is exempted.
			}
		}

		// Filter out exempted packages.
		var violatingPkgs []string
		for _, pkg := range packages {
			if exceptions != nil {
				if exempt, _ := exceptions.IsExempt(pkg, licenseID); exempt {
					continue
				}
			}
			violatingPkgs = append(violatingPkgs, pkg)
		}

		if len(violatingPkgs) == 0 {
			continue // All packages in this license are exempted.
		}

		entry, ok := agg[sbomID]
		if !ok {
			entry = &sbomAgg{sbomID: sbomID, sourceFile: sourceFile, documentName: documentName}
			agg[sbomID] = entry
			order = append(order, sbomID)
		}
		if category == "copyleft" {
			entry.copyleft += uint64(len(violatingPkgs))
		} else {
			entry.unknown += uint64(len(violatingPkgs))
		}
		entry.licenses = append(entry.licenses, licenseID)

		seen := make(map[string]bool)
		for _, pkg := range violatingPkgs {
			if !seen[pkg] && pkg != "" {
				seen[pkg] = true
				entry.packages = append(entry.packages, pkg)
			}
		}
	}

	items := make([]dto.ProjectLicenseViolation, 0, len(order))
	for _, id := range order {
		e := agg[id]
		// Deduplicate licenses.
		licSeen := make(map[string]bool)
		var uniqueLics []string
		for _, l := range e.licenses {
			if !licSeen[l] {
				licSeen[l] = true
				uniqueLics = append(uniqueLics, l)
			}
		}
		items = append(items, dto.ProjectLicenseViolation{
			SBOMID:               e.sbomID,
			SourceFile:           e.sourceFile,
			DocumentName:         e.documentName,
			CopyleftCount:        e.copyleft,
			UnknownCount:         e.unknown,
			ViolatingLicenses:    uniqueLics,
			NonCompliantPackages: e.packages,
		})
	}

	if items == nil {
		items = []dto.ProjectLicenseViolation{}
	}
	return items, nil
}

// QueryAffectedProjectsByCVE finds all SBOMs affected by a specific vulnerability.
// This checks both direct and transitive dependencies by looking up the PURL in
// the sbom_packages arrays.
func (c *Client) QueryAffectedProjectsByCVE(ctx context.Context, vulnID string) ([]dto.AffectedProject, error) {
	// First find all PURLs affected by this CVE.
	purlRows, err := c.Conn.Query(ctx,
		"SELECT DISTINCT purl, severity FROM vulnerabilities FINAL WHERE vuln_id = ?", vulnID)
	if err != nil {
		return nil, fmt.Errorf("failed to query purls for %s: %w", vulnID, err)
	}
	defer purlRows.Close()

	type purlSeverity struct {
		purl     string
		severity string
	}
	var affectedPURLs []purlSeverity
	for purlRows.Next() {
		var ps purlSeverity
		if err := purlRows.Scan(&ps.purl, &ps.severity); err != nil {
			return nil, fmt.Errorf("failed to scan purl: %w", err)
		}
		affectedPURLs = append(affectedPURLs, ps)
	}

	if len(affectedPURLs) == 0 {
		return []dto.AffectedProject{}, nil
	}

	// For each affected PURL, find all SBOMs that contain it anywhere in their dependency tree.
	var items []dto.AffectedProject
	for _, ps := range affectedPURLs {
		rows, err := c.Conn.Query(ctx, `
			SELECT
				p.sbom_id,
				p.source_file,
				ifNull(s.document_name, p.source_file) AS document_name,
				indexOf(p.package_purls, ?) AS purl_idx,
				p.package_names,
				p.package_versions,
				p.package_purls,
				p.rel_source_indices,
				p.rel_target_indices
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			LEFT JOIN (SELECT * FROM sboms FINAL) AS s ON s.sbom_id = p.sbom_id
			WHERE has(p.package_purls, ?)
		`, ps.purl, ps.purl)
		if err != nil {
			return nil, fmt.Errorf("failed to query projects for purl %s: %w", ps.purl, err)
		}

		for rows.Next() {
			var (
				sbomID       string
				sourceFile   string
				documentName string
				purlIdx      uint64
				names        []string
				versions     []string
				purls        []string
				relSources   []uint32
				relTargets   []uint32
			)
			if err := rows.Scan(
				&sbomID, &sourceFile, &documentName, &purlIdx,
				&names, &versions, &purls, &relSources, &relTargets,
			); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to scan project row: %w", err)
			}

			pkgName := ""
			version := ""
			if purlIdx > 0 && int(purlIdx) <= len(names) {
				pkgName = names[purlIdx-1] // indexOf is 1-based in ClickHouse
				if int(purlIdx) <= len(versions) {
					version = versions[purlIdx-1]
				}
			}

			// Determine if this is a direct (top-level) dependency.
			// A direct dependency is one that is a target of the root package (index 0).
			isDirect := false
			if purlIdx > 0 {
				depIdx := uint32(purlIdx - 1) // Convert to 0-based
				for i, src := range relSources {
					if src == 0 && i < len(relTargets) && relTargets[i] == depIdx {
						isDirect = true
						break
					}
				}
			}

			// Check VEX status.
			var vexStatus string
			_ = c.Conn.QueryRow(ctx,
				"SELECT status FROM vex_statements FINAL WHERE vuln_id = ? AND product_purl = ? LIMIT 1",
				vulnID, ps.purl).Scan(&vexStatus)

			items = append(items, dto.AffectedProject{
				SBOMID:       sbomID,
				SourceFile:   sourceFile,
				DocumentName: documentName,
				PURL:         ps.purl,
				PackageName:  pkgName,
				Version:      version,
				Severity:     ps.severity,
				VEXStatus:    vexStatus,
				IsDirect:     isDirect,
			})
		}
		rows.Close()
	}

	if items == nil {
		items = []dto.AffectedProject{}
	}
	return items, nil
}

// QueryDependencyStats returns cross-project dependency usage statistics.
func (c *Client) QueryDependencyStats(ctx context.Context, limit uint64) (*dto.DependencyStatsResponse, error) {
	if limit == 0 {
		limit = 50
	}

	// Total unique dependencies across all projects.
	var totalUnique uint64
	_ = c.Conn.QueryRow(ctx, `
		SELECT uniqExact(dep)
		FROM sbom_packages FINAL
		ARRAY JOIN package_names AS dep
	`).Scan(&totalUnique)

	// Top N most-used dependencies across all projects.
	// project_count = distinct projects, not SBOMs. We derive the project key from
	// source_file by extracting the first two path segments (org/repo) which are
	// stable across versions. For local files we fall back to document_name.
	// This avoids counting multiple releases of the same project separately.
	// Note: ClickHouse does not allow "TABLE FINAL AS alias" with ARRAY JOIN,
	// so we wrap sbom_packages in a subquery.
	rows, err := c.Conn.Query(ctx, `
		SELECT
			dep_name,
			dep_purl,
			count(DISTINCT
				multiIf(
					position(source_file, 's3://') = 1,
					arrayStringConcat(
						arraySlice(splitByChar('/', replaceOne(source_file, 's3://', '')), 2, 2),
						'/'
					),
					doc_name != '',
					doc_name,
					source_file
				)
			) AS project_count,
			groupArray(DISTINCT dep_version) AS versions
		FROM (
			SELECT
				p.source_file,
				ifNull(s.document_name, p.source_file) AS doc_name,
				dep_name,
				dep_purl,
				dep_version
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			INNER JOIN (SELECT sbom_id, document_name FROM sboms FINAL) AS s
				ON p.sbom_id = s.sbom_id
			ARRAY JOIN
				p.package_names AS dep_name,
				p.package_purls AS dep_purl,
				p.package_versions AS dep_version
		)
		WHERE dep_name != ''
		GROUP BY dep_name, dep_purl
		ORDER BY project_count DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query dependency stats: %w", err)
	}
	defer rows.Close()

	var deps []dto.DependencyStatsItem
	for rows.Next() {
		var item dto.DependencyStatsItem
		if err := rows.Scan(&item.PackageName, &item.PURL, &item.ProjectCount, &item.Versions); err != nil {
			return nil, fmt.Errorf("failed to scan dep stat row: %w", err)
		}

		// Count vulnerabilities for this PURL.
		if item.PURL != "" {
			_ = c.Conn.QueryRow(ctx,
				"SELECT count(DISTINCT vuln_id) FROM vulnerabilities FINAL WHERE purl = ?",
				item.PURL).Scan(&item.VulnCount)
		}

		deps = append(deps, item)
	}

	if deps == nil {
		deps = []dto.DependencyStatsItem{}
	}

	return &dto.DependencyStatsResponse{
		TotalUniqueDeps: totalUnique,
		TopDependencies: deps,
	}, nil
}
