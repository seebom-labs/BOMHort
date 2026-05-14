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
	// Step 1: Get the license compliance summary (categories, exemptions).
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
		var nonCompliant []string
		var exempted []string
		var reason string
		if err := rows.Scan(&item.LicenseID, &item.Category, &item.PackageCount, &nonCompliant, &exempted, &reason); err != nil {
			return nil, fmt.Errorf("failed to scan license row: %w", err)
		}
		item.Packages = nonCompliant
		if len(exempted) > 0 {
			item.ExemptedPackages = exempted
			item.ExemptionReason = reason
		}
		items = append(items, item)
	}
	if items == nil {
		items = []dto.SBOMLicenseBreakdownItem{}
	}

	// Step 2: For items where the package list is empty (typically permissive
	// licenses where non_compliant_packages is always []), resolve the actual
	// package names from sbom_packages by matching on the license array.
	needsResolve := false
	for _, it := range items {
		if len(it.Packages) == 0 && it.PackageCount > 0 {
			needsResolve = true
			break
		}
	}
	if needsResolve {
		pkgMap, err := c.resolvePackagesByLicense(ctx, sbomID)
		if err == nil {
			for i := range items {
				if len(items[i].Packages) == 0 && items[i].PackageCount > 0 {
					if pkgs, ok := pkgMap[items[i].LicenseID]; ok {
						items[i].Packages = pkgs
					}
				}
			}
		}
	}

	return items, nil
}

// resolvePackagesByLicense returns a map of license_id → []package_name by
// exploding the parallel arrays in sbom_packages.
func (c *Client) resolvePackagesByLicense(ctx context.Context, sbomID string) (map[string][]string, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT pkg_license, groupArray(pkg_name) AS pkg_names
		FROM (
			SELECT pkg_name, pkg_license
			FROM sbom_packages FINAL
			ARRAY JOIN
				package_names    AS pkg_name,
				package_licenses AS pkg_license
			WHERE sbom_id = ?
			  AND pkg_name != ''
		)
		GROUP BY pkg_license
	`, sbomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]string)
	for rows.Next() {
		var license string
		var names []string
		if err := rows.Scan(&license, &names); err != nil {
			continue
		}
		result[license] = names
	}
	return result, nil
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

// QueryVersionSkew returns packages with inconsistent versions across projects,
// ranked by project count. Only packages with >1 distinct version are included.
// Uses server-side pagination to handle large datasets efficiently.
func (c *Client) QueryVersionSkew(ctx context.Context, page, pageSize uint64, search string) (*dto.VersionSkewResponse, error) {
	if pageSize == 0 {
		pageSize = 50
	}
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// Build optional search filter.
	searchFilter := ""
	args := []interface{}{}
	if search != "" {
		searchFilter = "AND dep_name ILIKE ?"
		args = append(args, "%"+search+"%")
	}

	// Count total skewed packages (packages with >1 version across projects).
	var totalSkewed uint64
	countQuery := fmt.Sprintf(`
		SELECT count() FROM (
			SELECT dep_name
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			ARRAY JOIN p.package_names AS dep_name, p.package_versions AS dep_version
			WHERE dep_name != '' AND dep_version != '' %s
			GROUP BY dep_name
			HAVING uniqExact(dep_version) > 1
		)
	`, searchFilter)
	if search != "" {
		_ = c.Conn.QueryRow(ctx, countQuery, "%"+search+"%").Scan(&totalSkewed)
	} else {
		_ = c.Conn.QueryRow(ctx, countQuery).Scan(&totalSkewed)
	}

	// Find paginated skewed packages.
	mainQuery := fmt.Sprintf(`
		SELECT
			dep_name,
			any(dep_purl) AS purl,
			uniqExact(dep_version) AS version_count,
			count(DISTINCT project_key) AS project_count,
			groupArray(DISTINCT dep_version) AS versions
		FROM (
			SELECT
				dep_name,
				dep_purl,
				dep_version,
				multiIf(
					position(source_file, 's3://') = 1,
					arrayStringConcat(
						arraySlice(splitByChar('/', replaceOne(source_file, 's3://', '')), 2, 2),
						'/'
					),
					doc_name != '',
					doc_name,
					source_file
				) AS project_key
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
			WHERE dep_name != '' AND dep_version != '' %s
		)
		GROUP BY dep_name
		HAVING uniqExact(dep_version) > 1
		ORDER BY project_count DESC, version_count DESC
		LIMIT ? OFFSET ?
	`, searchFilter)

	var rows interface{ Next() bool; Scan(dest ...interface{}) error; Close() error }
	var err error
	if search != "" {
		rows2, err2 := c.Conn.Query(ctx, mainQuery, "%"+search+"%", pageSize, offset)
		if err2 != nil {
			return nil, fmt.Errorf("failed to query version skew: %w", err2)
		}
		rows = rows2
		err = nil
	} else {
		rows2, err2 := c.Conn.Query(ctx, mainQuery, pageSize, offset)
		if err2 != nil {
			return nil, fmt.Errorf("failed to query version skew: %w", err2)
		}
		rows = rows2
		err = nil
	}
	_ = err
	defer rows.Close()

	var items []dto.VersionSkewItem
	for rows.Next() {
		var item dto.VersionSkewItem
		var versions []string
		if err := rows.Scan(&item.PackageName, &item.PURL, &item.VersionCount, &item.ProjectCount, &versions); err != nil {
			return nil, fmt.Errorf("failed to scan version skew row: %w", err)
		}

		for _, v := range versions {
			item.Versions = append(item.Versions, dto.VersionSkewDetail{
				Version:      v,
				ProjectCount: 0,
			})
		}
		items = append(items, item)
	}

	// Second pass: per-version project counts and names (efficient for ≤50 items per page).
	for i := range items {
		vRows, err := c.Conn.Query(ctx, `
			SELECT
				dep_version,
				count(DISTINCT project_key) AS project_count,
				groupArray(DISTINCT project_key) AS projects
			FROM (
				SELECT
					dep_version,
					multiIf(
						position(source_file, 's3://') = 1,
						arrayStringConcat(
							arraySlice(splitByChar('/', replaceOne(source_file, 's3://', '')), 2, 2),
							'/'
						),
						doc_name != '',
						doc_name,
						source_file
					) AS project_key
				FROM (
					SELECT
						p.source_file,
						ifNull(s.document_name, p.source_file) AS doc_name,
						dep_version
					FROM (SELECT * FROM sbom_packages FINAL) AS p
					INNER JOIN (SELECT sbom_id, document_name FROM sboms FINAL) AS s
						ON p.sbom_id = s.sbom_id
					ARRAY JOIN
						p.package_names AS dep_name,
						p.package_versions AS dep_version
					WHERE dep_name = ?
				)
			)
			GROUP BY dep_version
		`, items[i].PackageName)
		if err == nil {
			type versionInfo struct {
				count    uint64
				projects []string
			}
			versionData := make(map[string]versionInfo)
			for vRows.Next() {
				var v string
				var cnt uint64
				var projects []string
				if err := vRows.Scan(&v, &cnt, &projects); err == nil {
					versionData[v] = versionInfo{count: cnt, projects: projects}
				}
			}
			vRows.Close()
			for j := range items[i].Versions {
				if info, ok := versionData[items[i].Versions[j].Version]; ok {
					items[i].Versions[j].ProjectCount = info.count
					items[i].Versions[j].Projects = info.projects
				}
			}
		}
	}

	if items == nil {
		items = []dto.VersionSkewItem{}
	}

	return &dto.VersionSkewResponse{
		TotalSkewedPackages: totalSkewed,
		Items:               items,
		Page:                page,
		PageSize:            pageSize,
	}, nil
}

// QueryDependencySearch searches packages by name (ILIKE fuzzy match) and returns
// paginated results with project counts and a preview of projects per package.
func (c *Client) QueryDependencySearch(ctx context.Context, query string, page, pageSize uint64) (*dto.DependencySearchResponse, error) {
	if pageSize == 0 {
		pageSize = 20
	}
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize
	searchPattern := "%" + query + "%"

	var totalResults uint64
	_ = c.Conn.QueryRow(ctx, `
		SELECT count() FROM (
			SELECT dep_name
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			ARRAY JOIN p.package_names AS dep_name
			WHERE dep_name ILIKE ?
			GROUP BY dep_name
		)
	`, searchPattern).Scan(&totalResults)

	rows, err := c.Conn.Query(ctx, `
		SELECT
			dep_name,
			any(dep_purl) AS purl,
			count(DISTINCT project_key) AS project_count,
			groupArray(DISTINCT dep_version) AS versions
		FROM (
			SELECT
				dep_name,
				dep_purl,
				dep_version,
				multiIf(
					position(source_file, 's3://') = 1,
					arrayStringConcat(
						arraySlice(splitByChar('/', replaceOne(source_file, 's3://', '')), 2, 2),
						'/'
					),
					doc_name != '',
					doc_name,
					source_file
				) AS project_key
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
			WHERE dep_name ILIKE ?
		)
		GROUP BY dep_name
		ORDER BY project_count DESC, dep_name ASC
		LIMIT ? OFFSET ?
	`, searchPattern, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query dependency search: %w", err)
	}
	defer rows.Close()

	var items []dto.DependencySearchResult
	for rows.Next() {
		var item dto.DependencySearchResult
		if err := rows.Scan(&item.PackageName, &item.PURL, &item.ProjectCount, &item.Versions); err != nil {
			return nil, fmt.Errorf("failed to scan search result: %w", err)
		}
		items = append(items, item)
	}

	for i := range items {
		projRows, err := c.Conn.Query(ctx, `
			SELECT
				project_key,
				any(dep_version) AS version,
				any(sbom_id) AS sbom_id
			FROM (
				SELECT
					p.sbom_id,
					dep_version,
					multiIf(
						position(p.source_file, 's3://') = 1,
						arrayStringConcat(
							arraySlice(splitByChar('/', replaceOne(p.source_file, 's3://', '')), 2, 2),
							'/'
						),
						doc_name != '',
						doc_name,
						p.source_file
					) AS project_key
				FROM (
					SELECT
						p.sbom_id,
						p.source_file,
						ifNull(s.document_name, p.source_file) AS doc_name,
						dep_name,
						dep_version
					FROM (SELECT * FROM sbom_packages FINAL) AS p
					INNER JOIN (SELECT sbom_id, document_name FROM sboms FINAL) AS s
						ON p.sbom_id = s.sbom_id
					ARRAY JOIN
						p.package_names AS dep_name,
						p.package_versions AS dep_version
				) AS p
				WHERE dep_name = ?
			)
			GROUP BY project_key
			ORDER BY project_key ASC
			LIMIT 5
		`, items[i].PackageName)
		if err == nil {
			for projRows.Next() {
				var proj dto.DependencySearchProject
				if err := projRows.Scan(&proj.ProjectName, &proj.Version, &proj.SBOMID); err == nil {
					items[i].Projects = append(items[i].Projects, proj)
				}
			}
			projRows.Close()
		}
		if items[i].Projects == nil {
			items[i].Projects = []dto.DependencySearchProject{}
		}
	}

	if items == nil {
		items = []dto.DependencySearchResult{}
	}

	return &dto.DependencySearchResponse{
		TotalResults: totalResults,
		Items:        items,
		Page:         page,
		PageSize:     pageSize,
		Query:        query,
	}, nil
}

// QueryPackageDetail returns ALL projects using a specific package (paginated).
func (c *Client) QueryPackageDetail(ctx context.Context, packageName string, page, pageSize uint64) (*dto.PackageDetailResponse, error) {
	if pageSize == 0 {
		pageSize = 50
	}
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var totalProjects uint64
	_ = c.Conn.QueryRow(ctx, `
		SELECT count(DISTINCT project_key) FROM (
			SELECT
				multiIf(
					position(p.source_file, 's3://') = 1,
					arrayStringConcat(
						arraySlice(splitByChar('/', replaceOne(p.source_file, 's3://', '')), 2, 2),
						'/'
					),
					doc_name != '',
					doc_name,
					p.source_file
				) AS project_key
			FROM (
				SELECT
					p.source_file,
					ifNull(s.document_name, p.source_file) AS doc_name,
					dep_name
				FROM (SELECT * FROM sbom_packages FINAL) AS p
				INNER JOIN (SELECT sbom_id, document_name FROM sboms FINAL) AS s
					ON p.sbom_id = s.sbom_id
				ARRAY JOIN p.package_names AS dep_name
			) AS p
			WHERE dep_name = ?
		)
	`, packageName).Scan(&totalProjects)

	rows, err := c.Conn.Query(ctx, `
		SELECT
			project_key,
			any(dep_version) AS version,
			any(sbom_id) AS sbom_id
		FROM (
			SELECT
				p.sbom_id,
				dep_version,
				multiIf(
					position(p.source_file, 's3://') = 1,
					arrayStringConcat(
						arraySlice(splitByChar('/', replaceOne(p.source_file, 's3://', '')), 2, 2),
						'/'
					),
					doc_name != '',
					doc_name,
					p.source_file
				) AS project_key
			FROM (
				SELECT
					p.sbom_id,
					p.source_file,
					ifNull(s.document_name, p.source_file) AS doc_name,
					dep_name,
					dep_version
				FROM (SELECT * FROM sbom_packages FINAL) AS p
				INNER JOIN (SELECT sbom_id, document_name FROM sboms FINAL) AS s
					ON p.sbom_id = s.sbom_id
				ARRAY JOIN
					p.package_names AS dep_name,
					p.package_versions AS dep_version
			) AS p
			WHERE dep_name = ?
		)
		GROUP BY project_key
		ORDER BY project_key ASC
		LIMIT ? OFFSET ?
	`, packageName, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query package detail: %w", err)
	}
	defer rows.Close()

	var projects []dto.DependencySearchProject
	for rows.Next() {
		var proj dto.DependencySearchProject
		if err := rows.Scan(&proj.ProjectName, &proj.Version, &proj.SBOMID); err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		projects = append(projects, proj)
	}
	if projects == nil {
		projects = []dto.DependencySearchProject{}
	}

	return &dto.PackageDetailResponse{
		PackageName:   packageName,
		TotalProjects: totalProjects,
		Projects:      projects,
		Page:          page,
		PageSize:      pageSize,
	}, nil
}
