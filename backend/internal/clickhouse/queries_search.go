package clickhouse

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// QuerySBOMVulnerabilities fetches vulnerabilities for a specific SBOM with
// the effective VEX statement per (vuln_id, purl).
//
// Row semantics (#335): exactly one row per (vuln_id, purl). When several
// VEX statements exist for the pair (e.g. an automated under_investigation
// draft followed by a human not_affected), the statement with the newest
// vex_timestamp wins — the same OpenVEX conflict rule the dashboard scoring
// applies. argMax collapses the statements; LIMIT 1 BY guards against
// duplicate vulnerability rows that FINAL cannot merge (differing non-key
// columns after a re-scan).
//
// The argMax aliases are deliberately prefixed (vex_status, winning_timestamp,
// …) rather than reusing the source column names: ClickHouse resolves an alias
// that shadows a column inside the same aggregate expression recursively and
// rejects the query with "aggregate function ... is found inside another
// aggregate function".
//
// Scope semantics (#350): only statements scoped to this SBOM (sbom_id = ?)
// apply — a statement about another product must never suppress findings
// here. Unscoped ("global") statements are ignored: there is no fleet-wide
// VEX scope.
//
// scope ("" or a depgraph scope label) keeps only findings whose package is
// pulled in that way. reachability ("" or "reachable", "not_reachable", "unknown")
// filters by reachability evidence (#535).
func (c *Client) QuerySBOMVulnerabilities(ctx context.Context, sbomID string, scope string, reachability string) ([]dto.VulnerabilityListItem, error) {
	scopeAnd := ""
	if pred := depthPredicate(scope, "v.dependency_depth"); pred != "" {
		scopeAnd = " AND " + pred
	}
	args := []any{sbomID, sbomID, sbomID}
	if reachability != "" {
		scopeAnd += " AND v.reachability = ?"
		args = append(args, reachability)
	}
	vexOrder := vexPrecedenceExpr("s")
	rows, err := c.Conn.Query(ctx, `
		SELECT
			v.vuln_id, v.severity, v.purl, v.summary,
			v.fixed_version, v.source_file, v.discovered_at,
			v.dependency_depth, v.aliases,
			v.advisory_source, v.advisory_status, v.component_location,
			ifNull(vx.vex_status, '') AS vex_status,
			ifNull(vx.vex_justification, '') AS vex_justification,
			ifNull(vx.winning_timestamp, toDateTime(0)) AS vex_timestamp,
			ifNull(vx.vex_statement_id, '') AS vex_statement_id,
			ifNull(vx.vex_author, '') AS vex_author,
			ifNull(vx.vex_tooling, '') AS vex_tooling,
			ifNull(vx.vex_role, '') AS vex_role,
			ifNull(q.has_no_dep_graph, 0) AS has_no_dep_graph,
			v.reachability, v.evidence_source, v.evidence_ref, v.evidence_at
		FROM (SELECT * FROM vulnerabilities FINAL) AS v
		LEFT JOIN (
			SELECT sbom_id, has(quality_flags, 'no-dependency-graph') AS has_no_dep_graph
			FROM sboms FINAL
		) AS q ON q.sbom_id = v.sbom_id
		LEFT JOIN (
			SELECT
				f.vuln_id AS vuln_id, f.purl AS purl,
				argMax(s.status, `+vexOrder+`) AS vex_status,
				argMax(s.justification, `+vexOrder+`) AS vex_justification,
				argMax(toString(s.vex_id), `+vexOrder+`) AS vex_statement_id,
				argMax(s.author, `+vexOrder+`) AS vex_author,
				argMax(s.tooling, `+vexOrder+`) AS vex_tooling,
				argMax(s.role, `+vexOrder+`) AS vex_role,
				argMax(s.vex_timestamp, `+vexOrder+`) AS winning_timestamp
			FROM (
				SELECT DISTINCT vuln_id, purl,
					arrayJoin(arrayConcat([vuln_id], aliases)) AS match_id
				FROM vulnerabilities FINAL WHERE sbom_id = ?
			) AS f
			INNER JOIN (SELECT * FROM vex_statements FINAL WHERE sbom_id = ?) AS s
				ON s.vuln_id = f.match_id
			WHERE s.product_purl = f.purl OR s.product_purl = '*'
			GROUP BY f.vuln_id, f.purl
		) AS vx ON vx.vuln_id = v.vuln_id AND vx.purl = v.purl
		WHERE v.sbom_id = ?`+scopeAnd+`
		ORDER BY v.severity ASC, v.discovered_at DESC
		LIMIT 1 BY v.vuln_id, v.purl
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulns for sbom %s: %w", sbomID, err)
	}
	defer rows.Close()

	var items []dto.VulnerabilityListItem
	for rows.Next() {
		var item dto.VulnerabilityListItem
		var discoveredAt, vexTimestamp, evidenceAt time.Time
		var depth uint16
		var aliases []string
		var components string
		var hasNoDepGraph uint8
		if err := rows.Scan(
			&item.VulnID, &item.Severity, &item.PURL,
			&item.Summary, &item.FixedVersion, &item.SourceFile,
			&discoveredAt, &depth, &aliases,
			&item.AdvisorySource, &item.AdvisoryStatus, &components,
			&item.VEXStatus,
			&item.VEXJustification, &vexTimestamp, &item.VEXStatementID,
			&item.VEXAuthor, &item.VEXTooling, &item.VEXRole, &hasNoDepGraph,
			&item.Reachability, &item.EvidenceSource, &item.EvidenceRef, &evidenceAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vuln row: %w", err)
		}
		item.AdvisoryComponents = advisoryComponents(components)
		item.Aliases, item.CVEID = identify(item.VulnID, aliases)
		item.DiscoveredAt = discoveredAt.Format(time.RFC3339)
		item.DependencyScope, item.DependencyDepth = scopeFields(depth)
		if item.DependencyScope == "unknown" && hasNoDepGraph == 1 {
			item.ScopeReason = "no-dependency-graph"
		}
		if (item.Reachability == "" || item.Reachability == models.ReachabilityUnknown) && item.VEXJustification == "vulnerable_code_not_in_execute_path" {
			item.Reachability = models.ReachabilityNotReachable
			if item.EvidenceSource == "" {
				item.EvidenceSource = item.VEXTooling
			}
		}
		if !evidenceAt.IsZero() && evidenceAt.Unix() > 0 {
			item.EvidenceAt = evidenceAt.Format(time.RFC3339)
		}
		if item.VEXStatus != "" {
			item.VEXScope = "sbom"
		}
		// Zero time = no VEX statement for this pair (LEFT JOIN miss);
		// leave the field empty so omitempty drops it from the JSON.
		if !vexTimestamp.IsZero() && vexTimestamp.Unix() != 0 {
			item.VEXTimestamp = vexTimestamp.Format(time.RFC3339)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
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

	// Step 3: direct vs. transitive per listed package. Best effort - an
	// SBOM ingested before migration 025 simply has no scopes.
	if len(items) > 0 {
		var names []string
		for _, it := range items {
			names = append(names, it.Packages...)
			names = append(names, it.ExemptedPackages...)
		}
		scopes, err := c.packageScopesFor(ctx, map[string][]string{sbomID: names})
		if err != nil {
			log.Printf("WARNING: package scopes for sbom %s: %v", sbomID, err)
		} else if all := scopes[sbomID]; len(all) > 0 {
			for i := range items {
				items[i].PackageScopes = pickScopes(all, items[i].Packages, items[i].ExemptedPackages)
			}
		}
	}

	return items, nil
}

// pickScopes narrows a per-SBOM scope map to the names in the given lists.
func pickScopes(all map[string]string, lists ...[]string) map[string]string {
	var out map[string]string
	for _, list := range lists {
		for _, name := range list {
			if scope, ok := all[name]; ok {
				if out == nil {
					out = make(map[string]string)
				}
				out[name] = scope
			}
		}
	}
	return out
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return result, nil
}

// QuerySBOMDetail fetches detailed info for a single SBOM with severity breakdown.
func (c *Client) QuerySBOMDetail(ctx context.Context, sbomID string) (*dto.SBOMDetail, error) {
	var detail dto.SBOMDetail
	var ingestedAt time.Time

	err := c.Conn.QueryRow(ctx, `
		SELECT
			s.sbom_id, s.source_file, s.spdx_version, s.document_name, s.document_version, s.ingested_at,
			s.source_repo, s.source_ref, s.image_ref, s.image_digest,
			ifNull(p.pkg_count, 0) AS package_count,
			s.quality_score, s.quality_flags
		FROM (SELECT * FROM sboms FINAL) AS s
		LEFT JOIN (
			SELECT sbom_id, length(package_names) AS pkg_count
			FROM sbom_packages FINAL
		) AS p ON s.sbom_id = p.sbom_id
		WHERE s.sbom_id = ?
		LIMIT 1
	`, sbomID).Scan(
		&detail.SBOMID, &detail.SourceFile, &detail.SPDXVersion,
		&detail.DocumentName, &detail.DocumentVersion, &ingestedAt,
		&detail.SourceRepo, &detail.SourceRef, &detail.ImageRef, &detail.ImageDigest, &detail.PackageCount,
		&detail.QualityScore, &detail.QualityFlags,
	)
	if err != nil {
		// An unknown sbom_id is a missing resource, not a server fault: report
		// it as such so the gateway can answer 404 instead of 500 and the
		// error log stays free of routine client mistakes.
		if isNoRows(err) {
			return nil, ErrSBOMNotFound
		}
		return nil, fmt.Errorf("failed to query sbom detail for %s: %w", sbomID, err)
	}
	detail.IngestedAt = ingestedAt.Format(time.RFC3339)

	// Severity breakdown for this SBOM, split by dependency scope.
	sevRows, err := c.Conn.Query(ctx,
		"SELECT severity, "+scopeExpr("dependency_depth")+" AS scope, count() FROM vulnerabilities FINAL WHERE sbom_id = ? GROUP BY severity, scope", sbomID)
	if err != nil {
		return nil, fmt.Errorf("failed to query severity for sbom %s: %w", sbomID, err)
	}
	detail.ScopeBreakdown, err = scanSeverityScopes(sevRows, &detail.VulnCount, &detail.CriticalVulns, &detail.HighVulns, &detail.MediumVulns, &detail.LowVulns)
	if err != nil {
		return nil, err
	}

	return &detail, nil
}

// QueryAffectedProjectsByCVE finds all SBOMs affected by a specific vulnerability.
// This checks both direct and transitive dependencies by looking up the PURL in
// the sbom_packages arrays.
//
// f restricts the rows to the SBOMs of an ownership slice (#459).
func (c *Client) QueryAffectedProjectsByCVE(ctx context.Context, vulnID string, f VulnFilter) ([]dto.AffectedProject, error) {
	// Any name of the flaw works (#412): the findings may be stored as
	// GO-2024-3333 while the caller asks for CVE-2024-45338.
	storedIDs, err := c.resolveVulnIDs(ctx, vulnID)
	if err != nil {
		return nil, err
	}
	if len(storedIDs) == 0 {
		return []dto.AffectedProject{}, nil
	}

	// The requested id, the stored ids and every alias of them (GHSA <-> CVE
	// <-> GO-...). VEX documents routinely use a different identifier for
	// the same flaw than the one the finding is stored under; matching on
	// the exact string alone made those statements silently miss.
	matchIDs := append([]string{vulnID}, storedIDs...)
	if groups, err := c.lookupAliases(ctx, storedIDs); err != nil {
		log.Printf("WARNING: alias lookup for %s: %v", vulnID, err)
	} else {
		for _, id := range storedIDs {
			matchIDs = append(matchIDs, groups[id]...)
		}
	}

	// Severity per affected PURL.
	purlRows, err := c.Conn.Query(ctx,
		`SELECT purl,
			argMax(severity, multiIf(severity = 'CRITICAL', 4, severity = 'HIGH', 3, severity = 'MEDIUM', 2, severity = 'LOW', 1, 0))
		FROM vulnerabilities FINAL
		WHERE vuln_id IN (?)
		GROUP BY purl`, storedIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to query purls for %s: %w", vulnID, err)
	}
	defer purlRows.Close()

	severityByPURL := map[string]string{}
	var purls []string
	for purlRows.Next() {
		var purl, severity string
		if err := purlRows.Scan(&purl, &severity); err != nil {
			return nil, fmt.Errorf("failed to scan purl: %w", err)
		}
		severityByPURL[purl] = severity
		purls = append(purls, purl)
	}
	if err := purlRows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	if len(purls) == 0 {
		return []dto.AffectedProject{}, nil
	}

	// VEX status per (sbom, purl), one query for the whole listing.
	//
	// Scoped to sbom_id (#350): without it a statement issued for one
	// product coloured the rows of every other project carrying the same
	// library. argMax over vex_timestamp (#335) so the newest statement
	// wins, and '*' matches the product-wide shape. A failure leaves the
	// statuses empty rather than failing the listing, but it is logged -
	// discarding it is how the dashboard reported a wrong 0 for months (#356).
	type vexKey struct{ sbomID, purl string }
	vexByKey := map[vexKey]string{}
	vexRows, err := c.Conn.Query(ctx, `
		SELECT sbom_id, product_purl, argMax(status, vex_timestamp)
		FROM vex_statements FINAL
		WHERE vuln_id IN (?) AND (product_purl IN (?) OR product_purl = '*')
		GROUP BY sbom_id, product_purl
	`, matchIDs, purls)
	if err != nil {
		log.Printf("WARNING: vex status for %s: %v", vulnID, err)
	} else {
		for vexRows.Next() {
			var k vexKey
			var status string
			if err := vexRows.Scan(&k.sbomID, &k.purl, &status); err != nil {
				log.Printf("WARNING: vex status for %s: %v", vulnID, err)
				break
			}
			vexByKey[k] = status
		}
		if err := vexRows.Err(); err != nil {
			log.Printf("WARNING: vex status for %s: %v", vulnID, err)
		}
		vexRows.Close()
	}
	vexStatus := func(sbomID, purl string) string {
		if st, ok := vexByKey[vexKey{sbomID, purl}]; ok {
			return st
		}
		return vexByKey[vexKey{sbomID, "*"}]
	}

	// Every SBOM row carrying any affected PURL, one row per hit. A single
	// pass over sbom_packages without FINAL: the per-PURL full scan it
	// replaced timed out at the ingress on large instances. Name, version
	// and depth are picked in SQL; shipping the full arrays of thousands of
	// SBOMs to pick one element each took longer than the query.
	// Depth: minimum over every occurrence of the PURL, 65535 (unknown) for
	// a position beyond package_depths — the rule of depgraph.MinDepthForPURL.
	ownerWhere, ownerArgs := ownerPredicate(f, false)
	if ownerWhere != "" {
		ownerWhere = " WHERE p." + ownerWhere
	}
	rows, err := c.Conn.Query(ctx, `
		SELECT
			p.sbom_id,
			p.source_file,
			ifNull(s.document_name, p.source_file) AS document_name,
			ifNull(s.cluster, '') AS cluster,
			ifNull(s.namespace, '') AS namespace,
			hit,
			indexOf(p.package_purls, hit) AS idx,
			arrayElement(p.package_names, idx) AS name,
			arrayElement(p.package_versions, idx) AS version,
			arrayMin(arrayMap(i -> if(i <= length(p.package_depths), p.package_depths[i], 65535),
				arrayFilter((i, x) -> x = hit, arrayEnumerate(p.package_purls), p.package_purls))) AS depth
		FROM sbom_packages AS p
		ARRAY JOIN arrayFilter(x -> x IN (?), p.package_purls) AS hit
		LEFT JOIN (SELECT sbom_id, document_name, cluster, namespace FROM sboms) AS s ON s.sbom_id = p.sbom_id
	`+ownerWhere, append([]any{purls}, ownerArgs...)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query projects for %s: %w", vulnID, err)
	}
	defer rows.Close()

	var items []dto.AffectedProject
	seen := map[vexKey]bool{}
	for rows.Next() {
		var sbomID, sourceFile, documentName, cluster, namespace, hit, pkgName, version string
		var idx uint64
		var depthRaw uint16
		if err := rows.Scan(&sbomID, &sourceFile, &documentName, &cluster, &namespace, &hit, &idx, &pkgName, &version, &depthRaw); err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		// No FINAL above: skip a duplicate pre-merge row.
		// shortcut: the first row wins, which may be the older one until
		// ClickHouse merges; revisit if re-scans become frequent.
		if seen[vexKey{sbomID, hit}] {
			continue
		}
		seen[vexKey{sbomID, hit}] = true

		scope, depth := scopeFields(depthRaw)
		items = append(items, dto.AffectedProject{
			SBOMID:          sbomID,
			SourceFile:      sourceFile,
			DocumentName:    documentName,
			Cluster:         cluster,
			Namespace:       namespace,
			PURL:            hit,
			PackageName:     pkgName,
			Version:         version,
			Severity:        severityByPURL[hit],
			VEXStatus:       vexStatus(sbomID, hit),
			IsDirect:        scope == depgraph.ScopeDirect,
			DependencyScope: scope,
			DependencyDepth: depth,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
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
	if err := c.Conn.QueryRow(ctx, `
		SELECT uniqExact(dep)
		FROM sbom_packages
		ARRAY JOIN package_names AS dep
	`).Scan(&totalUnique); err != nil {
		return nil, fmt.Errorf("failed to count unique dependencies: %w", err)
	}

	// Top N most-used dependencies across all projects.
	// project_count counts distinct projects, not SBOMs; the project column is
	// derived at ingest, source_file is the fallback for rows without one.
	rows, err := c.Conn.Query(ctx, `
		SELECT
			dep_name,
			dep_purl,
			uniqExact(`+packageProjectKey+`) AS project_count,
			groupUniqArray(dep_version) AS versions
		FROM sbom_packages
		ARRAY JOIN
			package_names AS dep_name,
			package_purls AS dep_purl,
			package_versions AS dep_version
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
		deps = append(deps, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// Vulnerability counts for the page in one query, not one per row.
	purls := make([]string, 0, len(deps))
	for _, d := range deps {
		if d.PURL != "" {
			purls = append(purls, d.PURL)
		}
	}
	if len(purls) > 0 {
		vRows, err := c.Conn.Query(ctx,
			"SELECT purl, uniqExact(vuln_id) FROM vulnerabilities FINAL WHERE purl IN (?) GROUP BY purl", purls)
		if err != nil {
			return nil, fmt.Errorf("failed to count dependency vulnerabilities: %w", err)
		}
		defer vRows.Close()
		counts := map[string]uint64{}
		for vRows.Next() {
			var purl string
			var n uint64
			if err := vRows.Scan(&purl, &n); err != nil {
				return nil, fmt.Errorf("failed to scan vulnerability count: %w", err)
			}
			counts[purl] = n
		}
		if err := vRows.Err(); err != nil {
			return nil, fmt.Errorf("rows error: %w", err)
		}
		for i := range deps {
			deps[i].VulnCount = counts[deps[i].PURL]
		}
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
			FROM sbom_packages
			ARRAY JOIN package_names AS dep_name, package_versions AS dep_version
			WHERE dep_name != '' AND dep_version != '' %s
			GROUP BY dep_name
			HAVING uniqExact(dep_version) > 1
		)
	`, searchFilter)
	if err := c.Conn.QueryRow(ctx, countQuery, args...).Scan(&totalSkewed); err != nil {
		return nil, fmt.Errorf("failed to count version skew: %w", err)
	}

	// Find paginated skewed packages.
	mainQuery := fmt.Sprintf(`
		SELECT
			dep_name,
			any(dep_purl) AS purl,
			uniqExact(dep_version) AS version_count,
			uniqExact(%s) AS project_count,
			groupUniqArray(dep_version) AS versions
		FROM sbom_packages
		ARRAY JOIN
			package_names AS dep_name,
			package_purls AS dep_purl,
			package_versions AS dep_version
		WHERE dep_name != '' AND dep_version != '' %s
		GROUP BY dep_name
		HAVING version_count > 1
		ORDER BY project_count DESC, version_count DESC
		LIMIT ? OFFSET ?
	`, packageProjectKey, searchFilter)

	rows, err := c.Conn.Query(ctx, mainQuery, append(args, pageSize, offset)...)
	if err != nil {
		return nil, fmt.Errorf("failed to query version skew: %w", err)
	}
	defer rows.Close()

	var items []dto.VersionSkewItem
	for rows.Next() {
		var item dto.VersionSkewItem
		var versions []string
		if err := rows.Scan(&item.PackageName, &item.PURL, &item.VersionCount, &item.ProjectCount, &versions); err != nil {
			return nil, fmt.Errorf("failed to scan version skew row: %w", err)
		}
		for _, v := range versions {
			item.Versions = append(item.Versions, dto.VersionSkewDetail{Version: v})
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// Second pass: per-version project counts and names for the whole page
	// in one query. One query per item took 12 s for a page of 50 on a
	// 6M-row corpus, within reach of the ingress timeout.
	names := make([]string, len(items))
	byName := make(map[string]int, len(items))
	for i := range items {
		names[i] = items[i].PackageName
		byName[items[i].PackageName] = i
	}
	if len(items) > 0 {
		vRows, err := c.Conn.Query(ctx, fmt.Sprintf(`
			SELECT dep_name, dep_version, uniqExact(pk) AS project_count, groupUniqArray(pk) AS projects
			FROM (
				SELECT dep_name, dep_version, %s AS pk
				FROM sbom_packages
				ARRAY JOIN package_names AS dep_name, package_versions AS dep_version
				WHERE dep_name IN (?)
			)
			GROUP BY dep_name, dep_version
		`, packageProjectKey), names)
		if err != nil {
			return nil, fmt.Errorf("failed to query version detail: %w", err)
		}
		defer vRows.Close()
		for vRows.Next() {
			var name, v string
			var cnt uint64
			var projects []string
			if err := vRows.Scan(&name, &v, &cnt, &projects); err != nil {
				return nil, fmt.Errorf("failed to scan version detail: %w", err)
			}
			i, ok := byName[name]
			if !ok {
				continue
			}
			for j := range items[i].Versions {
				if items[i].Versions[j].Version == v {
					items[i].Versions[j].ProjectCount = cnt
					items[i].Versions[j].Projects = projects
				}
			}
		}
		if err := vRows.Err(); err != nil {
			return nil, fmt.Errorf("rows error: %w", err)
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
	if err := c.Conn.QueryRow(ctx, `
		SELECT uniqExact(dep_name)
		FROM sbom_packages
		ARRAY JOIN package_names AS dep_name
		WHERE dep_name ILIKE ?
	`, searchPattern).Scan(&totalResults); err != nil {
		return nil, fmt.Errorf("failed to count dependency search: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT
			dep_name,
			any(dep_purl) AS purl,
			uniqExact(`+packageProjectKey+`) AS project_count,
			groupUniqArray(dep_version) AS versions
		FROM sbom_packages
		ARRAY JOIN
			package_names AS dep_name,
			package_purls AS dep_purl,
			package_versions AS dep_version
		WHERE dep_name ILIKE ?
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	// Five example projects per result, one query for the whole page: one
	// scan per result is the loop shape that made version skew take 12 s.
	if len(items) > 0 {
		names := make([]string, len(items))
		byName := make(map[string]int, len(items))
		for i := range items {
			names[i] = items[i].PackageName
			byName[items[i].PackageName] = i
			items[i].Projects = []dto.DependencySearchProject{}
		}
		pRows, err := c.Conn.Query(ctx, `
			SELECT dep_name, `+packageProjectKey+` AS project_key,
				any(dep_version) AS version, any(toString(sbom_id)) AS sbom_id
			FROM sbom_packages
			ARRAY JOIN package_names AS dep_name, package_versions AS dep_version
			WHERE dep_name IN (?)
			GROUP BY dep_name, project_key
			ORDER BY dep_name, project_key
			LIMIT 5 BY dep_name
		`, names)
		if err != nil {
			return nil, fmt.Errorf("failed to query package projects: %w", err)
		}
		defer pRows.Close()
		for pRows.Next() {
			var name string
			var proj dto.DependencySearchProject
			if err := pRows.Scan(&name, &proj.ProjectName, &proj.Version, &proj.SBOMID); err != nil {
				return nil, fmt.Errorf("failed to scan project row: %w", err)
			}
			if i, ok := byName[name]; ok {
				items[i].Projects = append(items[i].Projects, proj)
			}
		}
		if err := pRows.Err(); err != nil {
			return nil, fmt.Errorf("rows error: %w", err)
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
	if err := c.Conn.QueryRow(ctx, `
		SELECT uniqExact(`+packageProjectKey+`)
		FROM sbom_packages
		ARRAY JOIN package_names AS dep_name
		WHERE dep_name = ?
	`, packageName).Scan(&totalProjects); err != nil {
		return nil, fmt.Errorf("failed to count package projects: %w", err)
	}

	projects, err := c.queryPackageProjects(ctx, packageName, pageSize, offset)
	if err != nil {
		return nil, err
	}

	return &dto.PackageDetailResponse{
		PackageName:   packageName,
		TotalProjects: totalProjects,
		Projects:      projects,
		Page:          page,
		PageSize:      pageSize,
	}, nil
}

// packageProjectKey is the project a sbom_packages row belongs to: the
// ingest-time project column, or the source path for rows without one.
// Package-wide aggregations use it instead of joining sboms for
// projectKeyExpr: that join over 6M+ rows exceeded the api-gateway's
// max_memory_usage on large instances and the pages rendered empty.
// shortcut: rows with an empty project column count by source_file, not by
// the document-name rule of projectKeyExpr; revisit if an instance ingests
// SBOMs without INGEST_PATH_LAYOUT or per-bucket project.
const packageProjectKey = "if(project != '', project, source_file)"

// queryPackageProjects lists the projects using a package, one row per
// project, ordered by name.
func (c *Client) queryPackageProjects(ctx context.Context, packageName string, limit, offset uint64) ([]dto.DependencySearchProject, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			`+packageProjectKey+` AS project_key,
			any(dep_version) AS version,
			any(toString(sbom_id)) AS sbom_id
		FROM sbom_packages
		ARRAY JOIN package_names AS dep_name, package_versions AS dep_version
		WHERE dep_name = ?
		GROUP BY project_key
		ORDER BY project_key ASC
		LIMIT ? OFFSET ?
	`, packageName, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query package projects: %w", err)
	}
	defer rows.Close()

	projects := []dto.DependencySearchProject{}
	for rows.Next() {
		var proj dto.DependencySearchProject
		if err := rows.Scan(&proj.ProjectName, &proj.Version, &proj.SBOMID); err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		projects = append(projects, proj)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	return projects, nil
}
