package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// Project-scoped read model (#398).
//
// A project is the unit maintainers care about; an SBOM is one version of
// it. Before these queries existed the only way to look at a project was to
// search the SBOM list for its name, which matched every *other* project
// whose path contained the same word — "kubernetes" returned 1 368 documents,
// eleven of which were Kubernetes. Every query here scopes through
// projectSBOMs, so the identity rule is projectKeyExpr and nothing else.
//
// All counts are de-duplicated across the project's SBOMs. See
// dto.ProjectListItem for why that is the contract.

// QueryProjectDetail returns the aggregated view of one project, or
// ErrSBOMNotFound when no SBOM resolves to that name — the gateway maps it
// to 404.
func (c *Client) QueryProjectDetail(ctx context.Context, name string) (*dto.ProjectDetail, error) {
	d := &dto.ProjectDetail{
		ProjectName:      name,
		Tags:             []string{},
		Parents:          []string{},
		Clusters:         []string{},
		Namespaces:       []string{},
		LicenseBreakdown: make(map[string]uint64),
		Children:         []string{},
	}

	// One pass over the project's SBOMs for everything that lives on the
	// sboms row. groupUniqArray on cluster/namespace drops the '' that a
	// catalogue instance stores, so those arrays are genuinely empty there.
	var latestIngested time.Time
	err := c.Conn.QueryRow(ctx, fmt.Sprintf(`
		SELECT
			count(),
			max(ingested_at),
			argMax(toString(sbom_id), `+fmt.Sprintf(latestKey, "s")+`),
			argMax(document_version, `+fmt.Sprintf(latestKey, "s")+`),
			argMaxIf(source_repo, ingested_at, source_repo != ''),
			arraySort(groupUniqArrayArray(tags)),
			arraySort(arrayFilter(x -> x != '', groupUniqArray(cluster))),
			arraySort(arrayFilter(x -> x != '', groupUniqArray(namespace)))
		FROM %s AS s
		WHERE s.project_name = ?
	`, projectSBOMs), name).Scan(
		&d.SBOMCount, &latestIngested, &d.LatestSBOMID, &d.LatestVersion,
		&d.SourceRepo, &d.Tags, &d.Clusters, &d.Namespaces,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query project %q: %w", name, err)
	}
	if d.SBOMCount == 0 {
		return nil, ErrSBOMNotFound
	}
	d.LatestIngested = latestIngested.UTC().Format(time.RFC3339)

	// Parents: which of this project's tags are project names themselves.
	// Sub-projects: how many other projects carry *this* name as a tag.
	// Both are one IN against the distinct project names; the second excludes
	// the project itself so a self-tagged project is not its own child.
	if len(d.Tags) > 0 {
		if err := c.Conn.QueryRow(ctx, fmt.Sprintf(`
			SELECT arraySort(arrayFilter(t -> t IN (SELECT DISTINCT project_name FROM %s), ?))
		`, projectSBOMs), d.Tags).Scan(&d.Parents); err != nil {
			return nil, fmt.Errorf("failed to resolve parents of %q: %w", name, err)
		}
	}
	if err := c.Conn.QueryRow(ctx, fmt.Sprintf(`
		SELECT uniqExact(project_name)
		FROM %s AS s
		WHERE has(s.tags, ?) AND s.project_name != ?
	`, projectSBOMs), name, name).Scan(&d.RelatedProjectCount); err != nil {
		return nil, fmt.Errorf("failed to count sub-projects of %q: %w", name, err)
	}

	// Distinct components.
	if err := c.Conn.QueryRow(ctx, fmt.Sprintf(`
		SELECT uniqExact(pkg_key)
		FROM %s AS s
		INNER JOIN (
			SELECT p.sbom_id AS sbom_id, arrayJoin(%s) AS pkg_key
			FROM %s AS p
		) AS pk ON pk.sbom_id = s.sbom_id
	`, projectSBOMs, packageKeyExpr, projectRows("*", "sbom_packages", "s.project_name = ?")), name).Scan(&d.PackageCount); err != nil {
		return nil, fmt.Errorf("failed to count packages of %q: %w", name, err)
	}

	// Distinct (vuln_id, purl) pairs, bucketed by severity. A pair that
	// appears with different severities across versions (OSV re-rated it) is
	// counted under its highest — argMax over a rank keeps it to one bucket.
	sevRows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		SELECT severity, count()
		FROM (
			SELECT v.vuln_id, v.purl,
				argMax(v.severity, multiIf(v.severity = 'CRITICAL', 4, v.severity = 'HIGH', 3, v.severity = 'MEDIUM', 2, v.severity = 'LOW', 1, 0)) AS severity
			FROM %s AS s
			INNER JOIN %s AS v
				ON v.sbom_id = s.sbom_id
			GROUP BY v.vuln_id, v.purl
		)
		GROUP BY severity
	`, projectSBOMs, projectRows("sbom_id, vuln_id, purl, severity", "vulnerabilities", "s.project_name = ?")), name)
	if err != nil {
		return nil, fmt.Errorf("failed to query severity breakdown of %q: %w", name, err)
	}
	defer sevRows.Close()
	for sevRows.Next() {
		var severity string
		var cnt uint64
		if err := sevRows.Scan(&severity, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan severity row: %w", err)
		}
		d.VulnCount += cnt
		switch severity {
		case "CRITICAL":
			d.CriticalVulns = cnt
		case "HIGH":
			d.HighVulns = cnt
		case "MEDIUM":
			d.MediumVulns = cnt
		case "LOW":
			d.LowVulns = cnt
		}
	}

	// License categories, summed over SBOMs. This one is deliberately *not*
	// de-duplicated: license_compliance stores per-SBOM package counts per
	// category, and the component identity is not available at that grain.
	// It answers "what does this project ship under" as a proportion, which
	// summing preserves.
	licRows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		SELECT lc.category, sum(lc.package_count)
		FROM %s AS s
		INNER JOIN %s AS lc
			ON lc.sbom_id = s.sbom_id
		GROUP BY lc.category
	`, projectSBOMs, projectRows("sbom_id, category, package_count", "license_compliance", "s.project_name = ?")), name)
	if err != nil {
		return nil, fmt.Errorf("failed to query license breakdown of %q: %w", name, err)
	}
	defer licRows.Close()
	for licRows.Next() {
		var category string
		var cnt uint64
		if err := licRows.Scan(&category, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan license row: %w", err)
		}
		d.LicenseBreakdown[category] = cnt
	}

	return d, nil
}

// QueryProjectSBOMs lists the SBOMs — the versions — of one project, newest
// first. Same row shape as every other SBOM listing so the UI reuses the
// component.
func (c *Client) QueryProjectSBOMs(ctx context.Context, name string, page, pageSize uint64) (*dto.PaginatedResponse[dto.SBOMListItem], error) {
	return c.QuerySBOMs(ctx, page, pageSize, "", name)
}

// QueryProjectVulnerabilities returns one row per distinct (vuln_id, purl)
// across every SBOM of the project, with the effective VEX statement.
//
// VEX semantics follow #335: among all statements scoped to any of the
// project's SBOMs that cover the pair, the newest wins. A not_affected issued
// for version 1.2 therefore also shows as the status for the pair when 1.1
// still carries the finding — which is the right answer for "is this project
// affected", and the per-SBOM view remains available for the version-exact
// question. AffectedSBOMs tells the reader how many versions carry the pair.
//
// depScope ("" or a depgraph scope label) keeps only findings whose package
// is pulled in that way in at least one of the project's SBOMs.
func (c *Client) QueryProjectVulnerabilities(ctx context.Context, name string, depScope string) ([]dto.VulnerabilityListItem, error) {
	scopeAnd := ""
	if pred := depthPredicate(depScope, "v.dependency_depth"); pred != "" {
		scopeAnd = " AND " + pred
	}
	rows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		WITH scope AS (SELECT sbom_id FROM %s AS s WHERE s.project_name = ?)
		SELECT
			f.vuln_id, f.severity, f.purl, f.summary, f.fixed_version,
			f.source_file, f.discovered_at, f.affected_sboms, f.dependency_depth, f.aliases,
			ifNull(vx.vex_status, '')            AS vex_status,
			ifNull(vx.vex_justification, '')     AS vex_justification,
			ifNull(vx.winning_timestamp, toDateTime(0)) AS vex_timestamp,
			ifNull(vx.vex_statement_id, '')      AS vex_statement_id,
			ifNull(vx.vex_author, '')            AS vex_author,
			ifNull(vx.vex_tooling, '')           AS vex_tooling
		FROM (
			SELECT
				v.vuln_id AS vuln_id, v.purl AS purl,
				argMax(v.severity, multiIf(v.severity = 'CRITICAL', 4, v.severity = 'HIGH', 3, v.severity = 'MEDIUM', 2, v.severity = 'LOW', 1, 0)) AS severity,
				argMax(v.summary, v.discovered_at)       AS summary,
				argMax(v.fixed_version, v.discovered_at) AS fixed_version,
				argMax(v.source_file, v.discovered_at)   AS source_file,
				max(v.discovered_at)                     AS discovered_at,
				uniqExact(v.sbom_id)                     AS affected_sboms,
				min(v.dependency_depth)                  AS dependency_depth,
				groupUniqArrayArray(v.aliases)           AS aliases
			FROM (SELECT * FROM vulnerabilities FINAL) AS v
			WHERE v.sbom_id IN scope%s
			GROUP BY v.vuln_id, v.purl
		) AS f
		LEFT JOIN (
			SELECT
				m.vuln_id AS vuln_id, m.purl AS purl,
				argMax(st.status, st.vex_timestamp)          AS vex_status,
				argMax(st.justification, st.vex_timestamp)   AS vex_justification,
				argMax(toString(st.vex_id), st.vex_timestamp) AS vex_statement_id,
				argMax(st.author, st.vex_timestamp)          AS vex_author,
				argMax(st.tooling, st.vex_timestamp)         AS vex_tooling,
				max(st.vex_timestamp)                        AS winning_timestamp
			FROM (
				SELECT DISTINCT vuln_id, purl,
					arrayJoin(arrayConcat([vuln_id], aliases)) AS match_id
				FROM vulnerabilities FINAL WHERE sbom_id IN scope
			) AS m
			INNER JOIN (SELECT * FROM vex_statements FINAL WHERE sbom_id IN scope) AS st
				ON st.vuln_id = m.match_id
			WHERE st.product_purl = m.purl OR st.product_purl = '*'
			GROUP BY m.vuln_id, m.purl
		) AS vx ON vx.vuln_id = f.vuln_id AND vx.purl = f.purl
		ORDER BY
			multiIf(f.severity = 'CRITICAL', 0, f.severity = 'HIGH', 1, f.severity = 'MEDIUM', 2, f.severity = 'LOW', 3, 4) ASC,
			f.affected_sboms DESC, f.vuln_id ASC
	`, projectSBOMs, scopeAnd), name)
	if err != nil {
		return nil, fmt.Errorf("failed to query vulnerabilities of project %q: %w", name, err)
	}
	defer rows.Close()

	var items []dto.VulnerabilityListItem
	for rows.Next() {
		var item dto.VulnerabilityListItem
		var discoveredAt, vexTimestamp time.Time
		var depth uint16
		var aliases []string
		if err := rows.Scan(
			&item.VulnID, &item.Severity, &item.PURL, &item.Summary, &item.FixedVersion,
			&item.SourceFile, &discoveredAt, &item.AffectedSBOMs, &depth, &aliases,
			&item.VEXStatus, &item.VEXJustification, &vexTimestamp,
			&item.VEXStatementID, &item.VEXAuthor, &item.VEXTooling,
		); err != nil {
			return nil, fmt.Errorf("failed to scan project vulnerability row: %w", err)
		}
		item.Aliases, item.CVEID = identify(item.VulnID, aliases)
		item.DiscoveredAt = discoveredAt.Format(time.RFC3339)
		item.DependencyScope, item.DependencyDepth = scopeFields(depth)
		if item.VEXStatus != "" {
			item.VEXScope = "sbom"
		}
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
	return items, rows.Err()
}

// QueryProjectPackages lists the distinct components across a project's
// SBOMs with how many versions ship each and how many vulnerability ids are
// known against it. search matches name or PURL. Sorted by exposure first
// (most vulnerable, then most widespread), then name, so the top of page one
// is what a maintainer should look at.
func (c *Client) QueryProjectPackages(ctx context.Context, name string, page, pageSize uint64, search string) (*dto.PaginatedResponse[dto.ProjectPackageItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	searchWhere := ""
	args := []interface{}{name}
	if search != "" {
		searchWhere = "WHERE pkg_name ILIKE ? OR purl ILIKE ?"
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern)
	}

	// The component identity is packageKeyExpr; name/version/purl come along
	// via arrayZip so the same arrayJoin yields all four. argMax(...) over the
	// key picks one representative row per key — they are identical by
	// construction, argMax just satisfies GROUP BY.
	components := fmt.Sprintf(`
		SELECT
			pkg_key,
			any(pkg_name)    AS pkg_name,
			any(pkg_version) AS pkg_version,
			any(purl)        AS purl,
			uniqExact(sbom_id) AS sbom_count
		FROM (
			SELECT
				pk.sbom_id AS sbom_id,
				tupleElement(z, 1) AS pkg_key,
				tupleElement(z, 2) AS pkg_name,
				tupleElement(z, 3) AS pkg_version,
				tupleElement(z, 4) AS purl
			FROM (
				SELECT p.sbom_id AS sbom_id,
					arrayJoin(arrayZip(%s, p.package_names, p.package_versions, p.package_purls)) AS z
				FROM (SELECT sbom_id, package_names, package_versions, package_purls FROM sbom_packages FINAL) AS p
				WHERE p.sbom_id IN (SELECT sbom_id FROM %s AS s WHERE s.project_name = ?)
			) AS pk
		)
		GROUP BY pkg_key
	`, packageKeyExpr, projectSBOMs)

	var total uint64
	if err := c.Conn.QueryRow(ctx, fmt.Sprintf(`
		SELECT count() FROM (%s) %s
	`, components, searchWhere), args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count packages of project %q: %w", name, err)
	}

	// Vulnerability ids per purl within the project. Joined on purl (not the
	// synthetic key): findings are only ever recorded against PURLs, so a
	// purl-less package has zero by definition.
	query := fmt.Sprintf(`
		SELECT
			c.pkg_name, c.pkg_version, c.purl, c.sbom_count,
			ifNull(vc.vuln_count, 0) AS vuln_count
		FROM (%s) AS c
		LEFT JOIN (
			SELECT v.purl AS purl, uniqExact(v.vuln_id) AS vuln_count
			FROM (SELECT * FROM vulnerabilities FINAL) AS v
			WHERE v.sbom_id IN (SELECT sbom_id FROM %s AS s WHERE s.project_name = ?)
			GROUP BY v.purl
		) AS vc ON vc.purl = c.purl AND c.purl != ''
		%s
		ORDER BY vuln_count DESC, c.sbom_count DESC, c.pkg_name ASC, c.pkg_version ASC
		LIMIT ? OFFSET ?
	`, components, projectSBOMs, searchWhere)

	// Argument order follows placeholder order: components(name),
	// vuln subquery(name), search(2), limit, offset.
	qargs := []interface{}{name, name}
	if search != "" {
		qargs = append(qargs, args[1], args[2])
	}
	qargs = append(qargs, pageSize, offset)

	rows, err := c.Conn.Query(ctx, query, qargs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query packages of project %q: %w", name, err)
	}
	defer rows.Close()

	var items []dto.ProjectPackageItem
	for rows.Next() {
		var item dto.ProjectPackageItem
		if err := rows.Scan(&item.Name, &item.Version, &item.PURL, &item.SBOMCount, &item.VulnCount); err != nil {
			return nil, fmt.Errorf("failed to scan project package row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}
	if items == nil {
		items = []dto.ProjectPackageItem{}
	}

	return &dto.PaginatedResponse[dto.ProjectPackageItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, rows.Err()
}
