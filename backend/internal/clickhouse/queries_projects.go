package clickhouse

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// projectKeyExpr resolves the project a row belongs to.
//
// The explicit `project` column wins whenever it is set. That column is what
// the operator configured (per bucket, via INGEST_PATH_LAYOUT, or on upload),
// so preferring anything else would mean the UI silently disagreeing with the
// configuration — the exact complaint that motivated #357, where SBOMs stored
// under a grouping prefix were listed as one lump "sandbox-applications/527"
// project instead of the real projects they describe.
//
// Everything below the first branch is a fallback for rows that predate
// ownership config or arrived without any:
//   - S3 sources: derive org/project from the key's shape
//   - otherwise: the document name, minus any " - component" suffix
//
// It is a const rather than two inline copies because QueryProjects and
// enrichProjectStats must bucket rows identically; when they drift apart the
// stats attach to project names nothing else produces, and every package and
// vulnerability count silently renders as zero.
//
// Requires the aliased relation `s` to expose project, source_file and
// document_name.
const projectKeyExpr = `
	multiIf(
		s.project != '',
		s.project,
		position(s.source_file, 's3://') = 1,
		if(
			length(splitByChar('/', replaceOne(s.source_file, 's3://', ''))) > 4,
			arrayStringConcat(arraySlice(splitByChar('/', replaceOne(s.source_file, 's3://', '')), 2, 2), '/'),
			arrayElement(splitByChar('/', replaceOne(s.source_file, 's3://', '')), 2)
		),
		s.document_name != '',
		if(
			position(s.document_name, ' - ') > 0,
			trim(BOTH ' ' FROM substring(s.document_name, 1, position(s.document_name, ' - ') - 1)),
			s.document_name
		),
		s.source_file
	)
`

// projectSBOMs selects the (sbom_id, project_name) pairs of the whole estate
// with the project resolved through projectKeyExpr. Every project-scoped
// query starts from this so the identity rule is applied in exactly one
// place; a caller that re-derived the name differently would attach stats to
// projects the listing never produces.
//
// Filter on project_name in an outer WHERE — ClickHouse resolves SELECT
// aliases there, so `WHERE project_name = ?` works without repeating the
// expression.
const projectSBOMs = `(
	SELECT s.sbom_id AS sbom_id, s.ingested_at AS ingested_at, s.tags AS tags,
	       s.document_version AS document_version, s.source_repo AS source_repo,
	       s.cluster AS cluster, s.namespace AS namespace,
	       ` + projectKeyExpr + ` AS project_name
	FROM (SELECT * FROM sboms FINAL) AS s
)`

// projectRows reads table with FINAL, restricted to the SBOMs of the projects
// matching filter (a predicate over projectSBOMs' columns, aliased `s`, e.g.
// "s.project_name IN (?)").
//
// This is the right-hand side for every project-scoped JOIN against
// sbom_packages, vulnerabilities and license_compliance (#344-E). ClickHouse
// does not push a WHERE on the left side of a JOIN into the right side, so
// `projectSBOMs JOIN (SELECT … FROM sbom_packages FINAL) … WHERE project_name
// IN (…)` read and exploded the whole table for a page of fifty projects.
// Filtering on sbom_id here instead hits the primary key of all three tables,
// so only the granules of the selected projects' SBOMs are read.
//
// The JOIN then needs no outer WHERE: only the selected SBOMs have rows on
// the right, so the placeholder count of the query is unchanged.
func projectRows(columns, table, filter string) string {
	return fmt.Sprintf(`(
		SELECT %s FROM %s FINAL
		WHERE sbom_id IN (SELECT s.sbom_id FROM %s AS s WHERE %s)
	)`, columns, table, projectSBOMs, filter)
}

// packageKeyExpr is the de-duplication identity of a component (#398): the
// PURL, or name@version for packages without one. Requires the aliased
// relation `p` over sbom_packages.
const packageKeyExpr = `arrayMap(
	(purl, name, ver) -> if(purl != '', purl, concat(name, '@', ver)),
	p.package_purls, p.package_names, p.package_versions
)`

// latestKey orders a project's SBOMs for "latest" (#494): numeric parts of
// document_version as a tuple (v1.2.3, 1.2, chart-1.12.7 all parse), a
// pre-release ("-rc.1") below its release, build metadata ("+build.4")
// ignored, ingested_at as the tie-breaker
// and the only key when the version has no number. %s is the table alias.
const latestKey = "(arrayMap(x -> toUInt64OrZero(x), extractAll(splitByRegexp('[-+]', %[1]s.document_version)[1], '\\d+')), position(%[1]s.document_version, '-') = 0, %[1]s.ingested_at)"

// QueryProjects fetches a grouped project listing.
//
// tag, when non-empty, restricts the listing to projects having at least one
// SBOM carrying that grouping label. Filtering happens before grouping so the
// per-project counts describe the filtered set rather than the whole estate.
//
// A tag narrows *which* projects are listed; it never merges them. Projects
// stay the unit of the listing, which is the whole point of tags being a
// separate dimension: asking for "sandbox-applications" returns k2s as its own
// project, and k2s still shows all three of its SBOMs.
func (c *Client) QueryProjects(ctx context.Context, page, pageSize uint64, search, tag string) (*dto.PaginatedResponse[dto.ProjectListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// The tag filter is a row-level WHERE (pre-grouping), while search matches
	// the derived project name and must therefore be a HAVING (post-grouping).
	tagWhere := ""
	var tagArgs []interface{}
	if tag != "" {
		tagWhere = "WHERE has(s.tags, ?)"
		tagArgs = append(tagArgs, tag)
	}

	havingClause := ""
	var searchArgs []interface{}
	if search != "" {
		havingClause = "HAVING project_name ILIKE ?"
		searchArgs = append(searchArgs, "%"+search+"%")
	}

	// Count total projects.
	var total uint64
	countQuery := fmt.Sprintf(`
		SELECT count() FROM (
			SELECT %s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
			%s
			GROUP BY project_name
			%s
		)
	`, projectKeyExpr, tagWhere, havingClause)

	countArgs := append(append([]interface{}{}, tagArgs...), searchArgs...)
	if err := c.Conn.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count projects: %w", err)
	}

	// Fetch project list with aggregated stats.
	//
	// groupUniqArrayArray flattens the per-SBOM tag arrays into one distinct
	// set per project, so the listing can show a project's groupings without a
	// second round trip. argMax over latestKey picks the highest version.
	query := fmt.Sprintf(`
		SELECT
			project_name,
			count() AS sbom_count,
			max(s.ingested_at) AS latest_ingested,
			argMax(toString(s.sbom_id), `+fmt.Sprintf(latestKey, "s")+`) AS latest_sbom_id,
			arraySort(groupUniqArrayArray(s.tags)) AS project_tags
		FROM (
			SELECT
				s.sbom_id,
				s.ingested_at,
				s.document_version,
				s.tags,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
			%s
		) AS s
		GROUP BY project_name
		%s
		ORDER BY project_name ASC
		LIMIT ? OFFSET ?
	`, projectKeyExpr, tagWhere, havingClause)

	args := append(append([]interface{}{}, tagArgs...), searchArgs...)
	args = append(args, pageSize, offset)
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query projects: %w", err)
	}
	defer rows.Close()

	var items []dto.ProjectListItem
	for rows.Next() {
		var item dto.ProjectListItem
		var latestIngested time.Time
		if err := rows.Scan(&item.ProjectName, &item.SBOMCount, &latestIngested, &item.LatestSBOMID, &item.Tags); err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		item.LatestIngested = latestIngested.UTC().Format(time.RFC3339)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error: %w", err)
	}

	if items == nil {
		items = []dto.ProjectListItem{}
	}

	// Enrich with de-duplicated package and vulnerability counts for the
	// projects on this page only.
	if len(items) > 0 {
		c.enrichProjectStats(ctx, items)
	}

	return &dto.PaginatedResponse[dto.ProjectListItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// enrichProjectStats adds package_count and vuln_count to project items.
//
// Semantics (#398): both counts are de-duplicated across the project's
// SBOMs. Before this, package_count was the sum of per-SBOM array lengths
// and vuln_count the number of finding rows, so a project with ten versions
// reported roughly ten times its real size — numbers that grew with upload
// frequency rather than with content.
//
// Scope (#344-E): only the projects on the current page are aggregated, and
// only their SBOMs are read from sbom_packages and vulnerabilities (see
// projectRows). Earlier versions scanned both tables for the whole estate on
// every page view and threw away all but fifty rows.
//
// Errors are logged and leave the counts at zero rather than failing the
// listing: a slow or unavailable stats path must not take the project list
// down with it.
func (c *Client) enrichProjectStats(ctx context.Context, items []dto.ProjectListItem) {
	names := make([]string, len(items))
	for i := range items {
		names[i] = items[i].ProjectName
	}

	// Distinct components per project. The ARRAY JOIN explodes each SBOM's
	// package arrays into one row per component; uniqExact then collapses
	// the same component appearing in several versions.
	pkgQuery := fmt.Sprintf(`
		SELECT s.project_name, uniqExact(pkg_key) AS package_count
		FROM %s AS s
		INNER JOIN (
			SELECT p.sbom_id AS sbom_id, arrayJoin(%s) AS pkg_key
			FROM %s AS p
		) AS pk ON pk.sbom_id = s.sbom_id
		GROUP BY s.project_name
	`, projectSBOMs, packageKeyExpr, projectRows("*", "sbom_packages", "s.project_name IN (?)"))

	pkgMap := make(map[string]uint64, len(items))
	if rows, err := c.Conn.Query(ctx, pkgQuery, names); err != nil {
		log.Printf("WARNING: project package counts: %v", err)
	} else {
		for rows.Next() {
			var name string
			var count uint64
			if err := rows.Scan(&name, &count); err != nil {
				log.Printf("WARNING: project package counts: %v", err)
				break
			}
			pkgMap[name] = count
		}
		if err := rows.Err(); err != nil {
			log.Printf("WARNING: project package counts: %v", err)
		}
		rows.Close()
	}

	// Distinct (vuln_id, purl) pairs per project.
	vulnQuery := fmt.Sprintf(`
		SELECT s.project_name, uniqExact(v.vuln_id, v.purl) AS vuln_count
		FROM %s AS s
		INNER JOIN %s AS v
			ON v.sbom_id = s.sbom_id
		GROUP BY s.project_name
	`, projectSBOMs, projectRows("sbom_id, vuln_id, purl", "vulnerabilities", "s.project_name IN (?)"))

	vulnMap := make(map[string]uint64, len(items))
	if rows, err := c.Conn.Query(ctx, vulnQuery, names); err != nil {
		log.Printf("WARNING: project vulnerability counts: %v", err)
	} else {
		for rows.Next() {
			var name string
			var count uint64
			if err := rows.Scan(&name, &count); err != nil {
				log.Printf("WARNING: project vulnerability counts: %v", err)
				break
			}
			vulnMap[name] = count
		}
		if err := rows.Err(); err != nil {
			log.Printf("WARNING: project vulnerability counts: %v", err)
		}
		rows.Close()
	}

	for i := range items {
		items[i].PackageCount = pkgMap[items[i].ProjectName]
		items[i].VulnCount = vulnMap[items[i].ProjectName]
	}
}

// QueryTags returns every grouping label in use, with how many SBOMs and how
// many distinct projects carry it.
//
// This is what lets the UI be data-driven: the frontend renders the groupings
// that actually exist in the data instead of hard-coding a list that would be
// wrong for every instance but the one it was written for. An instance with no
// tags gets an empty list and hides the grouping affordance entirely.
func (c *Client) QueryTags(ctx context.Context) ([]dto.TagListItem, error) {
	// arrayJoin explodes the tag array into one row per (sbom, tag) pair,
	// which is what lets a single SBOM count towards several groupings — the
	// many-to-many behaviour the Array column exists for.
	//
	// project_count is the more meaningful number of the two: tags group
	// projects, so "12 projects" answers what an operator actually asked,
	// while the SBOM count mostly reflects how many versions were uploaded.
	//
	// is_project (#398): a tag that is also a project name is a parent. The
	// IN against the distinct project names is one extra pass over sboms,
	// which is cheap next to the arrayJoin and saves the UI a lookup per
	// chip.
	query := fmt.Sprintf(`
		SELECT
			tag,
			count() AS sbom_count,
			uniqExact(project_name) AS project_count,
			tag IN (SELECT DISTINCT %s FROM (SELECT * FROM sboms FINAL) AS s) AS is_project
		FROM (
			SELECT
				arrayJoin(s.tags) AS tag,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		)
		GROUP BY tag
		ORDER BY tag ASC
	`, projectKeyExpr, projectKeyExpr)

	rows, err := c.Conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close()

	items := []dto.TagListItem{}
	for rows.Next() {
		var item dto.TagListItem
		var isProject uint8
		if err := rows.Scan(&item.Tag, &item.SBOMCount, &item.ProjectCount, &isProject); err != nil {
			return nil, fmt.Errorf("failed to scan tag row: %w", err)
		}
		item.IsProject = isProject != 0
		items = append(items, item)
	}

	return items, rows.Err()
}
