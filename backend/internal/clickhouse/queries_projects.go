package clickhouse

import (
	"context"
	"fmt"
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
	// second round trip.
	query := fmt.Sprintf(`
		SELECT
			project_name,
			count() AS sbom_count,
			max(s.ingested_at) AS latest_ingested,
			groupArray(toString(s.sbom_id)) AS sbom_ids,
			arraySort(groupUniqArrayArray(s.tags)) AS project_tags
		FROM (
			SELECT
				s.sbom_id,
				s.ingested_at,
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
		var sbomIDs []string
		var latestIngested time.Time
		if err := rows.Scan(&item.ProjectName, &item.SBOMCount, &latestIngested, &sbomIDs, &item.Tags); err != nil {
			return nil, fmt.Errorf("failed to scan project row: %w", err)
		}
		item.LatestIngested = latestIngested.UTC().Format(time.RFC3339)
		// Store the latest SBOM ID for quick navigation.
		if len(sbomIDs) > 0 {
			item.LatestSBOMID = sbomIDs[0]
		}
		items = append(items, item)
	}

	if items == nil {
		items = []dto.ProjectListItem{}
	}

	// Enrich with package and vulnerability counts in a second pass.
	// This is more efficient than a massive JOIN in the main query.
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
// The joined sboms projection must carry `project` too, or projectKeyExpr
// would fall through to its heuristic here while the main query used the
// configured value — producing stats keyed by names that match no listed
// project, i.e. counts that silently render as zero.
func (c *Client) enrichProjectStats(ctx context.Context, items []dto.ProjectListItem) {
	const sbomProjection = `(SELECT sbom_id, source_file, document_name, project FROM sboms FINAL) AS s`

	// Package counts per project.
	pkgQuery := fmt.Sprintf(`
		SELECT project_name, sum(pkg_count) AS total_packages
		FROM (
			SELECT
				%s AS project_name,
				length(p.package_names) AS pkg_count
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			INNER JOIN %s
				ON p.sbom_id = s.sbom_id
		)
		GROUP BY project_name
	`, projectKeyExpr, sbomProjection)

	pkgMap := make(map[string]uint64)
	if rows, err := c.Conn.Query(ctx, pkgQuery); err == nil {
		for rows.Next() {
			var name string
			var count uint64
			if err := rows.Scan(&name, &count); err == nil {
				pkgMap[name] = count
			}
		}
		rows.Close()
	}

	// Vulnerability counts per project.
	vulnQuery := fmt.Sprintf(`
		SELECT project_name, count() AS vuln_count
		FROM (
			SELECT
				%s AS project_name
			FROM (SELECT * FROM vulnerabilities FINAL) AS v
			INNER JOIN %s
				ON v.sbom_id = s.sbom_id
		)
		GROUP BY project_name
	`, projectKeyExpr, sbomProjection)

	vulnMap := make(map[string]uint64)
	if rows, err := c.Conn.Query(ctx, vulnQuery); err == nil {
		for rows.Next() {
			var name string
			var count uint64
			if err := rows.Scan(&name, &count); err == nil {
				vulnMap[name] = count
			}
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
	query := fmt.Sprintf(`
		SELECT
			tag,
			count() AS sbom_count,
			uniqExact(project_name) AS project_count
		FROM (
			SELECT
				arrayJoin(s.tags) AS tag,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		)
		GROUP BY tag
		ORDER BY tag ASC
	`, projectKeyExpr)

	rows, err := c.Conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query tags: %w", err)
	}
	defer rows.Close()

	items := []dto.TagListItem{}
	for rows.Next() {
		var item dto.TagListItem
		if err := rows.Scan(&item.Tag, &item.SBOMCount, &item.ProjectCount); err != nil {
			return nil, fmt.Errorf("failed to scan tag row: %w", err)
		}
		items = append(items, item)
	}

	return items, rows.Err()
}
