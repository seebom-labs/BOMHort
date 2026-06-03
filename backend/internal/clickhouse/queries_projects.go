package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/seebom/backend/pkg/dto"
)

// QueryProjects fetches a grouped project listing.
// Projects are derived from the S3 source path (org/project) or document_name.
// Each project shows the count of SBOMs (versions), total packages, and vulnerabilities.
func (c *Client) QueryProjects(ctx context.Context, page, pageSize uint64, search string) (*dto.PaginatedResponse[dto.ProjectListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// project_key derivation: for S3 sources use org/project from path,
	// otherwise fall back to document_name (without trailing version).
	projectKeyExpr := `
		multiIf(
			position(s.source_file, 's3://') = 1,
			arrayStringConcat(
				arraySlice(splitByChar('/', replaceOne(s.source_file, 's3://', '')), 2, 2),
				'/'
			),
			s.document_name != '',
			s.document_name,
			s.source_file
		)
	`

	whereClause := ""
	var searchArgs []interface{}
	if search != "" {
		whereClause = "HAVING project_name ILIKE ?"
		pattern := "%" + search + "%"
		searchArgs = append(searchArgs, pattern)
	}

	// Count total projects.
	var total uint64
	countQuery := fmt.Sprintf(`
		SELECT count() FROM (
			SELECT %s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
			GROUP BY project_name
			%s
		)
	`, projectKeyExpr, whereClause)
	if err := c.Conn.QueryRow(ctx, countQuery, searchArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count projects: %w", err)
	}

	// Fetch project list with aggregated stats.
	query := fmt.Sprintf(`
		SELECT
			project_name,
			count() AS sbom_count,
			max(s.ingested_at) AS latest_ingested,
			groupArray(toString(s.sbom_id)) AS sbom_ids
		FROM (
			SELECT
				s.sbom_id,
				s.ingested_at,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		) AS s
		GROUP BY project_name
		%s
		ORDER BY project_name ASC
		LIMIT ? OFFSET ?
	`, projectKeyExpr, whereClause)

	args := append(searchArgs, pageSize, offset)
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
		if err := rows.Scan(&item.ProjectName, &item.SBOMCount, &latestIngested, &sbomIDs); err != nil {
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
func (c *Client) enrichProjectStats(ctx context.Context, items []dto.ProjectListItem) {
	projectKeyExpr := `
		multiIf(
			position(s.source_file, 's3://') = 1,
			arrayStringConcat(
				arraySlice(splitByChar('/', replaceOne(s.source_file, 's3://', '')), 2, 2),
				'/'
			),
			s.document_name != '',
			s.document_name,
			s.source_file
		)
	`

	// Package counts per project.
	pkgQuery := fmt.Sprintf(`
		SELECT project_name, sum(pkg_count) AS total_packages
		FROM (
			SELECT
				%s AS project_name,
				length(p.package_names) AS pkg_count
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			INNER JOIN (SELECT sbom_id, source_file, document_name FROM sboms FINAL) AS s
				ON p.sbom_id = s.sbom_id
		)
		GROUP BY project_name
	`, projectKeyExpr)

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
			INNER JOIN (SELECT sbom_id, source_file, document_name FROM sboms FINAL) AS s
				ON v.sbom_id = s.sbom_id
		)
		GROUP BY project_name
	`, projectKeyExpr)

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

