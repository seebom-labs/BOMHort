package clickhouse

import (
	"context"
	"fmt"
	"strings"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// QueryLicenseDiscrepancies returns packages where the discovered license differs
// from the declared license. The declared license remains authoritative for
// compliance (#530). Results are bounded by limit and offset and support server-side search.
func (c *Client) QueryLicenseDiscrepancies(ctx context.Context, sbomID, project, cluster, namespace, search string, page, pageSize uint64) (*dto.PaginatedResponse[dto.LicenseDiscrepancyItem], error) {
	if page == 0 {
		page = 1
	}
	if pageSize == 0 {
		pageSize = 50
	}
	if pageSize > 500 {
		pageSize = 500
	}
	offset := (page - 1) * pageSize

	var innerConditions []string
	var args []any

	if sbomID != "" {
		innerConditions = append(innerConditions, "sbom_id = ?")
		args = append(args, sbomID)
	}
	if project != "" {
		innerConditions = append(innerConditions, "project = ?")
		args = append(args, project)
	}
	if cluster != "" {
		innerConditions = append(innerConditions, "cluster = ?")
		args = append(args, cluster)
	}
	if namespace != "" {
		innerConditions = append(innerConditions, "namespace = ?")
		args = append(args, namespace)
	}

	whereClause := ""
	if len(innerConditions) > 0 {
		whereClause = "AND " + strings.Join(innerConditions, " AND ")
	}

	search = strings.TrimSpace(search)
	searchWhere := ""
	var searchArgs []any
	if search != "" {
		pattern := "%" + search + "%"
		searchWhere = "AND (name ILIKE ? OR ver ILIKE ? OR purl ILIKE ? OR coalesce(s.document_name, '') ILIKE ? OR lic ILIKE ? OR disc ILIKE ?)"
		searchArgs = append(searchArgs, pattern, pattern, pattern, pattern, pattern, pattern)
	}

	baseQuery := fmt.Sprintf(`
		FROM (
			SELECT
				sbom_id,
				cluster,
				namespace,
				project,
				package_names,
				package_versions,
				package_purls,
				package_licenses,
				if(length(license_discrepancy) = length(package_names),
				   license_discrepancy,
				   arrayResize(CAST([], 'Array(String)'), length(package_names), '')) AS discrepancies,
				if(length(package_license_sources) = length(package_names),
				   package_license_sources,
				   arrayResize(CAST([], 'Array(LowCardinality(String))'), length(package_names), '')) AS srcs
			FROM sbom_packages FINAL
			WHERE arrayExists(x -> x != '', license_discrepancy)
			  %s
		) AS p
		ARRAY JOIN
			package_names AS name,
			package_versions AS ver,
			package_purls AS purl,
			package_licenses AS lic,
			discrepancies AS disc,
			srcs AS src
		LEFT JOIN (
			SELECT sbom_id, document_name FROM sboms FINAL
		) AS s ON p.sbom_id = s.sbom_id
		WHERE disc != ''
		  %s
	`, whereClause, searchWhere)

	countArgs := append([]any(nil), args...)
	countArgs = append(countArgs, searchArgs...)

	var total uint64
	countQuery := "SELECT count() " + baseQuery
	if err := c.Conn.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count license discrepancies: %w", err)
	}

	selectQuery := fmt.Sprintf(`
		SELECT
			toString(p.sbom_id) AS sbom_id,
			coalesce(s.document_name, '') AS document_name,
			p.project AS project,
			p.cluster AS cluster,
			p.namespace AS namespace,
			name,
			ver,
			purl,
			lic,
			disc,
			src
		%s
		ORDER BY s.document_name, name, ver
		LIMIT ? OFFSET ?
	`, baseQuery)

	queryArgs := append([]any(nil), countArgs...)
	queryArgs = append(queryArgs, pageSize, offset)

	rows, err := c.Conn.Query(ctx, selectQuery, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query license discrepancies: %w", err)
	}
	defer rows.Close()

	items := []dto.LicenseDiscrepancyItem{}
	for rows.Next() {
		var item dto.LicenseDiscrepancyItem
		if err := rows.Scan(
			&item.SBOMID,
			&item.DocumentName,
			&item.Project,
			&item.Cluster,
			&item.Namespace,
			&item.PackageName,
			&item.PackageVersion,
			&item.PURL,
			&item.DeclaredLicense,
			&item.DiscoveredLicense,
			&item.Source,
		); err != nil {
			return nil, fmt.Errorf("failed to scan license discrepancy row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &dto.PaginatedResponse[dto.LicenseDiscrepancyItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}
