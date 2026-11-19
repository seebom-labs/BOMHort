package clickhouse

import (
	"context"
	"fmt"
	"strings"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// QueryLicenseDiscrepancies returns packages where the discovered license differs
// from the declared license. The declared license remains authoritative for
// compliance (#530).
func (c *Client) QueryLicenseDiscrepancies(ctx context.Context, sbomID, project, cluster, namespace string) ([]dto.LicenseDiscrepancyItem, error) {
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

	q := fmt.Sprintf(`
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
		ORDER BY s.document_name, name, ver
	`, whereClause)

	rows, err := c.Conn.Query(ctx, q, args...)
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
	return items, rows.Err()
}
