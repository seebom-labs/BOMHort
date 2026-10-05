package clickhouse

import (
	"context"
	"fmt"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// unrecordedSource labels packages from SBOMs ingested before
// package_license_sources existed (migration 024).
const unrecordedSource = "unrecorded"

// QueryLicenseSources aggregates sbom_packages.package_license_sources across
// all SBOMs: per source (or unresolved reason) the number of packages, the
// number of SBOMs and the most frequent package names.
func (c *Client) QueryLicenseSources(ctx context.Context) ([]dto.LicenseSourceItem, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			if(src = '', ?, src) AS source,
			count() AS package_count,
			uniqExact(sbom_id) AS sbom_count,
			topK(5)(name) AS examples
		FROM (
			SELECT
				sbom_id,
				package_names,
				if(length(package_license_sources) = length(package_names),
				   package_license_sources,
				   arrayResize(CAST([], 'Array(String)'), length(package_names), '')) AS srcs
			FROM sbom_packages FINAL
		)
		ARRAY JOIN package_names AS name, srcs AS src
		GROUP BY source
		ORDER BY package_count DESC
	`, unrecordedSource)
	if err != nil {
		return nil, fmt.Errorf("failed to query license sources: %w", err)
	}
	defer rows.Close()

	items := []dto.LicenseSourceItem{}
	for rows.Next() {
		var item dto.LicenseSourceItem
		if err := rows.Scan(&item.Source, &item.PackageCount, &item.SBOMCount, &item.Examples); err != nil {
			return nil, fmt.Errorf("failed to scan license source row: %w", err)
		}
		describeLicenseSource(&item)
		items = append(items, item)
	}
	return items, rows.Err()
}

// describeLicenseSource fills Origin, Modifiers and Resolved from Source.
func describeLicenseSource(item *dto.LicenseSourceItem) {
	parts := strings.Split(item.Source, "+")
	item.Origin = parts[0]
	item.Modifiers = append([]string{}, parts[1:]...)
	item.Resolved = item.Origin != unrecordedSource && !license.IsUnresolvedReason(item.Origin)
	if item.Examples == nil {
		item.Examples = []string{}
	}
}
