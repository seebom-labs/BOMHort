package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// QueryClusters returns a list of all known clusters with summary statistics.
func (c *Client) QueryClusters(ctx context.Context) ([]dto.ClusterListItem, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			s.cluster,
			s.sbom_count,
			coalesce(p.pkg_count, 0) AS package_count,
			coalesce(v.vuln_count, 0) AS vuln_count,
			s.last_ingested
		FROM (
			SELECT cluster, count() AS sbom_count, max(ingested_at) AS last_ingested
			FROM sboms FINAL
			GROUP BY cluster
		) s
		LEFT JOIN (
			SELECT cluster, sum(length(package_names)) AS pkg_count
			FROM sbom_packages FINAL
			GROUP BY cluster
		) p ON s.cluster = p.cluster
		LEFT JOIN (
			SELECT cluster, count() AS vuln_count
			FROM vulnerabilities FINAL
			GROUP BY cluster
		) v ON s.cluster = v.cluster
		ORDER BY s.sbom_count DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query clusters: %w", err)
	}
	defer rows.Close()

	var items []dto.ClusterListItem
	for rows.Next() {
		var item dto.ClusterListItem
		var lastIngested time.Time
		if err := rows.Scan(&item.Name, &item.SBOMCount, &item.PackageCount, &item.VulnCount, &lastIngested); err != nil {
			return nil, fmt.Errorf("failed to scan cluster row: %w", err)
		}
		if !lastIngested.IsZero() {
			item.LastIngested = lastIngested.Format(time.RFC3339)
		}
		items = append(items, item)
	}

	if items == nil {
		items = []dto.ClusterListItem{}
	}
	return items, nil
}

// QueryClusterStats returns detailed statistics for a specific cluster.
func (c *Client) QueryClusterStats(ctx context.Context, cluster string) (*dto.ClusterStats, error) {
	stats := &dto.ClusterStats{
		Cluster:          cluster,
		LicenseBreakdown: make(map[string]uint64),
	}

	// Total SBOMs for this cluster.
	var lastIngested time.Time
	err := c.Conn.QueryRow(ctx,
		"SELECT count(), max(ingested_at) FROM sboms FINAL WHERE cluster = ?", cluster).
		Scan(&stats.TotalSBOMs, &lastIngested)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster sbom count: %w", err)
	}
	if !lastIngested.IsZero() {
		stats.LastIngested = lastIngested.Format(time.RFC3339)
	}

	// Total packages.
	_ = c.Conn.QueryRow(ctx,
		"SELECT sum(length(package_names)) FROM sbom_packages FINAL WHERE cluster = ?", cluster).
		Scan(&stats.TotalPackages)

	// Vulnerability counts by severity.
	_ = c.Conn.QueryRow(ctx,
		"SELECT count() FROM vulnerabilities FINAL WHERE cluster = ?", cluster).
		Scan(&stats.TotalVulnerabilities)

	sevRows, err := c.Conn.Query(ctx,
		"SELECT severity, count() AS cnt FROM vulnerabilities FINAL WHERE cluster = ? GROUP BY severity", cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster severity breakdown: %w", err)
	}
	defer sevRows.Close()

	for sevRows.Next() {
		var severity string
		var cnt uint64
		if err := sevRows.Scan(&severity, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan severity row: %w", err)
		}
		switch severity {
		case "CRITICAL":
			stats.CriticalVulns = cnt
		case "HIGH":
			stats.HighVulns = cnt
		case "MEDIUM":
			stats.MediumVulns = cnt
		case "LOW":
			stats.LowVulns = cnt
		}
	}

	// License breakdown.
	licRows, err := c.Conn.Query(ctx,
		"SELECT category, sum(package_count) AS cnt FROM license_compliance FINAL WHERE cluster = ? GROUP BY category", cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster license breakdown: %w", err)
	}
	defer licRows.Close()

	for licRows.Next() {
		var category string
		var cnt uint64
		if err := licRows.Scan(&category, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan license row: %w", err)
		}
		stats.LicenseBreakdown[category] = cnt
	}

	return stats, nil
}

// QueryClusterSBOMs returns a paginated list of SBOMs for a specific cluster.
func (c *Client) QueryClusterSBOMs(ctx context.Context, cluster string, page, pageSize uint64) (*dto.PaginatedResponse[dto.SBOMListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// Total count for this cluster.
	var total uint64
	if err := c.Conn.QueryRow(ctx,
		"SELECT count() FROM sboms FINAL WHERE cluster = ?", cluster).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count cluster sboms: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT
			s.sbom_id,
			s.source_file,
			s.spdx_version,
			s.document_name,
			coalesce(p.pkg_count, 0) AS package_count,
			coalesce(v.vuln_count, 0) AS vuln_count,
			s.ingested_at
		FROM sboms FINAL AS s
		LEFT JOIN (
			SELECT sbom_id, sum(length(package_names)) AS pkg_count
			FROM sbom_packages FINAL
			WHERE cluster = ?
			GROUP BY sbom_id
		) p ON s.sbom_id = p.sbom_id
		LEFT JOIN (
			SELECT sbom_id, count() AS vuln_count
			FROM vulnerabilities FINAL
			WHERE cluster = ?
			GROUP BY sbom_id
		) v ON s.sbom_id = v.sbom_id
		WHERE s.cluster = ?
		ORDER BY s.ingested_at DESC
		LIMIT ? OFFSET ?
	`, cluster, cluster, cluster, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query cluster sboms: %w", err)
	}
	defer rows.Close()

	var items []dto.SBOMListItem
	for rows.Next() {
		var item dto.SBOMListItem
		var ingestedAt time.Time
		if err := rows.Scan(&item.SBOMID, &item.SourceFile, &item.SPDXVersion,
			&item.DocumentName, &item.PackageCount, &item.VulnCount, &ingestedAt); err != nil {
			return nil, fmt.Errorf("failed to scan cluster sbom row: %w", err)
		}
		item.IngestedAt = ingestedAt.Format(time.RFC3339)
		items = append(items, item)
	}

	if items == nil {
		items = []dto.SBOMListItem{}
	}

	return &dto.PaginatedResponse[dto.SBOMListItem]{
		Data:     items,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}, nil
}

// Ping checks the ClickHouse connection health.
func (c *Client) Ping(ctx context.Context) error {
	return c.Conn.Ping(ctx)
}
