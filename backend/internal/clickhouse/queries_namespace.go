package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// Namespace queries are the second half of the ownership drill-down: clusters
// answer "where is it deployed", namespaces answer "which tenant/team owns it".
//
// Unlike a cluster name, a namespace name is only unique *within* a cluster —
// `payments` legitimately exists in prod-eu, prod-us and staging at the same
// time. Every endpoint therefore takes an optional cluster filter. Without it
// the namespace is aggregated across the whole fleet (which is what a platform
// team wants); with it the view is scoped to one cluster (which is what the
// owning team wants).

// QueryNamespaces returns all known namespaces with summary statistics.
// An empty clusterFilter aggregates across all clusters.
func (c *Client) QueryNamespaces(ctx context.Context, clusterFilter string) ([]dto.NamespaceListItem, error) {
	// A single parameterised query with a "no filter" escape hatch keeps the
	// two cases from drifting apart. `? = ''` is evaluated once per query by
	// ClickHouse, not per row.
	rows, err := c.Conn.Query(ctx, `
		SELECT
			s.namespace,
			s.cluster_count,
			s.sbom_count,
			coalesce(p.pkg_count, 0)  AS package_count,
			coalesce(v.vuln_count, 0) AS vuln_count,
			s.last_ingested
		FROM (
			SELECT
				namespace,
				uniqExact(cluster) AS cluster_count,
				count()            AS sbom_count,
				max(ingested_at)   AS last_ingested
			FROM sboms FINAL
			WHERE ? = '' OR cluster = ?
			GROUP BY namespace
		) s
		LEFT JOIN (
			SELECT namespace, sum(length(package_names)) AS pkg_count
			FROM sbom_packages FINAL
			WHERE ? = '' OR cluster = ?
			GROUP BY namespace
		) p ON s.namespace = p.namespace
		LEFT JOIN (
			SELECT namespace, count() AS vuln_count
			FROM vulnerabilities FINAL
			WHERE ? = '' OR cluster = ?
			GROUP BY namespace
		) v ON s.namespace = v.namespace
		ORDER BY s.sbom_count DESC
	`, clusterFilter, clusterFilter, clusterFilter, clusterFilter, clusterFilter, clusterFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to query namespaces: %w", err)
	}
	defer rows.Close()

	var items []dto.NamespaceListItem
	for rows.Next() {
		var item dto.NamespaceListItem
		var lastIngested time.Time
		if err := rows.Scan(&item.Name, &item.ClusterCount, &item.SBOMCount,
			&item.PackageCount, &item.VulnCount, &lastIngested); err != nil {
			return nil, fmt.Errorf("failed to scan namespace row: %w", err)
		}
		if !lastIngested.IsZero() {
			item.LastIngested = lastIngested.Format(time.RFC3339)
		}
		item.Cluster = clusterFilter
		items = append(items, item)
	}

	if items == nil {
		items = []dto.NamespaceListItem{}
	}
	return items, nil
}

// QueryNamespaceStats returns detailed statistics for one namespace, optionally
// scoped to a single cluster.
func (c *Client) QueryNamespaceStats(ctx context.Context, namespace, clusterFilter string) (*dto.NamespaceStats, error) {
	stats := &dto.NamespaceStats{
		Namespace:        namespace,
		Cluster:          clusterFilter,
		Clusters:         []string{},
		LicenseBreakdown: make(map[string]uint64),
	}

	var lastIngested time.Time
	err := c.Conn.QueryRow(ctx, `
		SELECT count(), max(ingested_at), groupUniqArray(cluster)
		FROM sboms FINAL
		WHERE namespace = ? AND (? = '' OR cluster = ?)
	`, namespace, clusterFilter, clusterFilter).
		Scan(&stats.TotalSBOMs, &lastIngested, &stats.Clusters)
	if err != nil {
		return nil, fmt.Errorf("failed to query namespace sbom count: %w", err)
	}
	if !lastIngested.IsZero() {
		stats.LastIngested = lastIngested.Format(time.RFC3339)
	}

	_ = c.Conn.QueryRow(ctx, `
		SELECT sum(length(package_names))
		FROM sbom_packages FINAL
		WHERE namespace = ? AND (? = '' OR cluster = ?)
	`, namespace, clusterFilter, clusterFilter).Scan(&stats.TotalPackages)

	_ = c.Conn.QueryRow(ctx, `
		SELECT count()
		FROM vulnerabilities FINAL
		WHERE namespace = ? AND (? = '' OR cluster = ?)
	`, namespace, clusterFilter, clusterFilter).Scan(&stats.TotalVulnerabilities)

	sevRows, err := c.Conn.Query(ctx, `
		SELECT severity, count() AS cnt
		FROM vulnerabilities FINAL
		WHERE namespace = ? AND (? = '' OR cluster = ?)
		GROUP BY severity
	`, namespace, clusterFilter, clusterFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to query namespace severity breakdown: %w", err)
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

	licRows, err := c.Conn.Query(ctx, `
		SELECT category, sum(package_count) AS cnt
		FROM license_compliance FINAL
		WHERE namespace = ? AND (? = '' OR cluster = ?)
		GROUP BY category
	`, namespace, clusterFilter, clusterFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to query namespace license breakdown: %w", err)
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

// QueryNamespaceSBOMs returns a paginated list of SBOMs in one namespace,
// optionally scoped to a single cluster.
func (c *Client) QueryNamespaceSBOMs(ctx context.Context, namespace, clusterFilter string, page, pageSize uint64) (*dto.PaginatedResponse[dto.SBOMListItem], error) {
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var total uint64
	if err := c.Conn.QueryRow(ctx, `
		SELECT count() FROM sboms FINAL
		WHERE namespace = ? AND (? = '' OR cluster = ?)
	`, namespace, clusterFilter, clusterFilter).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count namespace sboms: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT
			s.sbom_id,
			s.source_file,
			s.spdx_version,
			s.document_name,
			coalesce(p.pkg_count, 0)  AS package_count,
			coalesce(v.vuln_count, 0) AS vuln_count,
			s.ingested_at,
			s.source_repo,
			s.source_ref,
			s.cluster,
			s.namespace,
			s.project
		FROM (SELECT * FROM sboms FINAL) AS s
		LEFT JOIN (
			SELECT sbom_id, sum(length(package_names)) AS pkg_count
			FROM sbom_packages FINAL
			WHERE namespace = ? AND (? = '' OR cluster = ?)
			GROUP BY sbom_id
		) p ON s.sbom_id = p.sbom_id
		LEFT JOIN (
			SELECT sbom_id, count() AS vuln_count
			FROM vulnerabilities FINAL
			WHERE namespace = ? AND (? = '' OR cluster = ?)
			GROUP BY sbom_id
		) v ON s.sbom_id = v.sbom_id
		WHERE s.namespace = ? AND (? = '' OR s.cluster = ?)
		ORDER BY s.ingested_at DESC
		LIMIT ? OFFSET ?
	`,
		namespace, clusterFilter, clusterFilter,
		namespace, clusterFilter, clusterFilter,
		namespace, clusterFilter, clusterFilter,
		pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query namespace sboms: %w", err)
	}
	defer rows.Close()

	var items []dto.SBOMListItem
	for rows.Next() {
		var item dto.SBOMListItem
		var ingestedAt time.Time
		if err := rows.Scan(&item.SBOMID, &item.SourceFile, &item.SPDXVersion,
			&item.DocumentName, &item.PackageCount, &item.VulnCount, &ingestedAt,
			&item.SourceRepo, &item.SourceRef,
			&item.Cluster, &item.Namespace, &item.Project); err != nil {
			return nil, fmt.Errorf("failed to scan namespace sbom row: %w", err)
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

// QueryFleetTree returns the full cluster → namespace → project hierarchy in a
// single round trip. The UI renders the whole ownership tree at once; issuing
// one query per cluster would turn a fleet view into an N+1 problem.
func (c *Client) QueryFleetTree(ctx context.Context) ([]dto.FleetCluster, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT
			s.cluster,
			s.namespace,
			s.project,
			s.sbom_count,
			coalesce(v.vuln_count, 0) AS vuln_count,
			s.last_ingested
		FROM (
			SELECT cluster, namespace, project,
			       count() AS sbom_count, max(ingested_at) AS last_ingested
			FROM sboms FINAL
			GROUP BY cluster, namespace, project
		) s
		LEFT JOIN (
			SELECT cluster, namespace, project, count() AS vuln_count
			FROM vulnerabilities FINAL
			GROUP BY cluster, namespace, project
		) v ON s.cluster = v.cluster AND s.namespace = v.namespace AND s.project = v.project
		ORDER BY s.cluster, s.namespace, s.project
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query fleet tree: %w", err)
	}
	defer rows.Close()

	var (
		clusters []dto.FleetCluster
		ci, ni   = -1, -1
	)
	for rows.Next() {
		var (
			cluster, namespace, project string
			sbomCount, vulnCount        uint64
			lastIngested                time.Time
		)
		if err := rows.Scan(&cluster, &namespace, &project, &sbomCount, &vulnCount, &lastIngested); err != nil {
			return nil, fmt.Errorf("failed to scan fleet tree row: %w", err)
		}

		// Rows arrive grouped by the ORDER BY, so the tree is built by
		// appending to the current branch instead of map lookups.
		if ci < 0 || clusters[ci].Name != cluster {
			clusters = append(clusters, dto.FleetCluster{Name: cluster, Namespaces: []dto.FleetNamespace{}})
			ci++
			ni = -1
		}
		if ni < 0 || clusters[ci].Namespaces[ni].Name != namespace {
			clusters[ci].Namespaces = append(clusters[ci].Namespaces, dto.FleetNamespace{Name: namespace, Projects: []dto.FleetProject{}})
			ni++
		}

		clusters[ci].Namespaces[ni].Projects = append(clusters[ci].Namespaces[ni].Projects, dto.FleetProject{
			Name:      project,
			SBOMCount: sbomCount,
			VulnCount: vulnCount,
			LastIngested: func() string {
				if lastIngested.IsZero() {
					return ""
				}
				return lastIngested.Format(time.RFC3339)
			}(),
		})

		clusters[ci].Namespaces[ni].SBOMCount += sbomCount
		clusters[ci].Namespaces[ni].VulnCount += vulnCount
		clusters[ci].SBOMCount += sbomCount
		clusters[ci].VulnCount += vulnCount
	}

	if clusters == nil {
		clusters = []dto.FleetCluster{}
	}
	return clusters, nil
}
