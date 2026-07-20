package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// globalSearchProjectKeyExpr derives a stable project key from an SBOM row
// aliased as `s`: S3 paths yield org/repo (or bucket-relative project), and
// document names of the form "Project - component version" yield "Project".
const globalSearchProjectKeyExpr = `
	multiIf(
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

// escapeLikePattern escapes ClickHouse ILIKE wildcards so user input is
// matched literally instead of acting as a wildcard. Backslash must be
// escaped first to avoid double-escaping the added escape characters.
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

// QueryGlobalSearch runs a faceted search across packages, projects,
// vulnerabilities, and licenses. Each facet returns at most `limit` items
// plus a total match count. Facet queries run concurrently.
func (c *Client) QueryGlobalSearch(ctx context.Context, query string, limit uint64) (*dto.GlobalSearchResponse, error) {
	if limit == 0 {
		limit = 5
	}
	pattern := "%" + escapeLikePattern(query) + "%"

	resp := &dto.GlobalSearchResponse{
		Query:           query,
		Packages:        []dto.GlobalSearchPackage{},
		Projects:        []dto.GlobalSearchProject{},
		Vulnerabilities: []dto.GlobalSearchVulnerability{},
		Licenses:        []dto.GlobalSearchLicense{},
	}

	var wg sync.WaitGroup
	errs := make([]error, 4)

	wg.Add(4)
	go func() {
		defer wg.Done()
		errs[0] = c.searchPackagesFacet(ctx, pattern, limit, resp)
	}()
	go func() {
		defer wg.Done()
		errs[1] = c.searchProjectsFacet(ctx, pattern, limit, resp)
	}()
	go func() {
		defer wg.Done()
		errs[2] = c.searchVulnerabilitiesFacet(ctx, pattern, limit, resp)
	}()
	go func() {
		defer wg.Done()
		errs[3] = c.searchLicensesFacet(ctx, pattern, limit, resp)
	}()
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (c *Client) searchPackagesFacet(ctx context.Context, pattern string, limit uint64, resp *dto.GlobalSearchResponse) error {
	if err := c.Conn.QueryRow(ctx, `
		SELECT count() FROM (
			SELECT dep_name
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			ARRAY JOIN p.package_names AS dep_name
			WHERE dep_name ILIKE ?
			GROUP BY dep_name
		)
	`, pattern).Scan(&resp.TotalPackages); err != nil {
		return fmt.Errorf("failed to count package search results: %w", err)
	}

	rows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		SELECT
			dep_name,
			any(dep_purl) AS purl,
			count(DISTINCT project_key) AS project_count
		FROM (
			SELECT
				dep_name,
				dep_purl,
				%s AS project_key
			FROM (SELECT * FROM sbom_packages FINAL) AS p
			INNER JOIN (SELECT sbom_id, source_file, document_name FROM sboms FINAL) AS s
				ON p.sbom_id = s.sbom_id
			ARRAY JOIN
				p.package_names AS dep_name,
				p.package_purls AS dep_purl
			WHERE dep_name ILIKE ?
		)
		GROUP BY dep_name
		ORDER BY project_count DESC, dep_name ASC
		LIMIT ?
	`, globalSearchProjectKeyExpr), pattern, limit)
	if err != nil {
		return fmt.Errorf("failed to search packages: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item dto.GlobalSearchPackage
		if err := rows.Scan(&item.PackageName, &item.PURL, &item.ProjectCount); err != nil {
			return fmt.Errorf("failed to scan package search row: %w", err)
		}
		resp.Packages = append(resp.Packages, item)
	}
	return rows.Err()
}

func (c *Client) searchProjectsFacet(ctx context.Context, pattern string, limit uint64, resp *dto.GlobalSearchResponse) error {
	if err := c.Conn.QueryRow(ctx, fmt.Sprintf(`
		SELECT count() FROM (
			SELECT %s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
			GROUP BY project_name
			HAVING project_name ILIKE ?
		)
	`, globalSearchProjectKeyExpr), pattern).Scan(&resp.TotalProjects); err != nil {
		return fmt.Errorf("failed to count project search results: %w", err)
	}

	rows, err := c.Conn.Query(ctx, fmt.Sprintf(`
		SELECT
			project_name,
			count() AS sbom_count,
			argMax(toString(s.sbom_id), s.ingested_at) AS latest_sbom_id
		FROM (
			SELECT
				s.sbom_id,
				s.ingested_at,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		) AS s
		GROUP BY project_name
		HAVING project_name ILIKE ?
		ORDER BY sbom_count DESC, project_name ASC
		LIMIT ?
	`, globalSearchProjectKeyExpr), pattern, limit)
	if err != nil {
		return fmt.Errorf("failed to search projects: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item dto.GlobalSearchProject
		if err := rows.Scan(&item.ProjectName, &item.SBOMCount, &item.LatestSBOMID); err != nil {
			return fmt.Errorf("failed to scan project search row: %w", err)
		}
		resp.Projects = append(resp.Projects, item)
	}
	return rows.Err()
}

func (c *Client) searchVulnerabilitiesFacet(ctx context.Context, pattern string, limit uint64, resp *dto.GlobalSearchResponse) error {
	if err := c.Conn.QueryRow(ctx, `
		SELECT count(DISTINCT vuln_id)
		FROM (SELECT * FROM vulnerabilities FINAL)
		WHERE vuln_id ILIKE ? OR summary ILIKE ?
	`, pattern, pattern).Scan(&resp.TotalVulnerabilities); err != nil {
		return fmt.Errorf("failed to count vulnerability search results: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT
			vuln_id,
			any(severity) AS vuln_severity,
			any(summary) AS vuln_summary,
			count(DISTINCT sbom_id) AS affected_sboms
		FROM (SELECT * FROM vulnerabilities FINAL)
		WHERE vuln_id ILIKE ? OR summary ILIKE ?
		GROUP BY vuln_id
		ORDER BY affected_sboms DESC, vuln_id ASC
		LIMIT ?
	`, pattern, pattern, limit)
	if err != nil {
		return fmt.Errorf("failed to search vulnerabilities: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item dto.GlobalSearchVulnerability
		if err := rows.Scan(&item.VulnID, &item.Severity, &item.Summary, &item.AffectedSBOMs); err != nil {
			return fmt.Errorf("failed to scan vulnerability search row: %w", err)
		}
		resp.Vulnerabilities = append(resp.Vulnerabilities, item)
	}
	return rows.Err()
}

func (c *Client) searchLicensesFacet(ctx context.Context, pattern string, limit uint64, resp *dto.GlobalSearchResponse) error {
	if err := c.Conn.QueryRow(ctx, `
		SELECT count(DISTINCT license_id)
		FROM (SELECT * FROM license_compliance FINAL)
		WHERE license_id ILIKE ?
	`, pattern).Scan(&resp.TotalLicenses); err != nil {
		return fmt.Errorf("failed to count license search results: %w", err)
	}

	rows, err := c.Conn.Query(ctx, `
		SELECT
			license_id,
			any(category) AS category,
			count(DISTINCT sbom_id) AS sbom_count
		FROM (SELECT * FROM license_compliance FINAL)
		WHERE license_id ILIKE ?
		GROUP BY license_id
		ORDER BY sbom_count DESC, license_id ASC
		LIMIT ?
	`, pattern, limit)
	if err != nil {
		return fmt.Errorf("failed to search licenses: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var item dto.GlobalSearchLicense
		if err := rows.Scan(&item.LicenseID, &item.Category, &item.SBOMCount); err != nil {
			return fmt.Errorf("failed to scan license search row: %w", err)
		}
		resp.Licenses = append(resp.Licenses, item)
	}
	return rows.Err()
}
