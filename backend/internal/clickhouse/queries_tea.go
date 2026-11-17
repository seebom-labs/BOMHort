package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TEAProductSummary holds project-level metadata for TEA product mapping (#534).
type TEAProductSummary struct {
	ProjectName     string
	Parent          string
	RootPURL        string
	ReleaseCount    uint64
	LatestVersion   string
	LatestTimestamp time.Time
	LatestSBOMID    uuid.UUID
}

// QueryTEAProducts returns distinct projects as TEA products with pagination (#534).
func (c *Client) QueryTEAProducts(ctx context.Context, page, pageSize uint64) ([]TEAProductSummary, uint64, error) {
	if pageSize == 0 {
		pageSize = 50
	}
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	// Total count of distinct projects
	var total uint64
	countQuery := fmt.Sprintf(`
		SELECT count() FROM (
			SELECT %s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
			GROUP BY project_name
		)
		WHERE project_name != ''
	`, projectKeyExpr)

	if err := c.Conn.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting tea products: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			project_name,
			any(parent),
			any(root_purl),
			count() AS sbom_count,
			max(ingested_at) AS latest_time
		FROM (
			SELECT
				s.parent AS parent,
				s.root_purl AS root_purl,
				s.ingested_at AS ingested_at,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		)
		WHERE project_name != ''
		GROUP BY project_name
		ORDER BY project_name ASC
		LIMIT ? OFFSET ?
	`, projectKeyExpr)

	rows, err := c.Conn.Query(ctx, query, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying tea products: %w", err)
	}
	defer rows.Close()

	var results []TEAProductSummary
	for rows.Next() {
		var sum TEAProductSummary
		var latestTime time.Time
		if err := rows.Scan(
			&sum.ProjectName,
			&sum.Parent,
			&sum.RootPURL,
			&sum.ReleaseCount,
			&latestTime,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning tea product: %w", err)
		}
		sum.LatestTimestamp = latestTime
		results = append(results, sum)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating tea products: %w", err)
	}

	return results, total, nil
}

// QueryTEAProductByName retrieves product summary for a specific project name (#534).
func (c *Client) QueryTEAProductByName(ctx context.Context, projectName string) (*TEAProductSummary, error) {
	query := fmt.Sprintf(`
		SELECT
			project_name,
			any(parent),
			any(root_purl),
			count() AS sbom_count,
			max(ingested_at) AS latest_time
		FROM (
			SELECT
				s.parent AS parent,
				s.root_purl AS root_purl,
				s.ingested_at AS ingested_at,
				%s AS project_name
			FROM (SELECT * FROM sboms FINAL) AS s
		)
		WHERE project_name = ?
		GROUP BY project_name
		LIMIT 1
	`, projectKeyExpr)

	var sum TEAProductSummary
	var latestTime time.Time
	err := c.Conn.QueryRow(ctx, query, projectName).Scan(
		&sum.ProjectName,
		&sum.Parent,
		&sum.RootPURL,
		&sum.ReleaseCount,
		&latestTime,
	)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrSBOMNotFound
		}
		return nil, fmt.Errorf("querying tea product by name %s: %w", projectName, err)
	}
	sum.LatestTimestamp = latestTime
	return &sum, nil
}

// QueryTEAAllReleases lists all SBOM releases across all projects ordered by timestamp (#534).
func (c *Client) QueryTEAAllReleases(ctx context.Context, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	if pageSize == 0 {
		pageSize = 50
	}
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	var total uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting tea releases: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			s.sbom_id,
			%s AS project_name,
			s.parent,
			s.document_version,
			s.root_purl,
			s.ingested_at,
			s.source_file,
			s.sha256_hash,
			s.document_name
		FROM (SELECT * FROM sboms FINAL) AS s
		ORDER BY s.ingested_at DESC
		LIMIT ? OFFSET ?
	`, projectKeyExpr)

	rows, err := c.Conn.Query(ctx, query, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying all tea releases: %w", err)
	}
	defer rows.Close()

	var out []models.SBOM
	for rows.Next() {
		var r models.SBOM
		if err := rows.Scan(
			&r.SBOMID,
			&r.Project,
			&r.Parent,
			&r.DocumentVersion,
			&r.RootPURL,
			&r.IngestedAt,
			&r.SourceFile,
			&r.SHA256Hash,
			&r.DocumentName,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning tea release: %w", err)
		}
		r.CreationDate = r.IngestedAt
		out = append(out, r)
	}

	return out, total, rows.Err()
}

// QueryTEAReleasesByProject lists the releases of a specific project (#534).
func (c *Client) QueryTEAReleasesByProject(ctx context.Context, projectName string, page, pageSize uint64) ([]models.SBOM, uint64, error) {
	if pageSize == 0 {
		pageSize = 50
	}
	if page == 0 {
		page = 1
	}
	offset := (page - 1) * pageSize

	countQuery := fmt.Sprintf(`
		SELECT count()
		FROM (SELECT * FROM sboms FINAL) AS s
		WHERE %s = ?
	`, projectKeyExpr)

	var total uint64
	if err := c.Conn.QueryRow(ctx, countQuery, projectName).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting tea project releases: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			s.sbom_id,
			%s AS project_name,
			s.parent,
			s.document_version,
			s.root_purl,
			s.ingested_at,
			s.source_file,
			s.sha256_hash,
			s.document_name
		FROM (SELECT * FROM sboms FINAL) AS s
		WHERE %s = ?
		ORDER BY s.ingested_at DESC
		LIMIT ? OFFSET ?
	`, projectKeyExpr, projectKeyExpr)

	rows, err := c.Conn.Query(ctx, query, projectName, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying tea releases for project %s: %w", projectName, err)
	}
	defer rows.Close()

	var out []models.SBOM
	for rows.Next() {
		var r models.SBOM
		if err := rows.Scan(
			&r.SBOMID,
			&r.Project,
			&r.Parent,
			&r.DocumentVersion,
			&r.RootPURL,
			&r.IngestedAt,
			&r.SourceFile,
			&r.SHA256Hash,
			&r.DocumentName,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning tea project release: %w", err)
		}
		r.CreationDate = r.IngestedAt
		out = append(out, r)
	}

	return out, total, rows.Err()
}

// QueryTEAReleaseBySBOMID retrieves an SBOM by its unique UUID (#534).
func (c *Client) QueryTEAReleaseBySBOMID(ctx context.Context, sbomID string) (*models.SBOM, error) {
	query := fmt.Sprintf(`
		SELECT
			s.sbom_id,
			%s AS project_name,
			s.parent,
			s.document_version,
			s.root_purl,
			s.ingested_at,
			s.source_file,
			s.sha256_hash,
			s.document_name
		FROM (SELECT * FROM sboms FINAL) AS s
		WHERE toString(s.sbom_id) = ?
		LIMIT 1
	`, projectKeyExpr)

	var r models.SBOM
	err := c.Conn.QueryRow(ctx, query, sbomID).Scan(
		&r.SBOMID,
		&r.Project,
		&r.Parent,
		&r.DocumentVersion,
		&r.RootPURL,
		&r.IngestedAt,
		&r.SourceFile,
		&r.SHA256Hash,
		&r.DocumentName,
	)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrSBOMNotFound
		}
		return nil, fmt.Errorf("querying tea release by id %s: %w", sbomID, err)
	}
	r.CreationDate = r.IngestedAt
	return &r, nil
}

// QueryTEAReleasesByPURL finds all releases matching a package URL (#534).
// It returns both root_purl and sbom_packages.package_purls matches, deduplicated,
// using delimiter-safe matching to prevent prefix collisions (e.g. foo@1 vs foo@10).
func (c *Client) QueryTEAReleasesByPURL(ctx context.Context, purl string) ([]models.SBOM, error) {
	seen := make(map[uuid.UUID]bool)
	var out []models.SBOM

	// 1. Direct root_purl check with delimiter safety
	queryRoot := fmt.Sprintf(`
		SELECT
			s.sbom_id,
			%s AS project_name,
			s.parent,
			s.document_version,
			s.root_purl,
			s.ingested_at,
			s.source_file,
			s.sha256_hash,
			s.document_name
		FROM (SELECT * FROM sboms FINAL) AS s
		WHERE s.root_purl = ?
		   OR startsWith(s.root_purl, concat(?, '@'))
		   OR startsWith(s.root_purl, concat(?, '?'))
		   OR startsWith(s.root_purl, concat(?, '#'))
		ORDER BY s.ingested_at DESC
	`, projectKeyExpr)

	rows, err := c.Conn.Query(ctx, queryRoot, purl, purl, purl, purl)
	if err != nil {
		return nil, fmt.Errorf("querying tea releases by root purl: %w", err)
	}

	for rows.Next() {
		var r models.SBOM
		if err := rows.Scan(
			&r.SBOMID,
			&r.Project,
			&r.Parent,
			&r.DocumentVersion,
			&r.RootPURL,
			&r.IngestedAt,
			&r.SourceFile,
			&r.SHA256Hash,
			&r.DocumentName,
		); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scanning root purl release: %w", err)
		}
		r.CreationDate = r.IngestedAt
		if !seen[r.SBOMID] {
			seen[r.SBOMID] = true
			out = append(out, r)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterating root purl releases: %w", err)
	}
	rows.Close()

	// 2. Transitive / package check in sbom_packages with delimiter safety
	queryPackages := fmt.Sprintf(`
		SELECT
			s.sbom_id,
			%s AS project_name,
			s.parent,
			s.document_version,
			s.root_purl,
			s.ingested_at,
			s.source_file,
			s.sha256_hash,
			s.document_name
		FROM (SELECT * FROM sboms FINAL) AS s
		JOIN (
			SELECT DISTINCT sbom_id
			FROM sbom_packages FINAL
			WHERE arrayExists(x -> x = ?
				OR startsWith(x, concat(?, '@'))
				OR startsWith(x, concat(?, '?'))
				OR startsWith(x, concat(?, '#')), package_purls)
		) AS p ON s.sbom_id = p.sbom_id
		ORDER BY s.ingested_at DESC
	`, projectKeyExpr)

	rows2, err := c.Conn.Query(ctx, queryPackages, purl, purl, purl, purl)
	if err != nil {
		return nil, fmt.Errorf("querying tea releases by package purl: %w", err)
	}
	defer rows2.Close()

	for rows2.Next() {
		var r models.SBOM
		if err := rows2.Scan(
			&r.SBOMID,
			&r.Project,
			&r.Parent,
			&r.DocumentVersion,
			&r.RootPURL,
			&r.IngestedAt,
			&r.SourceFile,
			&r.SHA256Hash,
			&r.DocumentName,
		); err != nil {
			return nil, fmt.Errorf("scanning package purl release: %w", err)
		}
		r.CreationDate = r.IngestedAt
		if !seen[r.SBOMID] {
			seen[r.SBOMID] = true
			out = append(out, r)
		}
	}

	if err := rows2.Err(); err != nil {
		return nil, fmt.Errorf("iterating package purl releases: %w", err)
	}

	return out, nil
}

// QueryTEAVEXStatementsCount returns the number of VEX statements scoped to an SBOM (#534).
func (c *Client) QueryTEAVEXStatementsCount(ctx context.Context, sbomID string) (int, error) {
	var count uint64
	err := c.Conn.QueryRow(ctx, "SELECT count() FROM vex_statements FINAL WHERE sbom_id = ?", sbomID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting tea vex statements: %w", err)
	}
	return int(count), nil
}
