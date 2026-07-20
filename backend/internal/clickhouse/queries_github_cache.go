package clickhouse

import (
	"context"
	"fmt"
	"time"

	gh "github.com/seebom-labs/bomhort/backend/internal/github"
)

// QueryGitHubLicenseCache loads all cached GitHub repo→license mappings.
func (c *Client) QueryGitHubLicenseCache(ctx context.Context) (map[string]string, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT repo, spdx_id
		FROM github_license_cache FINAL
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query github license cache: %w", err)
	}
	defer rows.Close()

	cache := make(map[string]string)
	for rows.Next() {
		var repo, spdxID string
		if err := rows.Scan(&repo, &spdxID); err != nil {
			return nil, fmt.Errorf("failed to scan github license cache row: %w", err)
		}
		cache[repo] = spdxID
	}
	return cache, nil
}

// InsertGitHubLicenseCache batch-inserts resolved GitHub licenses into the cache.
func (c *Client) InsertGitHubLicenseCache(ctx context.Context, entries map[string]string) error {
	if len(entries) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO github_license_cache (repo, spdx_id)`)
	if err != nil {
		return fmt.Errorf("failed to prepare github license cache batch: %w", err)
	}

	for repo, spdxID := range entries {
		if err := batch.Append(repo, spdxID); err != nil {
			return fmt.Errorf("failed to append cache entry %s: %w", repo, err)
		}
	}

	return batch.Send()
}

// QueryGitHubRepoMetadata loads all cached repo metadata.
func (c *Client) QueryGitHubRepoMetadata(ctx context.Context) ([]*gh.RepoMetadata, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT repo, archived, fork, pushed_at, stargazers
		FROM github_repo_metadata FINAL
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query github repo metadata: %w", err)
	}
	defer rows.Close()

	var metadata []*gh.RepoMetadata
	for rows.Next() {
		m := &gh.RepoMetadata{}
		if err := rows.Scan(&m.Repo, &m.Archived, &m.Fork, &m.PushedAt, &m.Stargazers); err != nil {
			return nil, fmt.Errorf("failed to scan repo metadata: %w", err)
		}
		metadata = append(metadata, m)
	}
	return metadata, nil
}

// InsertGitHubRepoMetadata batch-inserts repo metadata.
func (c *Client) InsertGitHubRepoMetadata(ctx context.Context, entries []*gh.RepoMetadata) error {
	if len(entries) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO github_repo_metadata (repo, archived, fork, pushed_at, stargazers)`)
	if err != nil {
		return fmt.Errorf("failed to prepare repo metadata batch: %w", err)
	}

	for _, m := range entries {
		pushedAt := m.PushedAt
		if pushedAt.IsZero() {
			pushedAt = time.Now()
		}
		if err := batch.Append(m.Repo, m.Archived, m.Fork, pushedAt, m.Stargazers); err != nil {
			return fmt.Errorf("failed to append metadata %s: %w", m.Repo, err)
		}
	}

	return batch.Send()
}

// QueryArchivedPackages returns all packages that use archived GitHub repos.
func (c *Client) QueryArchivedPackages(ctx context.Context) ([]ArchivedPackageInfo, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT DISTINCT
			p.sbom_id,
			s.source_file,
			s.document_name AS project_name,
			'' AS project_version,
			pkg_name,
			pkg_purl,
			m.repo,
			m.pushed_at,
			m.stargazers
		FROM sbom_packages p FINAL
		ARRAY JOIN p.package_names AS pkg_name, p.package_purls AS pkg_purl
		JOIN sboms s FINAL ON p.sbom_id = s.sbom_id
		CROSS JOIN (
			SELECT repo, pushed_at, stargazers
			FROM github_repo_metadata FINAL
			WHERE archived = true
		) m
		WHERE lower(pkg_purl) LIKE concat('%', m.repo, '%')
		ORDER BY project_name, s.source_file
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query archived packages: %w", err)
	}
	defer rows.Close()

	var results []ArchivedPackageInfo
	for rows.Next() {
		var info ArchivedPackageInfo
		if err := rows.Scan(
			&info.SBOMID, &info.SourceFile, &info.ProjectName, &info.ProjectVersion,
			&info.PackageName, &info.PackagePURL, &info.Repo, &info.LastPushed, &info.Stars,
		); err != nil {
			return nil, fmt.Errorf("failed to scan archived package: %w", err)
		}
		results = append(results, info)
	}
	return results, nil
}

// ArchivedPackageInfo represents a package using an archived GitHub repo.
type ArchivedPackageInfo struct {
	SBOMID         string    `json:"sbom_id"`
	SourceFile     string    `json:"source_file"`
	ProjectName    string    `json:"project_name"`
	ProjectVersion string    `json:"project_version"`
	PackageName    string    `json:"package_name"`
	PackagePURL    string    `json:"package_purl"`
	Repo           string    `json:"repo"`
	LastPushed     time.Time `json:"last_pushed"`
	Stars          uint32    `json:"stars"`
}
