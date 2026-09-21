package clickhouse

import (
	"context"
	"fmt"
	"time"

	gh "github.com/seebom-labs/bomhort/backend/internal/github"
)

// Archived-repo reporting: which packages in the corpus come from a GitHub
// repository that has been archived upstream.
//
// The hard part is mapping a package back to its repository. The resolver
// does it with github.ExtractGitHubRepo when it *writes* github_repo_metadata,
// so the read path has to reproduce the same mapping — and the mapping is not
// a substring relation. `pkg:golang/gopkg.in/yaml.v3` belongs to the repo
// `go-yaml/yaml` and shares not one character with it; `k8s.io/api` belongs to
// `kubernetes/api`. Matching `purl LIKE '%' || repo || '%'` therefore finds
// only packages whose import path happens to spell out their repository, and
// silently reports nothing for everything the well-known table exists to
// translate.
//
// So the mapping is rebuilt in SQL, in the same order ExtractGitHubRepo uses:
//
//  1. pkg:golang/github.com/{owner}/{repo}… and pkg:github/{owner}/{repo} →
//     first two path segments.
//  2. otherwise the well-known module table, exact match or prefix match,
//     retried with a trailing /vN major-version segment stripped.
//
// The result is a real equality join against github_repo_metadata instead of a
// cross join with a wildcard LIKE, which is both correct and cheaper.
//
// purlRepoKeyQuery yields one row per (sbom_id, package) with the repo key it
// resolves to, or '' when the package is not a recognisable GitHub package.
// Parameter order: wkPrefixes, wkPrefixes, wkRepos, wkRepos.
const purlRepoKeyQuery = `
	SELECT
		sbom_id,
		package_name,
		package_purl,
		multiIf(
			direct_owner != '' AND direct_repo != '',
				concat(direct_owner, '/', direct_repo),
			wk_idx > 0,
				wk_repos[wk_idx],
			wk_idx_stripped > 0,
				wk_repos[wk_idx_stripped],
			''
		) AS repo_key
	FROM (
		SELECT
			sbom_id,
			package_name,
			package_purl,
			arrayElement(splitByChar('/', direct_path), 1) AS direct_owner,
			arrayElement(splitByChar('/', direct_path), 2) AS direct_repo,
			arrayFirstIndex(
				i -> module_path = wk_prefixes[i]
				     OR startsWith(module_path, concat(wk_prefixes[i], '/')),
				arrayEnumerate(wk_prefixes)
			) AS wk_idx,
			arrayFirstIndex(
				i -> module_path_stripped = wk_prefixes[i]
				     OR startsWith(module_path_stripped, concat(wk_prefixes[i], '/')),
				arrayEnumerate(wk_prefixes)
			) AS wk_idx_stripped,
			wk_repos
		FROM (
			SELECT
				sbom_id,
				package_name,
				package_purl,
				direct_path,
				module_path,
				if(
					length(splitByChar('/', module_path)) >= 2
						AND match(arrayElement(splitByChar('/', module_path), -1), '^v[0-9]'),
					arrayStringConcat(
						arraySlice(splitByChar('/', module_path), 1, length(splitByChar('/', module_path)) - 1),
						'/'
					),
					module_path
				) AS module_path_stripped,
				CAST(? AS Array(String)) AS wk_prefixes,
				CAST(? AS Array(String)) AS wk_repos
			FROM (
				SELECT
					sbom_id,
					package_name,
					package_purl,
					multiIf(
						startsWith(purl_clean, 'pkg:golang/github.com/'), substring(purl_clean, 23),
						startsWith(purl_clean, 'pkg:github/'),            substring(purl_clean, 12),
						''
					) AS direct_path,
					if(startsWith(purl_clean, 'pkg:golang/'), substring(purl_clean, 12), '') AS module_path
				FROM (
					SELECT
						sbom_id,
						package_name,
						package_purl,
						-- Cut at the first '@' (version), '?' (qualifiers) or
						-- '#' (subpath), mirroring ExtractGitHubRepo. length()
						-- is in the list so an unqualified purl keeps its tail.
						-- Everything is toInt64: position() and length() are
						-- UInt64, the subtraction is Int64, and ClickHouse
						-- refuses to build a common array type from both.
						substring(purl_lower, 1, arrayMin(arrayFilter(x -> x > 0, [
							toInt64(if(position(purl_lower, '@') > 1, position(purl_lower, '@') - 1, 0)),
							toInt64(if(position(purl_lower, '?') > 1, position(purl_lower, '?') - 1, 0)),
							toInt64(if(position(purl_lower, '#') > 1, position(purl_lower, '#') - 1, 0)),
							toInt64(length(purl_lower))
						]))) AS purl_clean
					FROM (
						SELECT
							p.sbom_id       AS sbom_id,
							pkg_name        AS package_name,
							pkg_purl        AS package_purl,
							lower(pkg_purl) AS purl_lower
						FROM sbom_packages p FINAL
						ARRAY JOIN p.package_names AS pkg_name, p.package_purls AS pkg_purl
						WHERE pkg_purl != ''
					)
				)
			)
		)
	)
`

// QueryArchivedPackages returns every package in the corpus whose GitHub
// repository has been archived upstream.
func (c *Client) QueryArchivedPackages(ctx context.Context) ([]ArchivedPackageInfo, error) {
	prefixes, repoKeys := gh.WellKnownModuleMappings()

	rows, err := c.Conn.Query(ctx, `
		SELECT DISTINCT
			k.sbom_id,
			s.source_file,
			s.document_name AS project_name,
			s.document_version AS project_version,
			k.package_name,
			k.package_purl,
			a.repo,
			a.pushed_at,
			a.stargazers
		FROM (`+purlRepoKeyQuery+`) k
		INNER JOIN (
			SELECT repo, pushed_at, stargazers
			FROM github_repo_metadata FINAL
			WHERE archived = true
		) a ON k.repo_key = a.repo
		INNER JOIN sboms s FINAL ON k.sbom_id = s.sbom_id
		WHERE k.repo_key != ''
		ORDER BY project_name, s.source_file, k.package_name
	`, prefixes, repoKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to query archived packages: %w", err)
	}
	defer rows.Close()

	results := []ArchivedPackageInfo{}
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
	return results, rows.Err()
}

// QueryArchivedReposInUse counts the archived repositories that are actually
// referenced by a package in the corpus.
//
// Deliberately not `count() FROM github_repo_metadata WHERE archived`: that
// table is a resolver cache keyed by repo, not a view of the corpus. It
// outlives the SBOMs that populated it, so after data is re-ingested or
// removed it happily reports archived repos that nothing depends on any more —
// a banner offering to show three problems, followed by an empty list.
func (c *Client) QueryArchivedReposInUse(ctx context.Context) (uint64, error) {
	prefixes, repoKeys := gh.WellKnownModuleMappings()

	var count uint64
	err := c.Conn.QueryRow(ctx, `
		SELECT uniqExact(a.repo)
		FROM (`+purlRepoKeyQuery+`) k
		INNER JOIN (
			SELECT repo
			FROM github_repo_metadata FINAL
			WHERE archived = true
		) a ON k.repo_key = a.repo
		WHERE k.repo_key != ''
	`, prefixes, repoKeys).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count archived repos in use: %w", err)
	}
	return count, nil
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


