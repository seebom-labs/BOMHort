package clickhouse

import (
	"context"
	"fmt"
	"sort"
	"time"

	gh "github.com/seebom-labs/bomhort/backend/internal/github"
)

// Archived-repo reporting: which packages in the corpus come from a GitHub
// repository that has been archived upstream.
//
// The hard part is mapping a package back to its repository. The resolver
// does it with github.ExtractGitHubRepo when it *writes* github_repo_metadata,
// and the mapping is not a substring relation: `pkg:golang/gopkg.in/yaml.v3`
// belongs to `go-yaml/yaml`, `k8s.io/api` to `kubernetes/api`.
//
// This used to be rebuilt in SQL: every package row of the corpus evaluated
// two lambdas over the whole well-known prefix table. ClickHouse materialises
// the constant arrays per row inside such lambdas, so on a production-sized
// corpus (millions of package rows) the query blew through the gateway's
// 512 MiB max_memory_usage — and QueryArchivedReposInUse runs it on every
// dashboard load.
//
// The mapping now runs in Go, with the very function the writer uses, on the
// only input it needs: the distinct, version-stripped golang/github purls.
//
//  1. Load the archived repos (a small set). None → nothing to scan.
//  2. Stream DISTINCT cleaned purls, map each with ExtractGitHubRepo and keep
//     those whose repo is archived.
//  3. Fetch the package rows of only those purls, in batches.

// archivedPurlFilter keeps the ecosystems ExtractGitHubRepo can map at all.
const archivedPurlFilter = `(startsWith(purl_lower, 'pkg:golang/') OR startsWith(purl_lower, 'pkg:github/'))`

// archivedPurlCleanExpr cuts purl_lower at the first '@' (version), '?'
// (qualifiers) or '#' (subpath), mirroring ExtractGitHubRepo. length() is in
// the list so an unqualified purl keeps its tail. Everything is toInt64:
// position() and length() are UInt64, the subtraction is Int64, and
// ClickHouse refuses to build a common array type from both.
const archivedPurlCleanExpr = `
	substring(purl_lower, 1, arrayMin(arrayFilter(x -> x > 0, [
		toInt64(if(position(purl_lower, '@') > 1, position(purl_lower, '@') - 1, 0)),
		toInt64(if(position(purl_lower, '?') > 1, position(purl_lower, '?') - 1, 0)),
		toInt64(if(position(purl_lower, '#') > 1, position(purl_lower, '#') - 1, 0)),
		toInt64(length(purl_lower))
	])))`

// archivedPurlBatchSize bounds the IN list of step 3, so the interpolated
// query stays far below ClickHouse's max_query_size.
const archivedPurlBatchSize = 500

type archivedRepo struct {
	pushedAt time.Time
	stars    uint32
}

// queryArchivedRepos loads github_repo_metadata's archived repos, keyed by
// the lowercase "owner/repo" key the resolver writes.
func (c *Client) queryArchivedRepos(ctx context.Context) (map[string]archivedRepo, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT repo, pushed_at, stargazers
		FROM github_repo_metadata FINAL
		WHERE archived = true
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query archived repos: %w", err)
	}
	defer rows.Close()

	repos := map[string]archivedRepo{}
	for rows.Next() {
		var (
			key string
			r   archivedRepo
		)
		if err := rows.Scan(&key, &r.pushedAt, &r.stars); err != nil {
			return nil, fmt.Errorf("failed to scan archived repo: %w", err)
		}
		repos[key] = r
	}
	return repos, rows.Err()
}

// queryArchivedPurls returns cleaned purl → archived repo key for every
// distinct golang/github purl in the corpus that maps to an archived repo.
func (c *Client) queryArchivedPurls(ctx context.Context, archived map[string]archivedRepo, sbomID string) (map[string]string, error) {
	scope, args := archivedSBOMScope(sbomID)
	rows, err := c.Conn.Query(ctx, `
		SELECT DISTINCT `+archivedPurlCleanExpr+` AS purl_clean
		FROM (
			SELECT lower(pkg_purl) AS purl_lower
			FROM sbom_packages FINAL
			ARRAY JOIN package_purls AS pkg_purl
			WHERE `+archivedPurlFilter+scope+`
		)
	`, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query package purls: %w", err)
	}
	defer rows.Close()

	matches := map[string]string{}
	for rows.Next() {
		var purl string
		if err := rows.Scan(&purl); err != nil {
			return nil, fmt.Errorf("failed to scan package purl: %w", err)
		}
		if repo, ok := archivedRepoFor(purl, archived); ok {
			matches[purl] = repo
		}
	}
	return matches, rows.Err()
}

// archivedRepoFor maps one cleaned purl to its repo key with the resolver's
// own ExtractGitHubRepo and reports whether that repo is archived.
func archivedRepoFor[V any](purl string, archived map[string]V) (string, bool) {
	owner, repo, ok := gh.ExtractGitHubRepo(purl)
	if !ok {
		return "", false
	}
	key := gh.RepoKey(owner, repo)
	if _, isArchived := archived[key]; !isArchived {
		return "", false
	}
	return key, true
}

// QueryArchivedPackages returns every package in the corpus whose GitHub
// repository has been archived upstream. A non-empty sbomID restricts the
// scan to that SBOM — its packages are one primary-key range instead of the
// whole corpus.
//
// The unscoped list is built by one caller at a time: on a production corpus
// it materialises ~100k rows (~200 MiB of allocations per call), and a
// handful of concurrent calls OOM-killed a 512 MiB gateway.
func (c *Client) QueryArchivedPackages(ctx context.Context, sbomID string) ([]ArchivedPackageInfo, error) {
	if sbomID == "" {
		c.archivedListMu.Lock()
		defer c.archivedListMu.Unlock()
	}
	results := []ArchivedPackageInfo{}

	archived, err := c.queryArchivedRepos(ctx)
	if err != nil || len(archived) == 0 {
		return results, err
	}
	matches, err := c.queryArchivedPurls(ctx, archived, sbomID)
	if err != nil || len(matches) == 0 {
		return results, err
	}

	purls := make([]string, 0, len(matches))
	for p := range matches {
		purls = append(purls, p)
	}
	sort.Strings(purls)

	for start := 0; start < len(purls); start += archivedPurlBatchSize {
		batch := purls[start:min(start+archivedPurlBatchSize, len(purls))]
		if err := c.scanArchivedPackages(ctx, batch, sbomID, func(info ArchivedPackageInfo, purl string) {
			repo := matches[purl]
			info.Repo = repo
			info.LastPushed = archived[repo].pushedAt
			info.Stars = archived[repo].stars
			results = append(results, info)
		}); err != nil {
			return nil, err
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.ProjectName != b.ProjectName {
			return a.ProjectName < b.ProjectName
		}
		if a.SourceFile != b.SourceFile {
			return a.SourceFile < b.SourceFile
		}
		return a.PackageName < b.PackageName
	})
	return results, nil
}

// archivedSBOMScope returns the sbom_id predicate and its argument for an
// optional SBOM scope; "" scopes nothing.
func archivedSBOMScope(sbomID string) (string, []any) {
	if sbomID == "" {
		return "", nil
	}
	return " AND sbom_id = ?", []any{sbomID}
}

// scanArchivedPackages fetches the package rows whose cleaned purl is in
// purls, with their SBOM's display columns.
func (c *Client) scanArchivedPackages(ctx context.Context, purls []string, sbomID string, emit func(ArchivedPackageInfo, string)) error {
	scope, args := archivedSBOMScope(sbomID)
	rows, err := c.Conn.Query(ctx, `
		SELECT DISTINCT
			k.sbom_id,
			s.source_file,
			s.document_name,
			s.document_version,
			k.package_name,
			k.package_purl,
			k.purl_clean
		FROM (
			SELECT sbom_id, package_name, package_purl, `+archivedPurlCleanExpr+` AS purl_clean
			FROM (
				SELECT
					p.sbom_id       AS sbom_id,
					pkg_name        AS package_name,
					pkg_purl        AS package_purl,
					lower(pkg_purl) AS purl_lower
				FROM sbom_packages p FINAL
				ARRAY JOIN p.package_names AS pkg_name, p.package_purls AS pkg_purl
				WHERE `+archivedPurlFilter+scope+`
			)
			WHERE purl_clean IN (?)
		) k
		INNER JOIN (
			SELECT sbom_id, source_file, document_name, document_version
			FROM sboms FINAL
		) s ON k.sbom_id = s.sbom_id
	`, append(args, purls)...)
	if err != nil {
		return fmt.Errorf("failed to query archived packages: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			info ArchivedPackageInfo
			purl string
		)
		if err := rows.Scan(
			&info.SBOMID, &info.SourceFile, &info.ProjectName, &info.ProjectVersion,
			&info.PackageName, &info.PackagePURL, &purl,
		); err != nil {
			return fmt.Errorf("failed to scan archived package: %w", err)
		}
		emit(info, purl)
	}
	return rows.Err()
}

// QueryArchivedReposInUse counts the archived repositories that are actually
// referenced by a package in the corpus.
//
// Deliberately not `count() FROM github_repo_metadata WHERE archived`: that
// table is a resolver cache keyed by repo, not a view of the corpus. It
// outlives the SBOMs that populated it, so after data is re-ingested or
// removed it happily reports archived repos that nothing depends on any more —
// a banner offering to show three problems, followed by an empty list.
//
// Cached for archivedInUseTTL: the answer changes once a day with the
// cve-refresher, and every dashboard view asked for it.
// shortcut: callers wait on the mutex during a refresh and a failed
// refresh is not cached; fine for one query every 5 min, serve the stale
// value instead if dashboards ever stall on it.
func (c *Client) QueryArchivedReposInUse(ctx context.Context) (uint64, error) {
	c.archivedMu.Lock()
	defer c.archivedMu.Unlock()
	if time.Since(c.archivedAt) < archivedInUseTTL {
		return c.archivedCount, nil
	}
	n, err := c.queryArchivedReposInUse(ctx)
	if err != nil {
		return 0, err
	}
	c.archivedCount, c.archivedAt = n, time.Now()
	return n, nil
}

const archivedInUseTTL = 5 * time.Minute

func (c *Client) queryArchivedReposInUse(ctx context.Context) (uint64, error) {
	archived, err := c.queryArchivedRepos(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to count archived repos in use: %w", err)
	}
	if len(archived) == 0 {
		return 0, nil
	}
	matches, err := c.queryArchivedPurls(ctx, archived, "")
	if err != nil {
		return 0, fmt.Errorf("failed to count archived repos in use: %w", err)
	}
	inUse := map[string]struct{}{}
	for _, repo := range matches {
		inUse[repo] = struct{}{}
	}
	return uint64(len(inUse)), nil
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
