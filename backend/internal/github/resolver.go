package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/licensetext"
)

const (
	githubAPIBase = "https://api.github.com"
	// Unauthenticated: 60 req/hour → ~1 req/min to be safe.
	defaultRate = 0.8
	// Authenticated: 5000 req/hour → ~1.3 req/s to be safe.
	authenticatedRate = 1.2
	defaultBurst      = 3
)

// licenseResponse is the GitHub API response for /repos/{owner}/{repo}/license.
// Besides the classification, GitHub returns the license file itself
// (base64), which lets us classify texts GitHub only labels as "Other".
type licenseResponse struct {
	License  *licenseInfo `json:"license"`
	Content  string       `json:"content"`
	Encoding string       `json:"encoding"`
}

type licenseInfo struct {
	SPDXID string `json:"spdx_id"`
	Name   string `json:"name"`
}

// repoResponse is the GitHub API response for /repos/{owner}/{repo}.
type repoResponse struct {
	Archived   bool         `json:"archived"`
	Fork       bool         `json:"fork"`
	PushedAt   string       `json:"pushed_at"`
	Stargazers int          `json:"stargazers_count"`
	License    *repoLicense `json:"license"`
}

type repoLicense struct {
	SPDXID string `json:"spdx_id"`
}

// RepoMetadata contains health indicators for a GitHub repository.
type RepoMetadata struct {
	Repo       string
	Archived   bool
	Fork       bool
	PushedAt   time.Time
	Stargazers int
	SPDXID     string
}

// knownLicenseOverrides maps GitHub repos (lowercase "owner/repo") to their correct
// SPDX license IDs. GitHub's license detection sometimes returns "Other" / NOASSERTION
// for repos with non-standard LICENSE file formats or dual-license setups.
// These have been verified manually.
var knownLicenseOverrides = map[string]string{
	"opencontainers/go-digest": "Apache-2.0",
	"shopspring/decimal":       "MIT",
	"go-yaml/yaml":             "Apache-2.0",
	"go-tomb/tomb":             "BSD-3-Clause",
	"go-inf/inf":               "BSD-3-Clause",
	"go-check/check":           "BSD-2-Clause",
}

// ErrRateLimited is returned while GitHub's rate limit is exhausted. The
// resolver does not wait it out and does not cache anything for the
// repository in question: an answer GitHub could not give is not a negative
// result, and a caller that treated it as one would resolve the package from
// a worse source. Callers defer their work until RateLimitResetAt.
var ErrRateLimited = errors.New("github: rate limited")

// rateLimitFallback is how long the resolver stays rate-limited when GitHub
// sends no usable X-RateLimit-Reset header.
const rateLimitFallback = time.Hour

// Resolver resolves unknown package licenses by querying the GitHub API.
type Resolver struct {
	token         string
	apiBase       string
	httpClient    *http.Client
	licenseCache  sync.Map // map[string]string (repo key → SPDX ID or "")
	metadataCache sync.Map // map[string]*RepoMetadata
	limiter       *tokenBucket

	mu               sync.Mutex
	rateLimitedUntil time.Time
}

// NewResolver creates a new GitHub license resolver.
// If token is provided, the rate limit is significantly higher.
func NewResolver(token string) *Resolver {
	rate := defaultRate
	if token != "" {
		rate = authenticatedRate
	}
	return &Resolver{
		token:   token,
		apiBase: githubAPIBase,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		limiter: newTokenBucket(rate, defaultBurst),
	}
}

// Resolve attempts to find the SPDX license ID for a package via the GitHub API.
// Returns the SPDX ID (e.g., "Apache-2.0") or empty string if not resolvable.
// Results are cached in-memory to avoid duplicate API calls.
//
// Resolve swallows ErrRateLimited (it returns ""); callers that must not
// mistake a rate limit for "no license" use ResolveErr.
func (r *Resolver) Resolve(ctx context.Context, purl string) string {
	spdxID, _ := r.ResolveErr(ctx, purl)
	return spdxID
}

// ResolveErr is Resolve returning ErrRateLimited instead of "" while GitHub's
// rate limit is exhausted. Nothing is cached in that case.
func (r *Resolver) ResolveErr(ctx context.Context, purl string) (string, error) {
	owner, repo, ok := ExtractGitHubRepo(purl)
	if !ok {
		return "", nil
	}

	key := strings.ToLower(owner + "/" + repo)

	// Check in-memory cache.
	if cached, found := r.licenseCache.Load(key); found {
		return cached.(string), nil
	}

	if r.isRateLimited() {
		return "", ErrRateLimited
	}

	// Rate-limit the request.
	if err := r.limiter.Wait(ctx); err != nil {
		return "", nil
	}

	spdxID, err := r.fetchLicense(ctx, owner, repo)
	if err != nil {
		return "", err
	}

	// Fallback: use manually verified overrides for repos where GitHub
	// returns "Other" / NOASSERTION despite having a valid LICENSE file.
	if spdxID == "" {
		if override, ok := knownLicenseOverrides[key]; ok {
			spdxID = override
		}
	}

	r.licenseCache.Store(key, spdxID)

	if spdxID != "" {
		log.Printf("  GitHub license resolved: %s/%s → %s", owner, repo, spdxID)
	}

	return spdxID, nil
}

// ResolveWithMetadata fetches license AND repo metadata (archived, fork, last push).
// Use this for comprehensive package health checks.
//
// ResolveWithMetadata swallows ErrRateLimited (it returns nil); callers that
// must not mistake a rate limit for "unknown repository" use
// ResolveWithMetadataErr.
func (r *Resolver) ResolveWithMetadata(ctx context.Context, purl string) *RepoMetadata {
	meta, _ := r.ResolveWithMetadataErr(ctx, purl)
	return meta
}

// ResolveWithMetadataErr is ResolveWithMetadata returning ErrRateLimited
// instead of nil while GitHub's rate limit is exhausted. Nothing is cached in
// that case, so the repository is looked up for real once the limit resets.
func (r *Resolver) ResolveWithMetadataErr(ctx context.Context, purl string) (*RepoMetadata, error) {
	owner, repo, ok := ExtractGitHubRepo(purl)
	if !ok {
		return nil, nil
	}

	key := strings.ToLower(owner + "/" + repo)

	// Check in-memory cache.
	if cached, found := r.metadataCache.Load(key); found {
		return cached.(*RepoMetadata), nil
	}

	if r.isRateLimited() {
		return nil, ErrRateLimited
	}

	// Rate-limit the request.
	if err := r.limiter.Wait(ctx); err != nil {
		return nil, nil
	}

	meta, err := r.fetchRepoMetadata(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	if meta != nil {
		r.metadataCache.Store(key, meta)
		r.licenseCache.Store(key, meta.SPDXID) // Also populate license cache

		if meta.Archived {
			log.Printf("  ⚠️  GitHub repo ARCHIVED: %s/%s", owner, repo)
		}
		if meta.SPDXID != "" {
			log.Printf("  GitHub license resolved: %s/%s → %s", owner, repo, meta.SPDXID)
		}
	} else {
		// Cache negative result
		r.metadataCache.Store(key, &RepoMetadata{Repo: key})
	}

	return meta, nil
}

// RateLimitResetAt reports when GitHub's rate limit is expected to reset, or
// the zero time when the resolver is not rate-limited.
func (r *Resolver) RateLimitResetAt() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Now().Before(r.rateLimitedUntil) {
		return r.rateLimitedUntil
	}
	return time.Time{}
}

func (r *Resolver) isRateLimited() bool {
	return !r.RateLimitResetAt().IsZero()
}

// PreloadCache loads known repo→license mappings (e.g., from ClickHouse).
func (r *Resolver) PreloadCache(entries map[string]string) {
	for k, v := range entries {
		r.licenseCache.Store(strings.ToLower(k), v)
	}
}

// PreloadMetadataCache loads repo metadata from ClickHouse.
func (r *Resolver) PreloadMetadataCache(entries []*RepoMetadata) {
	for _, m := range entries {
		r.metadataCache.Store(strings.ToLower(m.Repo), m)
		if m.SPDXID != "" {
			r.licenseCache.Store(strings.ToLower(m.Repo), m.SPDXID)
		}
	}
}

// CacheEntries returns all cached license entries (for persisting to ClickHouse).
func (r *Resolver) CacheEntries() map[string]string {
	entries := make(map[string]string)
	r.licenseCache.Range(func(key, value any) bool {
		entries[key.(string)] = value.(string)
		return true
	})
	return entries
}

// MetadataCacheEntries returns all cached metadata entries (for persisting to ClickHouse).
func (r *Resolver) MetadataCacheEntries() []*RepoMetadata {
	var entries []*RepoMetadata
	r.metadataCache.Range(func(key, value any) bool {
		if m, ok := value.(*RepoMetadata); ok && m != nil {
			entries = append(entries, m)
		}
		return true
	})
	return entries
}

func (r *Resolver) fetchLicense(ctx context.Context, owner, repo string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/license", r.apiBase, owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()

	if isRateLimitResponse(resp) {
		r.noteRateLimit(resp)
		return "", ErrRateLimited
	}

	if resp.StatusCode != http.StatusOK {
		// 404 = private repo or not found – cache empty to avoid retries.
		io.Copy(io.Discard, resp.Body)
		return "", nil
	}

	var lr licenseResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", nil
	}

	if lr.License != nil && lr.License.SPDXID != "" && lr.License.SPDXID != "NOASSERTION" {
		return lr.License.SPDXID, nil
	}

	// GitHub labelled the file "Other" (custom preamble, reformatted text, …).
	// Best effort: classify the license text ourselves.
	if spdxID := detectFromContent(lr.Content, lr.Encoding); spdxID != "" {
		log.Printf("  GitHub license for %s/%s classified from text: %s", owner, repo, spdxID)
		return spdxID, nil
	}
	return "", nil
}

// detectFromContent decodes the license file returned by the GitHub API and
// runs the phrase-based classifier on it.
func detectFromContent(content, encoding string) string {
	if content == "" {
		return ""
	}
	text := content
	if encoding == "base64" || encoding == "" {
		// GitHub wraps base64 at 60 chars with newlines.
		compact := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, content)
		decoded, err := base64.StdEncoding.DecodeString(compact)
		if err != nil {
			return ""
		}
		text = string(decoded)
	}
	return licensetext.Detect(text)
}

// fetchRepoMetadata gets full repo info including archived status.
func (r *Resolver) fetchRepoMetadata(ctx context.Context, owner, repo string) (*RepoMetadata, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", r.apiBase, owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	if isRateLimitResponse(resp) {
		r.noteRateLimit(resp)
		return nil, ErrRateLimited
	}

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, nil
	}

	var rr repoResponse
	if err := json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return nil, nil
	}

	meta := &RepoMetadata{
		Repo:       strings.ToLower(owner + "/" + repo),
		Archived:   rr.Archived,
		Fork:       rr.Fork,
		Stargazers: rr.Stargazers,
	}

	// Parse pushed_at timestamp
	if rr.PushedAt != "" {
		if t, err := time.Parse(time.RFC3339, rr.PushedAt); err == nil {
			meta.PushedAt = t
		}
	}

	// Extract license from repo response.
	if rr.License != nil && rr.License.SPDXID != "" && rr.License.SPDXID != "NOASSERTION" {
		meta.SPDXID = rr.License.SPDXID
	}

	// Fallback: if the repo API didn't return a usable license, try the dedicated
	// /repos/{owner}/{repo}/license endpoint which does deeper file analysis.
	if meta.SPDXID == "" {
		if err := r.limiter.Wait(ctx); err == nil {
			spdxID, err := r.fetchLicense(ctx, owner, repo)
			if err != nil {
				return nil, err
			}
			meta.SPDXID = spdxID
		}
	}

	// Last resort: use manually verified overrides for repos where GitHub
	// returns "Other" / NOASSERTION despite having a valid LICENSE file.
	if meta.SPDXID == "" {
		key := strings.ToLower(owner + "/" + repo)
		if override, ok := knownLicenseOverrides[key]; ok {
			meta.SPDXID = override
		}
	}

	return meta, nil
}

// isRateLimitResponse recognises GitHub's two rate-limit signals: 429, and
// 403 with the remaining quota reported as 0 (primary limit) or a Retry-After
// header (secondary limit). A plain 403 is an access problem, not a limit.
func isRateLimitResponse(resp *http.Response) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode != http.StatusForbidden {
		return false
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.Header.Get("Retry-After") != ""
}

// noteRateLimit records until when the resolver is rate-limited, from
// X-RateLimit-Reset (epoch seconds) or Retry-After (seconds), falling back
// to rateLimitFallback. It never sleeps: the worker holding a job must put
// the job back rather than stall the whole queue.
func (r *Resolver) noteRateLimit(resp *http.Response) {
	until := time.Now().Add(rateLimitFallback)
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if resetUnix, err := strconv.ParseInt(v, 10, 64); err == nil {
			if t := time.Unix(resetUnix, 0); t.After(time.Now()) {
				until = t.Add(time.Second)
			}
		}
	} else if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			until = time.Now().Add(time.Duration(secs) * time.Second)
		}
	}
	r.mu.Lock()
	if until.After(r.rateLimitedUntil) {
		r.rateLimitedUntil = until
	}
	r.mu.Unlock()
	log.Printf("  GitHub rate limited until %s; jobs needing GitHub are deferred", until.Format(time.RFC3339))
}

// tokenBucket is a simple rate limiter (same pattern as osv package).
type tokenBucket struct {
	rate       float64
	burst      int
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastRefill: time.Now(),
	}
}

func (tb *tokenBucket) Wait(ctx context.Context) error {
	for {
		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastRefill).Seconds()
		tb.tokens += elapsed * tb.rate
		if tb.tokens > float64(tb.burst) {
			tb.tokens = float64(tb.burst)
		}
		tb.lastRefill = now

		if tb.tokens >= 1.0 {
			tb.tokens -= 1.0
			tb.mu.Unlock()
			return nil
		}
		wait := time.Duration((1.0 - tb.tokens) / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
