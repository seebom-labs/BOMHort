package osv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	json "github.com/goccy/go-json"
)

const (
	// DefaultBaseURL is the OSV API base URL.
	DefaultBaseURL = "https://api.osv.dev"
	// BatchEndpoint is the batch query endpoint.
	BatchEndpoint = "/v1/querybatch"
	// maxRetries is the maximum number of retries for transient errors.
	maxRetries = 5
	// baseBackoff is the initial backoff duration.
	baseBackoff = 500 * time.Millisecond
)

// rateLimiter is a simple token-bucket limiter shared across all workers
// in the same process. Each worker gets its own Client, but they share
// this limiter via the package-level variable.
var (
	globalLimiter     *tokenBucket
	globalLimiterOnce sync.Once
)

func getGlobalLimiter() *tokenBucket {
	globalLimiterOnce.Do(func() {
		// Allow 10 requests per second with burst of 5.
		globalLimiter = newTokenBucket(10, 5)
	})
	return globalLimiter
}

// tokenBucket is a simple rate limiter.
type tokenBucket struct {
	rate       float64 // tokens per second
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
		// Calculate wait time for next token.
		wait := time.Duration((1.0 - tb.tokens) / tb.rate * float64(time.Second))
		tb.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// Client communicates with the OSV API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	limiter    *tokenBucket

	// vulnCache is a process-level cache of hydrated vulnerability details.
	// This prevents fetching the same vuln ID multiple times across SBOMs.
	vulnCache   map[string]*VulnEntry
	vulnCacheMu sync.RWMutex
}

// NewClient creates a new OSV API client with shared rate limiting.
func NewClient() *Client {
	return &Client{
		baseURL: DefaultBaseURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		limiter:   getGlobalLimiter(),
		vulnCache: make(map[string]*VulnEntry),
	}
}

// BatchQuery represents a single query in a batch request.
type BatchQuery struct {
	Package PackageQuery `json:"package"`
}

// PackageQuery identifies a package by PURL.
type PackageQuery struct {
	PURL string `json:"purl"`
}

// BatchRequest is the request body for /v1/querybatch.
type BatchRequest struct {
	Queries []BatchQuery `json:"queries"`
}

// BatchResponse is the response from /v1/querybatch.
type BatchResponse struct {
	Results []QueryResult `json:"results"`
}

// QueryResult contains the vulnerabilities for a single query.
type QueryResult struct {
	Vulns []VulnEntry `json:"vulns"`
}

// VulnEntry represents a single vulnerability from OSV.
type VulnEntry struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
	// Aliases lists the other identifiers assigned to the same flaw
	// (GHSA-… ↔ CVE-… ↔ GO-…). Dropping them made VEX matching an exact
	// string comparison, so a statement about the CVE never suppressed
	// the finding OSV reported under its GHSA id.
	Aliases          []string               `json:"aliases"`
	Severity         []Severity             `json:"severity"`
	Affected         []Affected             `json:"affected"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
}

// Severity holds CVSS severity information.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected holds affected version ranges.
type Affected struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
}

// AffectedPackage identifies the affected package.
type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

// Range holds version range information.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event represents a version event (introduced/fixed).
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// QueryBatch sends a batch of PURLs to the OSV API and returns the results.
// PURLs are sent in chunks of maxBatchSize to respect API limits.
// Includes rate limiting and exponential backoff retry for transient errors.
// NOTE: The batch endpoint returns minimal data (id + modified only).
// Use HydrateVulns() to fetch full details (severity, affected, etc.).
func (c *Client) QueryBatch(ctx context.Context, purls []string) (*BatchResponse, error) {
	if len(purls) == 0 {
		return &BatchResponse{}, nil
	}

	// Build the batch request.
	queries := make([]BatchQuery, 0, len(purls))
	for _, purl := range purls {
		if purl == "" {
			continue
		}
		queries = append(queries, BatchQuery{
			Package: PackageQuery{PURL: purl},
		})
	}

	if len(queries) == 0 {
		return &BatchResponse{}, nil
	}

	req := BatchRequest{Queries: queries}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	// Wait for rate limiter.
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter cancelled: %w", err)
	}

	// Retry loop with exponential backoff.
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(float64(baseBackoff) * math.Pow(2, float64(attempt-1)))
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			log.Printf("  OSV retry %d/%d after %v", attempt, maxRetries, backoff)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			// Re-acquire rate limiter token for retry.
			if err := c.limiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiter cancelled on retry: %w", err)
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.baseURL+BatchEndpoint, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("OSV batch query failed: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var batchResp BatchResponse
			if decErr := json.NewDecoder(resp.Body).Decode(&batchResp); decErr != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("failed to decode OSV response: %w", decErr)
			}
			resp.Body.Close()
			return &batchResp, nil
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Retryable status codes: 429 (rate limit) and 503 (overloaded).
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			lastErr = fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		// Non-retryable error.
		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil, fmt.Errorf("OSV API failed after %d retries: %w", maxRetries, lastErr)
}

// GetVulnerability fetches full vulnerability details from OSV by ID.
// Unlike QueryBatch, this returns complete data including severity and affected.
func (c *Client) GetVulnerability(ctx context.Context, id string) (*VulnEntry, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limiter cancelled: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(float64(baseBackoff) * math.Pow(2, float64(attempt-1)))
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			if err := c.limiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("rate limiter cancelled on retry: %w", err)
			}
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
			c.baseURL+"/v1/vulns/"+id, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %w", err)
		}

		resp, err := c.httpClient.Do(httpReq)
		if err != nil {
			lastErr = fmt.Errorf("OSV get vulnerability failed: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var entry VulnEntry
			if decErr := json.NewDecoder(resp.Body).Decode(&entry); decErr != nil {
				resp.Body.Close()
				return nil, fmt.Errorf("failed to decode OSV vulnerability: %w", decErr)
			}
			resp.Body.Close()
			return &entry, nil
		}

		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			lastErr = fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))
			continue
		}

		return nil, fmt.Errorf("OSV API returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil, fmt.Errorf("OSV API failed after %d retries: %w", maxRetries, lastErr)
}

// HydrateVulns fetches full vulnerability details for a set of vuln IDs.
// It deduplicates by ID, returns cached entries for previously fetched IDs,
// and fetches only new IDs concurrently (max 10). Results are cached for
// the lifetime of the Client so the same vuln is never fetched twice,
// even across different SBOMs.
func (c *Client) HydrateVulns(ctx context.Context, ids []string) (map[string]*VulnEntry, error) {
	// Deduplicate IDs and separate cached vs uncached.
	result := make(map[string]*VulnEntry, len(ids))
	var toFetch []string

	c.vulnCacheMu.RLock()
	for _, id := range ids {
		if _, done := result[id]; done {
			continue // duplicate in input
		}
		if cached, ok := c.vulnCache[id]; ok {
			result[id] = cached
		} else {
			result[id] = nil // placeholder, will be filled or remain nil
			toFetch = append(toFetch, id)
		}
	}
	c.vulnCacheMu.RUnlock()

	if len(toFetch) == 0 {
		if len(result) > 0 {
			log.Printf("  Hydration: %d IDs all served from cache", len(result))
		}
		return result, nil
	}

	log.Printf("  Hydrating %d new vulnerability IDs (%d cached)...", len(toFetch), len(result)-len(toFetch))

	// Limit concurrency to avoid overwhelming the API.
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	hydrated := 0

	for _, id := range toFetch {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(vulnID string) {
			defer wg.Done()
			defer func() { <-sem }()

			entry, err := c.GetVulnerability(ctx, vulnID)
			if err != nil {
				log.Printf("  WARNING: Failed to hydrate %s: %v", vulnID, err)
				return
			}

			// Store in both the result map and the persistent cache.
			mu.Lock()
			result[vulnID] = entry
			hydrated++
			if hydrated%100 == 0 {
				log.Printf("  Hydrated %d/%d vulnerabilities...", hydrated, len(toFetch))
			}
			mu.Unlock()

			c.vulnCacheMu.Lock()
			c.vulnCache[vulnID] = entry
			c.vulnCacheMu.Unlock()
		}(id)
	}

	wg.Wait()
	log.Printf("  Hydration complete: %d/%d fetched, %d from cache",
		hydrated, len(toFetch), len(result)-hydrated)

	// Clean nil placeholders for IDs that failed hydration.
	for id, entry := range result {
		if entry == nil {
			delete(result, id)
		}
	}

	return result, nil
}
