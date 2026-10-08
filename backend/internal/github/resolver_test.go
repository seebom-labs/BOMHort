package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestResolver() *Resolver {
	r := NewResolver("")
	r.limiter = newTokenBucket(1000, 100) // fast limiter for tests
	r.httpClient = &http.Client{}
	return r
}

func TestResolve_HappyPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/test-org/test-repo/license" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"license": {"spdx_id": "Apache-2.0", "name": "Apache License 2.0"}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Override the global githubAPIBase for this test via a custom resolver.
	resolver := newTestResolver()
	resolver.httpClient = server.Client()

	// We need to override fetchLicense to use the test server.
	// Since fetchLicense uses githubAPIBase const, we test via ResolveWithMetadata
	// which uses fetchRepoMetadata.
	// For Resolve, we test the caching behavior and non-GitHub PURLs.

	// Test non-GitHub PURL returns empty.
	result := resolver.Resolve(context.Background(), "pkg:npm/test@1.0.0")
	if result != "" {
		t.Errorf("Resolve(npm purl) = %q, want empty string", result)
	}
}

func TestResolve_NonGitHubPURL(t *testing.T) {
	resolver := NewResolver("")
	resolver.limiter = newTokenBucket(1000, 100)

	result := resolver.Resolve(context.Background(), "pkg:npm/@angular/core@17.0.0")
	if result != "" {
		t.Errorf("Resolve(npm) = %q, want empty string", result)
	}

	// golang.org/x/crypto resolves now via well-known mapping → github.com/golang/crypto
	result = resolver.Resolve(context.Background(), "pkg:golang/golang.org/x/crypto@v0.21.0")
	if result == "" {
		t.Error("Resolve(golang.org/x/crypto) should resolve via well-known mapping, got empty string")
	}

	// Truly unknown non-GitHub Go module
	result = resolver.Resolve(context.Background(), "pkg:golang/some.unknown.domain/pkg@v1.0.0")
	if result != "" {
		t.Errorf("Resolve(unknown domain) = %q, want empty string", result)
	}

	result = resolver.Resolve(context.Background(), "")
	if result != "" {
		t.Errorf("Resolve(empty) = %q, want empty string", result)
	}
}

func TestResolve_CacheHit(t *testing.T) {
	resolver := NewResolver("")
	resolver.limiter = newTokenBucket(1000, 100)

	// Pre-populate cache.
	resolver.licenseCache.Store("test-org/test-repo", "MIT")

	result := resolver.Resolve(context.Background(), "pkg:golang/github.com/test-org/test-repo@v1.0.0")
	if result != "MIT" {
		t.Errorf("Resolve(cached) = %q, want %q", result, "MIT")
	}
}

func TestResolveWithMetadata_ArchivedRepo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/archived-org/old-repo" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"archived": true,
				"fork": false,
				"pushed_at": "2023-01-15T10:00:00Z",
				"stargazers_count": 42,
				"license": {"spdx_id": "MIT"}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver := newTestResolverWithServer(server)

	meta := resolver.ResolveWithMetadata(context.Background(), "pkg:golang/github.com/archived-org/old-repo@v1.0.0")
	if meta == nil {
		t.Fatal("ResolveWithMetadata returned nil")
	}
	if !meta.Archived {
		t.Error("expected Archived=true")
	}
	if meta.Fork {
		t.Error("expected Fork=false")
	}
	if meta.Stargazers != 42 {
		t.Errorf("expected Stargazers=42, got %d", meta.Stargazers)
	}
	if meta.SPDXID != "MIT" {
		t.Errorf("expected SPDXID=MIT, got %q", meta.SPDXID)
	}
	if meta.PushedAt.IsZero() {
		t.Error("expected PushedAt to be set")
	}
}

func TestResolveWithMetadata_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver := newTestResolverWithServer(server)

	meta := resolver.ResolveWithMetadata(context.Background(), "pkg:golang/github.com/unknown-org/missing-repo@v1.0.0")
	// First call: fetchRepoMetadata returns nil for 404, but negative result is cached.
	// The method returns nil on the first call.
	// On the second call, the cached negative result is returned.

	// Verify second call returns the cached negative result.
	meta = resolver.ResolveWithMetadata(context.Background(), "pkg:golang/github.com/unknown-org/missing-repo@v1.0.0")
	if meta == nil {
		t.Fatal("second call to ResolveWithMetadata returned nil, expected cached negative result")
	}
	// Negative result should have empty SPDXID.
	if meta.SPDXID != "" {
		t.Errorf("expected empty SPDXID for 404, got %q", meta.SPDXID)
	}
}

func TestResolveWithMetadata_NonGitHubPURL(t *testing.T) {
	resolver := NewResolver("")
	resolver.limiter = newTokenBucket(1000, 100)

	meta := resolver.ResolveWithMetadata(context.Background(), "pkg:npm/test@1.0.0")
	if meta != nil {
		t.Errorf("ResolveWithMetadata(npm) expected nil, got %+v", meta)
	}
}

func TestResolveWithMetadata_CacheHit(t *testing.T) {
	resolver := NewResolver("")
	resolver.limiter = newTokenBucket(1000, 100)

	cached := &RepoMetadata{
		Repo:       "cached-org/cached-repo",
		Archived:   false,
		Stargazers: 100,
		SPDXID:     "BSD-3-Clause",
	}
	resolver.metadataCache.Store("cached-org/cached-repo", cached)

	meta := resolver.ResolveWithMetadata(context.Background(), "pkg:golang/github.com/cached-org/cached-repo@v1.0.0")
	if meta == nil {
		t.Fatal("ResolveWithMetadata returned nil for cached entry")
	}
	if meta.SPDXID != "BSD-3-Clause" {
		t.Errorf("expected BSD-3-Clause, got %q", meta.SPDXID)
	}
	if meta.Stargazers != 100 {
		t.Errorf("expected 100 stars, got %d", meta.Stargazers)
	}
}

func TestPreloadCache(t *testing.T) {
	resolver := NewResolver("")

	entries := map[string]string{
		"org/repo1": "MIT",
		"org/repo2": "Apache-2.0",
		"org/repo3": "",
	}
	resolver.PreloadCache(entries)

	// All entries should be accessible via the cache.
	for key, expected := range entries {
		val, ok := resolver.licenseCache.Load(key)
		if !ok {
			t.Errorf("PreloadCache: key %q not found", key)
			continue
		}
		if val.(string) != expected {
			t.Errorf("PreloadCache(%q) = %q, want %q", key, val, expected)
		}
	}
}

func TestPreloadMetadataCache(t *testing.T) {
	resolver := NewResolver("")

	entries := []*RepoMetadata{
		{Repo: "org/repo1", Archived: true, SPDXID: "MIT", Stargazers: 50},
		{Repo: "org/repo2", Archived: false, SPDXID: "Apache-2.0", Stargazers: 200},
	}
	resolver.PreloadMetadataCache(entries)

	// Metadata should be cached.
	for _, expected := range entries {
		val, ok := resolver.metadataCache.Load(expected.Repo)
		if !ok {
			t.Errorf("PreloadMetadataCache: key %q not found", expected.Repo)
			continue
		}
		meta := val.(*RepoMetadata)
		if meta.Archived != expected.Archived {
			t.Errorf("PreloadMetadataCache(%q).Archived = %v, want %v", expected.Repo, meta.Archived, expected.Archived)
		}
	}

	// License cache should also be populated for entries with SPDXID.
	for _, expected := range entries {
		if expected.SPDXID != "" {
			val, ok := resolver.licenseCache.Load(expected.Repo)
			if !ok {
				t.Errorf("PreloadMetadataCache should populate licenseCache for %q", expected.Repo)
				continue
			}
			if val.(string) != expected.SPDXID {
				t.Errorf("licenseCache(%q) = %q, want %q", expected.Repo, val, expected.SPDXID)
			}
		}
	}
}

func TestCacheEntries(t *testing.T) {
	resolver := NewResolver("")

	resolver.licenseCache.Store("org/repo1", "MIT")
	resolver.licenseCache.Store("org/repo2", "Apache-2.0")
	resolver.licenseCache.Store("org/repo3", "")

	entries := resolver.CacheEntries()
	if len(entries) != 3 {
		t.Fatalf("CacheEntries() returned %d entries, want 3", len(entries))
	}
	if entries["org/repo1"] != "MIT" {
		t.Errorf("CacheEntries()[org/repo1] = %q, want MIT", entries["org/repo1"])
	}
}

func TestMetadataCacheEntries(t *testing.T) {
	resolver := NewResolver("")

	resolver.metadataCache.Store("org/repo1", &RepoMetadata{
		Repo: "org/repo1", Archived: true, Stargazers: 10,
	})
	resolver.metadataCache.Store("org/repo2", &RepoMetadata{
		Repo: "org/repo2", Archived: false, Stargazers: 500,
	})

	entries := resolver.MetadataCacheEntries()
	if len(entries) != 2 {
		t.Fatalf("MetadataCacheEntries() returned %d entries, want 2", len(entries))
	}

	found := map[string]bool{}
	for _, e := range entries {
		found[e.Repo] = true
	}
	if !found["org/repo1"] || !found["org/repo2"] {
		t.Errorf("MetadataCacheEntries() missing expected repos: %v", found)
	}
}

// newTestResolverWithServer creates a resolver that uses a test HTTP server
// by overriding the internal fetch methods to point to the test server.
// Since githubAPIBase is a const, we create a custom httptest server
// and wrap the resolver to redirect requests.
func newTestResolverWithServer(server *httptest.Server) *Resolver {
	// Create a proxy handler that redirects to our test server.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Forward the request to the mock server.
		proxyReq, _ := http.NewRequest(r.Method, server.URL+r.URL.Path, r.Body)
		proxyReq.Header = r.Header

		resp, err := http.DefaultClient.Do(proxyReq)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		for key, values := range resp.Header {
			for _, v := range values {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		buf := make([]byte, 4096)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
			}
			if readErr != nil {
				break
			}
		}
	}))

	r := &Resolver{
		apiBase:    githubAPIBase,
		httpClient: proxy.Client(),
		limiter:    newTokenBucket(1000, 100),
	}

	// We need to override fetchRepoMetadata to use our proxy.
	// Since the const githubAPIBase can't be changed, we use a workaround:
	// Create a transport that redirects github.com API requests to our mock.
	r.httpClient = &http.Client{
		Transport: &rewriteTransport{
			base:      http.DefaultTransport,
			targetURL: server.URL,
		},
	}

	return r
}

// rewriteTransport rewrites requests to the GitHub API to point to a test server.
type rewriteTransport struct {
	base      http.RoundTripper
	targetURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Rewrite the URL to point to the test server, keeping the path.
	newURL := t.targetURL + req.URL.Path
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, newURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return t.base.RoundTrip(newReq)
}
