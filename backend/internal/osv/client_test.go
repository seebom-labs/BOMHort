package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestQueryBatch_EmptyPURLs(t *testing.T) {
	client := NewClient()
	resp, err := client.QueryBatch(context.Background(), []string{})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestQueryBatch_MockServer(t *testing.T) {
	// Create a mock OSV server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != BatchEndpoint {
			t.Errorf("expected path %s, got %s", BatchEndpoint, r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"results": [
				{
					"vulns": [
						{
							"id": "CVE-2024-1234",
							"summary": "Test vulnerability",
							"severity": [{"type": "CVSS_V3", "score": "7.5"}]
						}
					]
				}
			]
		}`))
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL,
		httpClient: server.Client(),
		limiter:    getGlobalLimiter(),
		vulnCache:  make(map[string]*VulnEntry),
	}

	resp, err := client.QueryBatch(context.Background(), []string{"pkg:npm/test@1.0.0"})
	if err != nil {
		t.Fatalf("QueryBatch() returned error: %v", err)
	}

	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	if len(resp.Results[0].Vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(resp.Results[0].Vulns))
	}
	if resp.Results[0].Vulns[0].ID != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", resp.Results[0].Vulns[0].ID)
	}
}

func TestQueryBatch_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "internal server error"}`))
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL,
		httpClient: server.Client(),
		limiter:    getGlobalLimiter(),
		vulnCache:  make(map[string]*VulnEntry),
	}

	_, err := client.QueryBatch(context.Background(), []string{"pkg:npm/test@1.0.0"})
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestQueryBatch_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response that should be cancelled.
		<-r.Context().Done()
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL,
		httpClient: server.Client(),
		limiter:    getGlobalLimiter(),
		vulnCache:  make(map[string]*VulnEntry),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := client.QueryBatch(ctx, []string{"pkg:npm/test@1.0.0"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestQueryBatch_NoVulns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"results": [{"vulns": []}]}`))
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL,
		httpClient: server.Client(),
		limiter:    getGlobalLimiter(),
		vulnCache:  make(map[string]*VulnEntry),
	}

	resp, err := client.QueryBatch(context.Background(), []string{"pkg:npm/safe-package@1.0.0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(resp.Results))
	}
	if len(resp.Results[0].Vulns) != 0 {
		t.Errorf("expected 0 vulns for safe package, got %d", len(resp.Results[0].Vulns))
	}
}

func TestHydrateVulns_CachesPreviousResults(t *testing.T) {
	// Track how many times each vuln ID is requested.
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "GHSA-test-1234",
			"summary": "Test vuln",
			"severity": [{"type": "CVSS_V3", "score": "7.5"}],
			"affected": []
		}`))
	}))
	defer server.Close()

	client := &Client{
		baseURL:    server.URL,
		httpClient: server.Client(),
		limiter:    getGlobalLimiter(),
		vulnCache:  make(map[string]*VulnEntry),
	}

	// First call: should fetch from API.
	result1, err := client.HydrateVulns(context.Background(), []string{"GHSA-test-1234"})
	if err != nil {
		t.Fatalf("HydrateVulns() first call error: %v", err)
	}
	if _, ok := result1["GHSA-test-1234"]; !ok {
		t.Fatal("expected GHSA-test-1234 in result")
	}
	if fetchCount != 1 {
		t.Errorf("expected 1 API fetch, got %d", fetchCount)
	}

	// Second call with same ID: should use cache, no new API call.
	result2, err := client.HydrateVulns(context.Background(), []string{"GHSA-test-1234"})
	if err != nil {
		t.Fatalf("HydrateVulns() second call error: %v", err)
	}
	if _, ok := result2["GHSA-test-1234"]; !ok {
		t.Fatal("expected GHSA-test-1234 in cached result")
	}
	if fetchCount != 1 {
		t.Errorf("expected still 1 API fetch (cached), got %d", fetchCount)
	}

	// Third call with duplicate IDs: should still use cache.
	result3, err := client.HydrateVulns(context.Background(), []string{"GHSA-test-1234", "GHSA-test-1234"})
	if err != nil {
		t.Fatalf("HydrateVulns() third call error: %v", err)
	}
	if len(result3) != 1 {
		t.Errorf("expected 1 unique result, got %d", len(result3))
	}
	if fetchCount != 1 {
		t.Errorf("expected still 1 API fetch (deduped+cached), got %d", fetchCount)
	}
}

func TestPURLToQuery(t *testing.T) {
	tests := []struct {
		name          string
		purl          string
		wantEcosystem string
		wantName      string
		wantVersion   string
		wantPURL      string
	}{
		{
			name:          "Debian with distro debian-12.7",
			purl:          "pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12.7",
			wantEcosystem: "Debian:12",
			wantName:      "openssl",
			wantVersion:   "3.0.11-1~deb12u1",
		},
		{
			name:          "Debian with codename bookworm",
			purl:          "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=bookworm",
			wantEcosystem: "Debian:12",
			wantName:      "openssl",
			wantVersion:   "3.0.11-1~deb12u1",
		},
		{
			name:          "Alpine with distro alpine-3.19.1",
			purl:          "pkg:apk/alpine/openssl@3.1.4-r0?arch=x86_64&distro=alpine-3.19.1",
			wantEcosystem: "Alpine:v3.19",
			wantName:      "openssl",
			wantVersion:   "3.1.4-r0",
		},
		{
			name:          "Alpine with distro 3.20.0",
			purl:          "pkg:apk/alpine/curl@8.7.1-r0?distro=3.20.0",
			wantEcosystem: "Alpine:v3.20",
			wantName:      "curl",
			wantVersion:   "8.7.1-r0",
		},
		{
			name:          "AlmaLinux 9",
			purl:          "pkg:rpm/almalinux/openssl@3.0.7-27.el9_2?distro=almalinux-9.2",
			wantEcosystem: "AlmaLinux:9",
			wantName:      "openssl",
			wantVersion:   "3.0.7-27.el9_2",
		},
		{
			name:          "Rocky Linux 9",
			purl:          "pkg:rpm/rocky-linux/openssl@3.0.7-27.el9_2?distro=rocky-9.2",
			wantEcosystem: "Rocky Linux:9",
			wantName:      "openssl",
			wantVersion:   "3.0.7-27.el9_2",
		},
		{
			name:          "Red Hat RHEL 9",
			purl:          "pkg:rpm/redhat/openssl-libs@3.5.9-1.el9_9?distro=rhel-9.9",
			wantEcosystem: "Red Hat",
			wantName:      "openssl-libs",
			wantVersion:   "3.5.9-1.el9_9",
		},
		{
			name:          "CentOS 7",
			purl:          "pkg:rpm/centos/curl@7.29.0-59.el7?distro=centos-7",
			wantEcosystem: "Red Hat",
			wantName:      "curl",
			wantVersion:   "7.29.0-59.el7",
		},
		{
			name:     "Ubuntu preserves PURL",
			purl:     "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?distro=ubuntu-22.04",
			wantPURL: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?distro=ubuntu-22.04",
		},
		{
			name:     "NPM preserves PURL",
			purl:     "pkg:npm/lodash@4.17.15",
			wantPURL: "pkg:npm/lodash@4.17.15",
		},
		{
			name:     "Invalid PURL preserves string",
			purl:     "not-a-purl",
			wantPURL: "not-a-purl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := PURLToQuery(tt.purl)
			if tt.wantPURL != "" {
				if q.Package.PURL != tt.wantPURL {
					t.Errorf("q.Package.PURL = %q, want %q", q.Package.PURL, tt.wantPURL)
				}
				return
			}
			if q.Package.Ecosystem != tt.wantEcosystem {
				t.Errorf("q.Package.Ecosystem = %q, want %q", q.Package.Ecosystem, tt.wantEcosystem)
			}
			if q.Package.Name != tt.wantName {
				t.Errorf("q.Package.Name = %q, want %q", q.Package.Name, tt.wantName)
			}
			if q.Version != tt.wantVersion {
				t.Errorf("q.Version = %q, want %q", q.Version, tt.wantVersion)
			}
		})
	}
}
