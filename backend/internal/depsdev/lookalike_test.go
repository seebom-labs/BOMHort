package depsdev

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestSimilarlyNamedPackages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v3alpha/systems/npm/packages/crossenv:similarlyNamedPackages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"packageKey": {"system": "NPM", "name": "crossenv"},
				"packages": [
					{"packageKey": {"system": "NPM", "name": "crossenv"}},
					{"packageKey": {"system": "NPM", "name": "cross-env"}}
				]
			}`))
		case "/v3alpha/systems/pypi/packages/reqeusts:similarlyNamedPackages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"packageKey": {"system": "PYPI", "name": "reqeusts"},
				"packages": [
					{"packageKey": {"system": "PYPI", "name": "requests"}}
				]
			}`))
		case "/v3alpha/systems/npm/packages/unknown-pkg:similarlyNamedPackages":
			http.NotFound(w, r)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	r := NewResolverWithBaseURL(server.URL)

	// 1. Resolve crossenv -> ["cross-env"] (crossenv itself filtered out)
	lookalikes := r.SimilarlyNamedPackages(context.Background(), "npm", "crossenv")
	want := []string{"cross-env"}
	if !reflect.DeepEqual(lookalikes, want) {
		t.Fatalf("got %v, want %v", lookalikes, want)
	}

	// 2. Resolve reqeusts -> ["requests"]
	pypiLookalikes := r.SimilarlyNamedPackages(context.Background(), "pypi", "reqeusts")
	pypiWant := []string{"requests"}
	if !reflect.DeepEqual(pypiLookalikes, pypiWant) {
		t.Fatalf("got %v, want %v", pypiLookalikes, pypiWant)
	}

	// 3. New entries returned
	entries := r.LookalikeCacheEntries()
	if len(entries) != 2 {
		t.Fatalf("expected 2 new cache entries, got %d", len(entries))
	}
	if !reflect.DeepEqual(entries["npm:crossenv"], want) {
		t.Fatalf("cache entry mismatch: got %v, want %v", entries["npm:crossenv"], want)
	}

	// 4. Calling again returns from in-memory cache without hitting server
	cachedLookalikes := r.SimilarlyNamedPackages(context.Background(), "npm", "crossenv")
	if !reflect.DeepEqual(cachedLookalikes, want) {
		t.Fatalf("cached: got %v, want %v", cachedLookalikes, want)
	}

	// 5. 404 is cached as negative result
	notFound := r.SimilarlyNamedPackages(context.Background(), "npm", "unknown-pkg")
	if len(notFound) != 0 {
		t.Fatalf("expected empty for unknown pkg, got %v", notFound)
	}
}

func TestPreloadLookalikeCache(t *testing.T) {
	r := NewResolverWithBaseURL("http://invalid-url-should-not-be-called")
	r.PreloadLookalikeCache(map[string][]string{
		"npm:jost": {"@types/jest", "jose"},
	})

	got := r.SimilarlyNamedPackages(context.Background(), "npm", "jost")
	want := []string{"@types/jest", "jose"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preloaded cache failed: got %v, want %v", got, want)
	}
}

func TestExtractPackage(t *testing.T) {
	pv, ok := ExtractPackage("pkg:pypi/requests")
	if !ok || pv.System != "PYPI" || pv.Name != "requests" {
		t.Fatalf("ExtractPackage failed for versionless purl: got %+v, ok %v", pv, ok)
	}

	pv, ok = ExtractPackage("pkg:npm/crossenv@1.0.0")
	if !ok || pv.System != "NPM" || pv.Name != "crossenv" {
		t.Fatalf("ExtractPackage failed for versioned purl: got %+v, ok %v", pv, ok)
	}
}
