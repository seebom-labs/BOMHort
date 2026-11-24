package clearlydefined

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	json "github.com/goccy/go-json"

	"github.com/seebom-labs/bomhort/backend/internal/license"
)

func TestCoordinateFromPURL(t *testing.T) {
	tests := []struct {
		purl     string
		wantType string
		wantProv string
		wantNS   string
		wantName string
		wantRev  string
		wantOK   bool
	}{
		{
			purl:     "pkg:npm/express@4.18.2",
			wantType: "npm", wantProv: "npmjs", wantNS: "-", wantName: "express", wantRev: "4.18.2", wantOK: true,
		},
		{
			purl:     "pkg:npm/@angular/core@17.0.0",
			wantType: "npm", wantProv: "npmjs", wantNS: "@angular", wantName: "core", wantRev: "17.0.0", wantOK: true,
		},
		{
			purl:     "pkg:npm/%40angular/core@17.0.0",
			wantType: "npm", wantProv: "npmjs", wantNS: "@angular", wantName: "core", wantRev: "17.0.0", wantOK: true,
		},
		{
			purl:     "pkg:pypi/flask@2.0.1",
			wantType: "pypi", wantProv: "pypi", wantNS: "-", wantName: "flask", wantRev: "2.0.1", wantOK: true,
		},
		{
			purl:     "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			wantType: "maven", wantProv: "mavencentral", wantNS: "org.apache.commons", wantName: "commons-lang3", wantRev: "3.12.0", wantOK: true,
		},
		{
			purl:     "pkg:nuget/Newtonsoft.Json@13.0.1",
			wantType: "nuget", wantProv: "nuget", wantNS: "-", wantName: "Newtonsoft.Json", wantRev: "13.0.1", wantOK: true,
		},
		{
			purl:     "pkg:cargo/serde@1.0.100",
			wantType: "crate", wantProv: "cratesio", wantNS: "-", wantName: "serde", wantRev: "1.0.100", wantOK: true,
		},
		{
			purl:     "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			wantType: "git", wantProv: "github", wantNS: "gin-gonic", wantName: "gin", wantRev: "v1.9.1", wantOK: true,
		},
		{
			purl:   "pkg:generic/binary@1.0",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/no-version",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/lodash@..",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/lodash@.",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/left-pad@file:../left-pad",
			wantOK: false,
		},
		{
			purl:   "pkg:pypi/requests@..",
			wantOK: false,
		},
		{
			purl:   "pkg:nuget/Moq@..",
			wantOK: false,
		},
		{
			purl:   "pkg:maven/org.apache/commons@..",
			wantOK: false,
		},
		{
			purl:   "pkg:cargo/serde@..",
			wantOK: false,
		},
		{
			purl:   "pkg:golang/github.com/foo/bar@..",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/%40..%2Fcore@1.0.0",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/..%2Fcore@1.0.0",
			wantOK: false,
		},
		{
			purl:   "pkg:maven/..%2Fartifact@1.0.0",
			wantOK: false,
		},
		{
			purl:   "pkg:gem/foo%20bar@1.0.0",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/foo%5Cbar@1.0.0",
			wantOK: false,
		},
		{
			purl:   "pkg:github/owner/..@v1",
			wantOK: false,
		},
		{
			purl:   "pkg:composer/vendor/..@1.0",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/foo@1.0.0%0A",
			wantOK: false,
		},
		{
			purl:   "pkg:npm/is-odd@3.0.1%0A",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.purl, func(t *testing.T) {
			coord, ok := CoordinateFromPURL(tt.purl)
			if ok != tt.wantOK {
				t.Fatalf("CoordinateFromPURL(%q) ok = %v, want %v", tt.purl, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if coord.Type != tt.wantType || coord.Provider != tt.wantProv || coord.Namespace != tt.wantNS || coord.Name != tt.wantName || coord.Revision != tt.wantRev {
				t.Errorf("got %+v, want Type=%q Prov=%q NS=%q Name=%q Rev=%q",
					coord, tt.wantType, tt.wantProv, tt.wantNS, tt.wantName, tt.wantRev)
			}
		})
	}
}

func TestResolver_ResolveAndDiscrepancy(t *testing.T) {
	mux := http.NewServeMux()

	// 1. Definition with declared license.
	mux.HandleFunc("GET /definitions/npm/npmjs/-/express/4.18.2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"licensed": {
				"declared": "MIT",
				"facets": {
					"core": {
						"attribution": {"parties": ["Copyright (c) 2014 TJ Holowaychuk"]},
						"discovered": {"expressions": ["MIT"]}
					}
				}
			}
		}`))
	})

	// 2. Definition with discrepancy: declared MIT, but discovered scan has GPL-2.0.
	mux.HandleFunc("GET /definitions/npm/npmjs/-/dual-licensed-trap/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"licensed": {
				"declared": "MIT",
				"facets": {
					"core": {
						"discovered": {"expressions": ["GPL-2.0"]}
					}
				}
			}
		}`))
	})

	// 3. Not harvested (404).
	mux.HandleFunc("GET /definitions/pypi/pypi/-/private-pkg/0.0.1", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	// Resolve express.
	lic := r.Resolve(ctx, "pkg:npm/express@4.18.2")
	if lic != "MIT" {
		t.Errorf("Resolve(express) = %q, want MIT", lic)
	}
	parties := r.GetAttributionParties("pkg:npm/express@4.18.2")
	if len(parties) != 1 || parties[0] != "Copyright (c) 2014 TJ Holowaychuk" {
		t.Errorf("GetAttributionParties = %v, want 1 TJ Holowaychuk party", parties)
	}

	// Discrepancy check on express (agreeing).
	if disc, has := r.CheckDiscrepancy(ctx, "pkg:npm/express@4.18.2", "MIT"); has {
		t.Errorf("expected no discrepancy for express, got %q", disc)
	}

	// Discrepancy check on dual-licensed-trap (declared MIT, discovered GPL-2.0).
	disc, has := r.CheckDiscrepancy(ctx, "pkg:npm/dual-licensed-trap@1.0.0", "MIT")
	if !has {
		t.Errorf("expected discrepancy for dual-licensed-trap, got none")
	}
	if disc != "GPL-2.0-only" {
		t.Errorf("expected discovered license GPL-2.0-only, got %q", disc)
	}

	// Unharvested package -> Explain returns not-harvested.
	unresolved := r.Resolve(ctx, "pkg:pypi/private-pkg@0.0.1")
	if unresolved != "" {
		t.Errorf("expected empty license for 404, got %q", unresolved)
	}
	handled, reason, latest := r.Explain("pkg:pypi/private-pkg@0.0.1")
	if !handled || reason != license.ReasonNotHarvested || latest {
		t.Errorf("Explain = handled:%v, reason:%q, latest:%v; want true, %q, false",
			handled, reason, latest, license.ReasonNotHarvested)
	}
}

func TestResolver_DiscrepancyRetainsAllDiscoveredExpressions(t *testing.T) {
	// A package declaring MIT with scan expressions ["MIT", "GPL-2.0-only"]
	// must retain all discovered expressions and detect the conflict with GPL-2.0-only (#530).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /definitions/npm/npmjs/-/bundled-gpl-pkg/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"licensed": {
				"declared": "MIT",
				"facets": {
					"core": {
						"discovered": {"expressions": ["MIT", "GPL-2.0-only"]}
					}
				}
			}
		}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	disc, has := r.CheckDiscrepancy(ctx, "pkg:npm/bundled-gpl-pkg@1.0.0", "MIT")
	if !has {
		t.Fatalf("expected discrepancy for bundled GPL file, got none")
	}
	if !strings.Contains(disc, "GPL-2.0-only") {
		t.Errorf("expected discovered conflict to include GPL-2.0-only, got %q", disc)
	}
}

func TestResolver_DoesNotTreatScannedFileAsDeclaredLicense(t *testing.T) {
	// When ClearlyDefined has no declared license and its scan returns MIT followed by GPL-2.0-only,
	// Resolve must leave the package unresolved rather than promoting the first scanned file to MIT (#530).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /definitions/npm/npmjs/-/scanned-only-pkg/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"licensed": {
				"declared": "",
				"facets": {
					"core": {
						"discovered": {"expressions": ["MIT", "GPL-2.0-only"]}
					}
				}
			}
		}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	lic := r.Resolve(ctx, "pkg:npm/scanned-only-pkg@1.0.0")
	if lic != "" {
		t.Errorf("Resolve() = %q, want empty string (must not promote file scan to declared license)", lic)
	}
	_, reason, _ := r.Explain("pkg:npm/scanned-only-pkg@1.0.0")
	if reason != license.ReasonNoLicenseUpstream {
		t.Errorf("Explain() reason = %q, want %q", reason, license.ReasonNoLicenseUpstream)
	}
}

func TestResolver_BatchColdCacheAndRestartPersistence(t *testing.T) {
	// Verifies batch definition fetching via POST /definitions, negative caching,
	// and full persistence/preloading across worker restarts (#530).
	batchCalled := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /definitions", func(w http.ResponseWriter, r *http.Request) {
		batchCalled++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"npm/npmjs/-/pkg-a/1.0.0": {
				"licensed": {
					"declared": "MIT",
					"facets": {
						"core": {
							"attribution": {"parties": ["Copyright 2024 Author A"]},
							"discovered": {"expressions": ["MIT"]}
						}
					}
				}
			},
			"npm/npmjs/-/pkg-b/2.0.0": {
				"licensed": {
					"declared": "Apache-2.0",
					"facets": {
						"core": {
							"discovered": {"expressions": ["GPL-3.0-only"]}
						}
					}
				}
			}
		}`))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	r1 := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	purls := []string{
		"pkg:npm/pkg-a@1.0.0",
		"pkg:npm/pkg-b@2.0.0",
		"pkg:npm/unharvested@3.0.0",
	}
	declared := []string{
		"MIT",
		"Apache-2.0",
		"BSD-3-Clause",
	}

	// 1. Run batch discrepancy check
	discs := r1.CheckDiscrepanciesBatch(ctx, purls, declared)
	if len(discs) != 3 {
		t.Fatalf("expected 3 discrepancy results, got %d", len(discs))
	}
	if discs[0] != "" {
		t.Errorf("expected no discrepancy for pkg-a, got %q", discs[0])
	}
	if discs[1] != "GPL-3.0-only" {
		t.Errorf("expected GPL-3.0-only discrepancy for pkg-b, got %q", discs[1])
	}
	if discs[2] != "" {
		t.Errorf("expected no discrepancy for unharvested, got %q", discs[2])
	}
	if batchCalled != 1 {
		t.Errorf("expected exactly 1 POST /definitions batch call, got %d", batchCalled)
	}

	// 2. Export cache entries and simulate worker restart
	entries := r1.CacheEntries()
	srv.Close() // Shut down server completely!

	r2 := NewResolverWithRegistry("http://127.0.0.1:9999") // dead server URL
	r2.PreloadCache(entries)

	// Verify preloaded state without network:
	// pkg-a attribution and resolved license:
	licA := r2.Resolve(context.Background(), "pkg:npm/pkg-a@1.0.0")
	if licA != "MIT" {
		t.Errorf("preloaded Resolve(pkg-a) = %q, want MIT", licA)
	}
	partiesA := r2.GetAttributionParties("pkg:npm/pkg-a@1.0.0")
	if len(partiesA) != 1 || partiesA[0] != "Copyright 2024 Author A" {
		t.Errorf("preloaded GetAttributionParties(pkg-a) = %v, want ['Copyright 2024 Author A']", partiesA)
	}

	// pkg-b discrepancy check:
	discB, hasB := r2.CheckDiscrepancy(context.Background(), "pkg:npm/pkg-b@2.0.0", "Apache-2.0")
	if !hasB || discB != "GPL-3.0-only" {
		t.Errorf("preloaded CheckDiscrepancy(pkg-b) = %q, %v; want GPL-3.0-only, true", discB, hasB)
	}

	// unharvested negative cache reuse:
	discU, hasU := r2.CheckDiscrepancy(context.Background(), "pkg:npm/unharvested@3.0.0", "BSD-3-Clause")
	if hasU || discU != "" {
		t.Errorf("preloaded CheckDiscrepancy(unharvested) = %q, %v; want false", discU, hasU)
	}
}

func TestResolver_NegativeCacheNeverReturnedAsLicense(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /definitions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Empty response: none of the coordinates are harvested
		w.Write([]byte(`{}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	purls := []string{"pkg:npm/unharvested-lib@1.0.0"}
	res := r.ResolveBatch(ctx, purls)

	// Result map must not contain negative cache markers as licenses (#530).
	if lic := res["pkg:npm/unharvested-lib@1.0.0"]; lic != "" {
		t.Fatalf("ResolveBatch returned negative cache marker as license: %q", lic)
	}

	// Cache must still retain reason for Explain
	handled, reason, _ := r.Explain("pkg:npm/unharvested-lib@1.0.0")
	if !handled || reason != license.ReasonNotHarvested {
		t.Errorf("Explain() = (%v, %q), want (true, %q)", handled, reason, license.ReasonNotHarvested)
	}
}

func TestResolver_PrivatePackagesNeverQueried(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		t.Errorf("unexpected external request to ClearlyDefined for private package: %s %s", r.Method, r.URL.Path)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	r.SetPrivatePrefixes([]string{
		"pkg:npm/%40acme-private/",
		"com.acme.private",
		"@internal/",
	})
	ctx := context.Background()

	privatePURLs := []string{
		"pkg:npm/%40acme-private/billing@1.0.0",
		"pkg:npm/@acme-private/auth@2.0.0",
		"pkg:maven/com.acme.private/billing@1.0.0",
		"pkg:npm/%40internal/utils@1.0.0",
		"pkg:npm/@golden/web@0.0.0-use.local",
		"pkg:maven/${project.groupId}/core@1",
	}

	for _, p := range privatePURLs {
		if !r.IsPrivate(p) {
			t.Errorf("IsPrivate(%q) = false, want true", p)
		}
		if lic := r.Resolve(ctx, p); lic != "" {
			t.Errorf("Resolve(%q) = %q, want empty", p, lic)
		}
		if disc, found := r.CheckDiscrepancy(ctx, p, "MIT"); found || disc != "" {
			t.Errorf("CheckDiscrepancy(%q) = (%q, %v), want empty, false", p, disc, found)
		}
	}

	// Batch resolve & discrepancy
	res := r.ResolveBatch(ctx, privatePURLs)
	if len(res) != 0 {
		t.Errorf("ResolveBatch on private packages returned %d items, want 0", len(res))
	}

	discs := r.CheckDiscrepanciesBatch(ctx, privatePURLs, []string{"MIT", "MIT", "MIT", "MIT", "MIT", "MIT"})
	for i, d := range discs {
		if d != "" {
			t.Errorf("discs[%d] = %q, want empty", i, d)
		}
	}

	pkgs := []NoticePackage{
		{Name: "billing", Version: "1.0.0", PURL: "pkg:npm/%40acme-private/billing@1.0.0"},
	}
	r.PopulateAttributions(ctx, pkgs)
	if len(pkgs[0].CopyrightParties) != 0 {
		t.Errorf("PopulateAttributions populated private package")
	}

	if requests != 0 {
		t.Fatalf("expected 0 requests to external service for private packages, got %d", requests)
	}
}

func TestResolveBatch_OversizedResponse_SplitsGracefully(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /definitions", func(w http.ResponseWriter, r *http.Request) {
		var reqCoords []string
		if err := json.NewDecoder(r.Body).Decode(&reqCoords); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// When batch has > 25 coordinates, return response exceeding 10 MiB to trigger LimitReader truncation (#530).
		if len(reqCoords) > 25 {
			w.Header().Set("Content-Type", "application/json")
			// Write > 10 MiB of JSON payload
			w.Write([]byte(`{"npm/npmjs/-/pkg-0/1.0.0":{"licensed":{"declared":"MIT"}}`))
			// Padding > 10 MiB
			padding := strings.Repeat(" ", 11<<20)
			w.Write([]byte(padding))
			w.Write([]byte(`}`))
			return
		}

		// Small chunks (<= 25): return valid JSON definition map
		respMap := make(map[string]any, len(reqCoords))
		for _, coord := range reqCoords {
			respMap[coord] = map[string]any{
				"licensed": map[string]any{
					"declared": "Apache-2.0",
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respMap)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	// Generate 50 coordinates
	purls := make([]string, 50)
	for i := 0; i < 50; i++ {
		purls[i] = fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i)
	}

	got := r.ResolveBatch(ctx, purls)

	// All 50 coordinates should be resolved to Apache-2.0 after recursive split
	if len(got) != 50 {
		t.Fatalf("ResolveBatch resolved %d coordinates, want 50", len(got))
	}
	for _, p := range purls {
		if got[p] != "Apache-2.0" {
			t.Errorf("ResolveBatch[%s] = %q, want Apache-2.0", p, got[p])
		}
	}
}

func TestFetchDefinitionsChunk_DoesNotSplitTransientFailures(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	coords := make([]Coordinate, maxBatchSize)
	for i := range coords {
		coord, ok := CoordinateFromPURL(fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i))
		if !ok {
			t.Fatalf("failed to parse test PURL at index %d", i)
		}
		coords[i] = coord
	}

	err := r.fetchDefinitionsBatch(context.Background(), coords)
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("fetchDefinitionsBatch error = %v, want HTTP 503", err)
	}
	if requests != 1 {
		t.Errorf("transient failure caused %d requests, want one", requests)
	}
}

func TestFetchDefinitionsChunk_SplitsPayloadTooLarge(t *testing.T) {
	requests := 0
	mux := http.NewServeMux()
	mux.HandleFunc("POST /definitions", func(w http.ResponseWriter, req *http.Request) {
		requests++
		var coordStrings []string
		if err := json.NewDecoder(req.Body).Decode(&coordStrings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(coordStrings) > 25 {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		definitions := make(map[string]any, len(coordStrings))
		for _, coord := range coordStrings {
			definitions[coord] = map[string]any{"licensed": map[string]string{"declared": "MIT"}}
		}
		_ = json.NewEncoder(w).Encode(definitions)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	coords := make([]Coordinate, maxBatchSize)
	for i := range coords {
		coord, ok := CoordinateFromPURL(fmt.Sprintf("pkg:npm/pkg-%d@1.0.0", i))
		if !ok {
			t.Fatalf("failed to parse test PURL at index %d", i)
		}
		coords[i] = coord
	}
	if err := r.fetchDefinitionsBatch(context.Background(), coords); err != nil {
		t.Fatalf("fetchDefinitionsBatch() error = %v", err)
	}
	if requests != 3 {
		t.Errorf("payload split made %d requests, want 3", requests)
	}
	if lic, _, ok := r.Load(CacheKey(coords[0])); !ok || lic != "MIT" {
		t.Errorf("split response license = %q, cached=%v; want MIT", lic, ok)
	}
}

func TestCoordinate_Valid(t *testing.T) {
	tests := []struct {
		name  string
		coord Coordinate
		want  bool
	}{
		{
			name:  "valid standard coordinate",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "lodash", Revision: "4.17.21"},
			want:  true,
		},
		{
			name:  "valid scoped npm",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "@angular", Name: "core", Revision: "17.0.0"},
			want:  true,
		},
		{
			name:  "empty type",
			coord: Coordinate{Type: "", Provider: "npmjs", Namespace: "-", Name: "lodash", Revision: "4.17.21"},
			want:  false,
		},
		{
			name:  "empty name",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "", Revision: "4.17.21"},
			want:  false,
		},
		{
			name:  "dot-dot revision",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "lodash", Revision: ".."},
			want:  false,
		},
		{
			name:  "dot revision",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "lodash", Revision: "."},
			want:  false,
		},
		{
			name:  "file protocol path in revision",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "left-pad", Revision: "file:../left-pad"},
			want:  false,
		},
		{
			name:  "dot-dot in namespace",
			coord: Coordinate{Type: "maven", Provider: "mavencentral", Namespace: "..", Name: "artifact", Revision: "1.0.0"},
			want:  false,
		},
		{
			name:  "dot-dot in name",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "foo..bar", Revision: "1.0.0"},
			want:  false,
		},
		{
			name:  "slash in name",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "foo/bar", Revision: "1.0.0"},
			want:  false,
		},
		{
			name:  "backslash in name",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "foo\\bar", Revision: "1.0.0"},
			want:  false,
		},
		{
			name:  "whitespace in namespace",
			coord: Coordinate{Type: "maven", Provider: "mavencentral", Namespace: "org apache", Name: "commons", Revision: "1.0.0"},
			want:  false,
		},
		{
			name:  "newline in revision",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "lodash", Revision: "1.0.0\n"},
			want:  false,
		},
		{
			name:  "internal newline in revision",
			coord: Coordinate{Type: "npm", Provider: "npmjs", Namespace: "-", Name: "lodash", Revision: "1.0\n0"},
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.coord.Valid(); got != tt.want {
				t.Errorf("Coordinate.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolver_HostilePURL_NoOutboundRequest(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		t.Errorf("unexpected outbound HTTP request: %s %s", r.Method, r.URL.RequestURI())
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := NewResolverWithRegistry(srv.URL)
	ctx := context.Background()

	hostilePURLs := []string{
		"pkg:npm/lodash@..",
		"pkg:npm/lodash@.",
		"pkg:npm/left-pad@file:../left-pad",
		"pkg:pypi/requests@..",
		"pkg:nuget/Moq@..",
		"pkg:maven/org.apache/commons@..",
		"pkg:maven/..%2Fartifact@1.0.0",
		"pkg:npm/%40..%2Fcore@1.0.0",
		"pkg:npm/..%2Fcore@1.0.0",
		"pkg:gem/foo%20bar@1.0.0",
		"pkg:npm/foo%5Cbar@1.0.0",
		"pkg:github/owner/..@v1",
		"pkg:composer/vendor/..@1.0",
		"pkg:npm/foo@1.0.0%0A",
		"pkg:npm/is-odd@3.0.1%0A",
	}

	for _, p := range hostilePURLs {
		if lic := r.Resolve(ctx, p); lic != "" {
			t.Errorf("Resolve(%q) = %q, want empty", p, lic)
		}
	}

	batchRes := r.ResolveBatch(ctx, hostilePURLs)
	if len(batchRes) != 0 {
		t.Errorf("ResolveBatch() = %v, want empty map", batchRes)
	}

	pkgs := make([]NoticePackage, len(hostilePURLs))
	for i, p := range hostilePURLs {
		pkgs[i] = NoticePackage{PURL: p}
	}
	r.PopulateAttributions(ctx, pkgs)

	if requestCount > 0 {
		t.Fatalf("expected 0 HTTP requests for hostile PURLs, got %d", requestCount)
	}
}
