package clearlydefined

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
