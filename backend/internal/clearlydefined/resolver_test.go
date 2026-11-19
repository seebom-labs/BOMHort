package clearlydefined

import (
	"context"
	"net/http"
	"net/http/httptest"
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
