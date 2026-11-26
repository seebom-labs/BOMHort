package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/clearlydefined"
)

func TestNoticeFilename(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", "NOTICE.txt"},
		{"   ", "NOTICE.txt"},
		{"my-project", "NOTICE-my-project.txt"},
		{"my-project (v1.0.0)", "NOTICE-my-project--v1.0.0.txt"},
		{"org/repo", "NOTICE-org-repo.txt"},
		{"../../evil", "NOTICE-evil.txt"},
	} {
		got := noticeFilename(tc.input)
		if got != tc.want {
			t.Errorf("noticeFilename(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestNoticeHandler_SBOMNoticeDownloadWithMissingAttributionFlags(t *testing.T) {
	mux := http.NewServeMux()

	cdResolver := clearlydefined.NewResolver()

	queryFunc := func(ctx context.Context, sbomID string) (string, []clearlydefined.NoticePackage, error) {
		return "my-production-app (v1.2.0)", []clearlydefined.NoticePackage{
			{
				Name:             "express",
				Version:          "4.18.2",
				PURL:             "pkg:npm/express@4.18.2",
				License:          "MIT",
				CopyrightParties: []string{"Copyright (c) 2014 TJ Holowaychuk"},
			},
			{
				Name:    "internal-lib",
				Version: "0.5.0",
				PURL:    "pkg:npm/%40acme/internal-lib@0.5.0",
				License: "Apache-2.0",
				// No CopyrightParties: must be flagged explicitly as missing upstream copyright!
			},
			{
				Name:    "unresolved-pkg",
				Version: "1.0.0",
				PURL:    "pkg:generic/unresolved-pkg@1.0.0",
				License: "NOASSERTION",
				// Unresolved license: must be retained and flagged for manual review!
			},
		}, nil
	}

	mux.HandleFunc("GET /api/v1/sboms/{id}/notices", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		targetName, pkgs, err := queryFunc(r.Context(), sbomID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to fetch packages for notice")
			return
		}

		content := cdResolver.GenerateNoticeWithFallback(r.Context(), targetName, pkgs)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, noticeFilename(targetName)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/550e8400-e29b-41d4-a716-446655440000/notices", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("expected Content-Type text/plain, got %q", contentType)
	}

	disp := rec.Header().Get("Content-Disposition")
	wantDisp := `attachment; filename="NOTICE-my-production-app--v1.2.0.txt"`
	if disp != wantDisp {
		t.Errorf("Content-Disposition = %q, want %q", disp, wantDisp)
	}

	body := rec.Body.String()

	// Verify Target header
	if !strings.Contains(body, "Target: my-production-app (v1.2.0)") {
		t.Errorf("missing target name in notice body: %s", body)
	}

	// Verify express package entry and copyright
	if !strings.Contains(body, "Package: express") || !strings.Contains(body, "Copyright (c) 2014 TJ Holowaychuk") {
		t.Errorf("missing express package or copyright in notice body")
	}

	// Verify missing attribution flag and summary count
	if !strings.Contains(body, "[No upstream copyright statement recorded; manual review required]") {
		t.Errorf("missing explicit copyright statement manual review flag in notice body")
	}
	if !strings.Contains(body, "Components missing upstream copyright notice: 2 (flagged for manual review)") {
		t.Errorf("missing attribution coverage summary count for missing copyright")
	}

	// Verify unresolved license flag and summary count
	if !strings.Contains(body, "License: NOASSERTION [Unresolved license; manual review required]") {
		t.Errorf("missing explicit unresolved license manual review flag")
	}
	if !strings.Contains(body, "Components with unresolved licenses: 1 (flagged for manual review)") {
		t.Errorf("missing coverage summary count for unresolved licenses")
	}

	// Verify full coverage total components count
	if !strings.Contains(body, "Total third-party components: 3") {
		t.Errorf("expected 3 total third-party components in summary: %s", body)
	}
}

func TestNoticeHandler_ProjectNoticeEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	cdResolver := clearlydefined.NewResolver()

	mux.HandleFunc("GET /api/v1/projects/{name}/notices", func(w http.ResponseWriter, r *http.Request) {
		name := sanitizeProjectName(r.PathValue("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, "Invalid project name")
			return
		}
		version := r.URL.Query().Get("version")

		if name == "not-found" {
			writeError(w, http.StatusNotFound, "Project or version not found")
			return
		}

		targetName := name
		if version != "" {
			targetName = fmt.Sprintf("%s (%s)", name, version)
		}

		pkgs := []clearlydefined.NoticePackage{
			{
				Name:    "core-lib",
				Version: "1.0.0",
				PURL:    "pkg:golang/github.com/org/core-lib@1.0.0",
				License: "Apache-2.0",
			},
		}

		content := cdResolver.GenerateNoticeWithFallback(r.Context(), targetName, pkgs)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, noticeFilename(targetName)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})

	// 1. Success with version
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/my-service/notices?version=v2.0.0", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	wantDisp := `attachment; filename="NOTICE-my-service--v2.0.0.txt"`
	if disp := rec.Header().Get("Content-Disposition"); disp != wantDisp {
		t.Errorf("Content-Disposition = %q, want %q", disp, wantDisp)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Target: my-service (v2.0.0)") {
		t.Errorf("expected target header in body: %s", body)
	}
	if !strings.Contains(body, "[No upstream copyright statement recorded; manual review required]") {
		t.Errorf("expected missing copyright notice flag in body: %s", body)
	}

	// 2. 404 when project not found
	req404 := httptest.NewRequest(http.MethodGet, "/api/v1/projects/not-found/notices", nil)
	rec404 := httptest.NewRecorder()
	mux.ServeHTTP(rec404, req404)
	if rec404.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec404.Code)
	}
}

func TestNoticeQueryMappingToNoticeFallback(t *testing.T) {
	// Exercise the exact mapping performed by QuerySBOMPackagesForNotice:
	// ClickHouse returns parallel arrays of names, versions, purls, licenses.
	names := []string{"left-pad", "private-module", "unknown-tool"}
	versions := []string{"1.3.0", "0.1.0", "2.0.0"}
	purls := []string{"pkg:npm/left-pad@1.3.0", "pkg:npm/%40corp/private-module@0.1.0", "pkg:generic/unknown-tool@2.0.0"}
	licenses := []string{"WTFPL", "MIT", "NOASSERTION"}

	pkgs := make([]clearlydefined.NoticePackage, len(names))
	for i := range names {
		p := clearlydefined.NoticePackage{
			Name: names[i],
		}
		if i < len(versions) {
			p.Version = versions[i]
		}
		if i < len(purls) {
			p.PURL = purls[i]
		}
		if i < len(licenses) {
			p.License = licenses[i]
		}
		pkgs[i] = p
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/definitions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"npm/npmjs/-/left-pad/1.3.0": {
				"licensed": {
					"facets": {
						"core": {
							"attribution": {"parties": ["Copyright 2011 left-pad authors"]}
						}
					}
				}
			}
		}`))
	}))
	defer srv.Close()

	cdResolver := clearlydefined.NewResolverWithRegistry(srv.URL)
	notice := cdResolver.GenerateNoticeWithFallback(context.Background(), "test-app (v1.0.0)", pkgs)

	// Verify all components exist in the notice
	for _, name := range names {
		if !strings.Contains(notice, "Package: "+name) {
			t.Errorf("missing package %q in generated notice", name)
		}
	}

	// Verify attribution summary counts:
	// left-pad harvests real copyright from ClearlyDefined, while private-module and unknown-tool
	// are flagged for manual review with missing upstream copyright.
	if !strings.Contains(notice, "Components with recorded copyright notices: 1") {
		t.Errorf("expected 1 recorded copyright notice in summary: %s", notice)
	}
	if !strings.Contains(notice, "Components missing upstream copyright notice: 2 (flagged for manual review)") {
		t.Errorf("expected 2 packages missing upstream copyright notice in summary: %s", notice)
	}

	// Verify unresolved license flag for unknown-tool
	if !strings.Contains(notice, "License: NOASSERTION [Unresolved license; manual review required]") {
		t.Errorf("expected NOASSERTION manual review flag: %s", notice)
	}
	if !strings.Contains(notice, "Components with unresolved licenses: 1 (flagged for manual review)") {
		t.Errorf("expected 1 unresolved license in summary: %s", notice)
	}
}
