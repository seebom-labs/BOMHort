package vexsub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestFetchOCIReferrers_ProtocolAndBearerAuth(t *testing.T) {
	const imageDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const vexManifestDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	const sigManifestDigest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	const vexBlobDigest = "sha256:4444444444444444444444444444444444444444444444444444444444444444"

	sigFetched := false
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"test-oci-token"}`))
		case "/v2/myorg/app/referrers/" + imageDigest:
			if r.Header.Get("Authorization") != "Bearer test-oci-token" {
				w.Header().Set("Www-Authenticate", `Bearer realm="`+srv.URL+`/token",service="ghcr.io",scope="repository:myorg/app:pull"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2,
				"mediaType":     "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{
					{
						"mediaType":    "application/vnd.oci.image.manifest.v1+json",
						"digest":       sigManifestDigest,
						"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
					},
					{
						"mediaType":    "application/vnd.oci.image.manifest.v1+json",
						"digest":       vexManifestDigest,
						"artifactType": "application/vnd.openvex+json",
					},
				},
			})
		case "/v2/myorg/app/manifests/" + sigManifestDigest:
			sigFetched = true
			http.Error(w, "should not fetch non-vex artifact manifest", http.StatusInternalServerError)
		case "/v2/myorg/app/manifests/" + vexManifestDigest:
			if r.Header.Get("Authorization") != "Bearer test-oci-token" {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"schemaVersion": 2,
				"artifactType":  "application/vnd.openvex+json",
				"layers": []map[string]any{
					{
						"mediaType": "application/vnd.openvex+json",
						"digest":    vexBlobDigest,
					},
				},
			})
		case "/v2/myorg/app/blobs/" + vexBlobDigest:
			_, _ = w.Write([]byte(`{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id": "https://oci.example.com/vex/app",
				"author": "Image Maintainer",
				"timestamp": "2026-06-01T12:00:00Z",
				"statements": [
					{
						"vulnerability": {"name": "CVE-2026-9999"},
						"products": [{"@id": "pkg:oci/app@` + imageDigest + `"}],
						"status": "not_affected",
						"justification": "vulnerable_code_not_in_execute_path"
					}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	regHost := strings.TrimPrefix(srv.URL, "http://")
	known := []string{"pkg:oci/app@" + imageDigest + "?repository_url=" + regHost + "/myorg/app"}

	res, err := FetchOCIReferrers(context.Background(), srv.Client(), srv.URL+"/myorg/app", known)
	if err != nil {
		t.Fatalf("FetchOCIReferrers failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot")
	}
	stmts := res.Statements
	if sigFetched {
		t.Fatalf("non-VEX signature referrer manifest was unexpectedly fetched")
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 VEX statement from OCI referrer blob, got %d", len(stmts))
	}
	if stmts[0].VulnID != "CVE-2026-9999" || stmts[0].Role != models.VEXRoleUpstream {
		t.Errorf("unexpected statement: %+v", stmts[0])
	}
	if stmts[0].Tooling != srv.URL+"/myorg/app" {
		t.Errorf("expected tooling %q, got %q", srv.URL+"/myorg/app", stmts[0].Tooling)
	}
}

func TestFetchOCIReferrers_DirectJSONAndError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/direct.openvex.json":
			_, _ = w.Write([]byte(`{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id": "https://vex.example.com/direct",
				"statements": [
					{
						"vulnerability": {"name": "CVE-2026-1111"},
						"products": [{"@id": "pkg:oci/nginx@sha256:aaaa"}],
						"status": "not_affected",
						"justification": "component_not_present"
					}
				]
			}`))
		case "/fail.json":
			http.Error(w, "upstream down", http.StatusBadGateway)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := FetchOCIReferrers(context.Background(), srv.Client(), srv.URL+"/direct.openvex.json", []string{"pkg:oci/nginx@sha256:aaaa"})
	if err != nil {
		t.Fatalf("expected direct JSON fetch to succeed, got %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot")
	}
	stmts := res.Statements
	if len(stmts) != 1 || stmts[0].Role != models.VEXRoleUpstream {
		t.Fatalf("unexpected direct statements: %+v", stmts)
	}

	if _, err := FetchOCIReferrers(context.Background(), srv.Client(), srv.URL+"/fail.json", nil); err == nil {
		t.Fatalf("expected error for HTTP 502 direct JSON endpoint, got nil")
	}
}
