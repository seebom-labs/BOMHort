package vexsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const sampleOpenVEXJSON = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-demo-1",
  "author": "Upstream Maintainers",
  "role": "author",
  "timestamp": "2024-05-10T00:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2024-24790"
      },
      "products": [
        {
          "@id": "pkg:golang/net/netip@v0.1.0"
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}`

func TestFetchOpenVEXHub_LocalDir(t *testing.T) {
	tmpDir := t.TempDir()
	vexDir := filepath.Join(tmpDir, ".vex")
	if err := os.MkdirAll(vexDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vexDir, "demo.openvex.json"), []byte(sampleOpenVEXJSON), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	res, err := FetchOpenVEXHub(ctx, nil, tmpDir, nil)
	if err != nil {
		t.Fatalf("FetchOpenVEXHub local failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot from local dir")
	}
	stmts := res.Statements
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	s := stmts[0]
	if s.VulnID != "CVE-2024-24790" {
		t.Errorf("expected CVE-2024-24790, got %s", s.VulnID)
	}
	if s.Status != models.VEXStatusNotAffected {
		t.Errorf("expected not_affected, got %s", s.Status)
	}
	if s.Role != RoleUpstream {
		t.Errorf("expected role upstream, got %s", s.Role)
	}
	if s.Author != "Upstream Maintainers" {
		t.Errorf("expected author Upstream Maintainers, got %s", s.Author)
	}
}

func TestFetchOpenVEXHub_HTTP_PURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pkg/golang/net/netip/vex.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(sampleOpenVEXJSON))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	ctx := context.Background()
	res, err := FetchOpenVEXHub(ctx, ts.Client(), ts.URL, []string{"pkg:golang/net/netip@v0.1.0"})
	if err != nil {
		t.Fatalf("FetchOpenVEXHub HTTP failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot")
	}
	stmts := res.Statements
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	if stmts[0].Role != RoleUpstream {
		t.Errorf("expected role upstream, got %s", stmts[0].Role)
	}
}

func TestFetchOpenVEXHub_KnownByCoreIndexing(t *testing.T) {
	indexJSON := `{
		"packages": [
			{"id": "pkg:npm/minimist@1.2.0", "location": "minimist-1.2.0.openvex.json"},
			{"id": "pkg:npm/minimist@1.2.5", "location": "minimist-1.2.5.openvex.json"},
			{"id": "pkg:pypi/unrelated@2.0.0", "location": "unrelated.openvex.json"}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(indexJSON))
		case "/minimist-1.2.0.openvex.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(sampleOpenVEXJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ctx := context.Background()
	// Only minimist@1.2.0 is in knownPURLs; 1.2.5 and unrelated should be filtered out by Core/candidate index.
	known := []string{"pkg:npm/minimist@1.2.0"}
	res, err := FetchOpenVEXHub(ctx, ts.Client(), ts.URL, known)
	if err != nil {
		t.Fatalf("FetchOpenVEXHub failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot")
	}
	stmts := res.Statements
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement fetched, got %d", len(stmts))
	}
}
