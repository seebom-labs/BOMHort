package vexsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestEnginePull_FiltersKnownPURLs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(sampleCSAFJSON))
	}))
	defer ts.Close()

	engine := NewEngine()
	ctx := context.Background()

	sources := []config.VEXSourceConfig{
		{Type: SourceTypeCSAFProvider, URL: ts.URL},
	}

	// 1. Filter with only the curl purl
	knownPURLs := []string{"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64"}
	res, err := engine.Pull(ctx, sources, knownPURLs)
	if err != nil {
		t.Fatalf("Engine.Pull failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot")
	}
	stmts := res.Statements

	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement matching known purl, got %d", len(stmts))
	}
	if stmts[0].ProductPURL != knownPURLs[0] {
		t.Errorf("expected matching purl %s, got %s", knownPURLs[0], stmts[0].ProductPURL)
	}
	if stmts[0].Status != models.VEXStatusNotAffected {
		t.Errorf("expected not_affected, got %s", stmts[0].Status)
	}
	if stmts[0].Role != RoleUpstream {
		t.Errorf("expected role upstream, got %s", stmts[0].Role)
	}
}
