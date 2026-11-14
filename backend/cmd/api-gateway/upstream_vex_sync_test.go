package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
)

type stubVEXSyncer struct {
	applied int
	err     error
	called  bool
}

func (s *stubVEXSyncer) SyncUpstreamVEX(ctx context.Context, sources []config.VEXSourceConfig) (int, error) {
	s.called = true
	return s.applied, s.err
}

func TestUpstreamVEXSyncHandler_AuthDisabled_Returns403(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: false,
		VEXSources: []config.VEXSourceConfig{
			{Type: config.VEXSourceTypeOpenVEXHub, URL: "https://example.com/vex"},
		},
	}
	syncer := &stubVEXSyncer{applied: 10}
	h := upstreamVEXSyncHandler(cfg, syncer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex/upstream/sync", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected status 403 when AUTH_ENABLED=false, got %d", rec.Code)
	}
	if syncer.called {
		t.Errorf("syncer should not be called when AUTH_ENABLED=false")
	}
}

func TestUpstreamVEXSyncHandler_NoSources(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: true,
		VEXSources:  nil,
	}
	syncer := &stubVEXSyncer{}
	h := upstreamVEXSyncHandler(cfg, syncer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex/upstream/sync", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if syncer.called {
		t.Errorf("syncer should not be called when no sources are configured")
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "no upstream VEX sources configured" {
		t.Errorf("expected status 'no upstream VEX sources configured', got %v", resp["status"])
	}
	if resp["applied"] != float64(0) {
		t.Errorf("expected applied 0, got %v", resp["applied"])
	}
}

func TestUpstreamVEXSyncHandler_Success(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: true,
		VEXSources: []config.VEXSourceConfig{
			{Type: config.VEXSourceTypeOpenVEXHub, URL: "https://example.com/vex"},
		},
	}
	syncer := &stubVEXSyncer{applied: 42}
	h := upstreamVEXSyncHandler(cfg, syncer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex/upstream/sync", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !syncer.called {
		t.Errorf("syncer should be called")
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
	if resp["applied"] != float64(42) {
		t.Errorf("expected applied 42, got %v", resp["applied"])
	}
}

func TestUpstreamVEXSyncHandler_Error(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: true,
		VEXSources: []config.VEXSourceConfig{
			{Type: config.VEXSourceTypeOpenVEXHub, URL: "https://example.com/vex"},
		},
	}
	syncer := &stubVEXSyncer{err: errors.New("upstream network failure")}
	h := upstreamVEXSyncHandler(cfg, syncer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex/upstream/sync", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
}
