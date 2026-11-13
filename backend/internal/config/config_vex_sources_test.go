package config

import (
	"os"
	"testing"
	"time"
)

func TestParseVEXSourcesJSON(t *testing.T) {
	raw := `[{"type": "openvex-hub", "url": "https://github.com/seebom-labs/vexhub"}, {"type": "csaf-provider", "url": "https://access.redhat.com/security/data/csaf/v2/provider-metadata.json"}]`
	sources, err := parseVEXSources(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
	if sources[0].Type != "openvex-hub" || sources[0].URL != "https://github.com/seebom-labs/vexhub" {
		t.Errorf("unexpected source 0: %+v", sources[0])
	}
	if sources[1].Type != "csaf-provider" || sources[1].URL != "https://access.redhat.com/security/data/csaf/v2/provider-metadata.json" {
		t.Errorf("unexpected source 1: %+v", sources[1])
	}
}

func TestParseVEXSourcesCommaSeparated(t *testing.T) {
	raw := "openvex-hub=https://github.com/example/vexhub, csaf-provider=https://example.com/csaf/provider-metadata.json, oci-referrers=ghcr.io/example/app"
	sources, err := parseVEXSources(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sources) != 3 {
		t.Fatalf("expected 3 sources, got %d", len(sources))
	}
	if sources[0].Type != "openvex-hub" || sources[0].URL != "https://github.com/example/vexhub" {
		t.Errorf("unexpected source 0: %+v", sources[0])
	}
	if sources[1].Type != "csaf-provider" || sources[1].URL != "https://example.com/csaf/provider-metadata.json" {
		t.Errorf("unexpected source 1: %+v", sources[1])
	}
	if sources[2].Type != "oci-referrers" || sources[2].URL != "ghcr.io/example/app" {
		t.Errorf("unexpected source 2: %+v", sources[2])
	}
}

func TestParseVEXSourcesInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"invalid type", "unknown-type=https://example.com"},
		{"missing url", "openvex-hub="},
		{"malformed pair", "openvex-hub"},
		{"bad json", `[{"type": 123}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseVEXSources(tc.raw)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.raw)
			}
		})
	}
}

func TestLoadVEXSourcesEnv(t *testing.T) {
	os.Setenv("VEX_SOURCES", "openvex-hub=https://github.com/example/vexhub")
	os.Setenv("VEX_REFRESH_INTERVAL", "2h")
	defer os.Unsetenv("VEX_SOURCES")
	defer os.Unsetenv("VEX_REFRESH_INTERVAL")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !cfg.HasVEXSources() {
		t.Fatal("expected HasVEXSources() to be true")
	}
	if len(cfg.VEXSources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(cfg.VEXSources))
	}
	if cfg.VEXRefreshInterval != 2*time.Hour {
		t.Errorf("expected 2h refresh interval, got %v", cfg.VEXRefreshInterval)
	}
}

func TestLoadVEXSourcesZeroIntervalDisablesTicker(t *testing.T) {
	os.Setenv("VEX_SOURCES", "openvex-hub=https://github.com/example/vexhub")
	os.Setenv("VEX_REFRESH_INTERVAL", "0")
	defer os.Unsetenv("VEX_SOURCES")
	defer os.Unsetenv("VEX_REFRESH_INTERVAL")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.VEXRefreshInterval != 0 {
		t.Errorf("expected 0 refresh interval, got %v", cfg.VEXRefreshInterval)
	}
}

func TestLoadVEXSourcesNegativeIntervalRejected(t *testing.T) {
	os.Setenv("VEX_SOURCES", "openvex-hub=https://github.com/example/vexhub")
	os.Setenv("VEX_REFRESH_INTERVAL", "-10m")
	defer os.Unsetenv("VEX_SOURCES")
	defer os.Unsetenv("VEX_REFRESH_INTERVAL")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for negative VEX_REFRESH_INTERVAL, got nil")
	}
}
