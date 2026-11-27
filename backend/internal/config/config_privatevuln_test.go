package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad_PrivateVulnerabilitiesDefaults(t *testing.T) {
	for _, env := range []string{
		"PRIVATE_VULNERABILITIES_FILE", "PRIVATE_VULNERABILITIES_SOURCE",
		"PRIVATE_VULNERABILITIES_SOURCE_TOKEN", "PRIVATE_VULNERABILITIES_REFRESH_INTERVAL",
	} {
		os.Unsetenv(env)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PrivateVulnerabilitiesFile != "/data/config/private-vulnerabilities.json" {
		t.Errorf("file = %q, want /data/config/private-vulnerabilities.json", cfg.PrivateVulnerabilitiesFile)
	}
	if cfg.PrivateVulnerabilitiesSource != "" || cfg.PrivateVulnerabilitiesSourceToken != "" {
		t.Errorf("source = %q token = %q, want empty", cfg.PrivateVulnerabilitiesSource, cfg.PrivateVulnerabilitiesSourceToken)
	}
	if cfg.PrivateVulnerabilitiesRefreshInterval != 60*time.Second {
		t.Errorf("interval = %v, want 60s", cfg.PrivateVulnerabilitiesRefreshInterval)
	}
}

func TestLoad_PrivateVulnerabilitiesSource(t *testing.T) {
	t.Setenv("PRIVATE_VULNERABILITIES_SOURCE", "https://example.com/private-vulns.json")
	t.Setenv("PRIVATE_VULNERABILITIES_SOURCE_TOKEN", "secret-token")
	t.Setenv("PRIVATE_VULNERABILITIES_REFRESH_INTERVAL", "5m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PrivateVulnerabilitiesSource != "https://example.com/private-vulns.json" {
		t.Errorf("source = %q", cfg.PrivateVulnerabilitiesSource)
	}
	if cfg.PrivateVulnerabilitiesSourceToken != "secret-token" {
		t.Errorf("token = %q", cfg.PrivateVulnerabilitiesSourceToken)
	}
	if cfg.PrivateVulnerabilitiesRefreshInterval != 5*time.Minute {
		t.Errorf("interval = %v", cfg.PrivateVulnerabilitiesRefreshInterval)
	}
}
