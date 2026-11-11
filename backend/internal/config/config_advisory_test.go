package config

import "testing"

func TestLoad_AdvisorySources(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AdvisorySources) != 0 {
		t.Fatalf("default sources = %+v, want none", cfg.AdvisorySources)
	}

	t.Setenv("ADVISORY_SOURCES", "wolfi|https://feed.example/osv/all.json|pkg:apk/wolfi")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AdvisorySources) != 1 || cfg.AdvisorySources[0].Name != "wolfi" || cfg.AdvisorySources[0].Prefixes[0] != "pkg:apk/wolfi" {
		t.Fatalf("sources = %+v", cfg.AdvisorySources)
	}

	t.Setenv("ADVISORY_SOURCES", "osv|https://feed.example/osv/all.json")
	if _, err := Load(); err == nil {
		t.Fatal("reserved source name accepted")
	}
}
