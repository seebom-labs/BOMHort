package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
)

func TestRenderShieldBadge(t *testing.T) {
	svgBytes, err := renderShieldBadge("BOMHort", "0 C · 2 H · 7 M · 11 L", "#e05d44")
	if err != nil {
		t.Fatalf("renderShieldBadge failed: %v", err)
	}
	svg := string(svgBytes)

	if !strings.HasPrefix(svg, "<svg") {
		t.Fatalf("expected SVG prefix, got: %s", svg)
	}
	if !strings.HasSuffix(strings.TrimSpace(svg), "</svg>") {
		t.Fatalf("expected SVG closing tag, got: %s", svg)
	}
	if !strings.Contains(svg, "BOMHort") {
		t.Errorf("SVG missing label BOMHort")
	}
	if !strings.Contains(svg, "0 C · 2 H · 7 M · 11 L") {
		t.Errorf("SVG missing value string")
	}
	if !strings.Contains(svg, `fill="#e05d44"`) {
		t.Errorf("SVG missing color #e05d44")
	}
}

func TestVulnBadgeColor(t *testing.T) {
	cases := []struct {
		crit, high, med, low uint64
		expectedColor        string
	}{
		{0, 0, 0, 0, "#44cc11"}, // all clean
		{0, 0, 0, 5, "#6b7280"}, // low only
		{0, 0, 3, 5, "#dfb317"}, // medium worst
		{0, 2, 0, 1, "#e05d44"}, // high worst
		{1, 0, 0, 0, "#cb2431"}, // critical worst
		{2, 3, 4, 5, "#cb2431"}, // critical beats all
	}

	for _, c := range cases {
		got := vulnBadgeColor(c.crit, c.high, c.med, c.low)
		if got != c.expectedColor {
			t.Errorf("vulnBadgeColor(%d,%d,%d,%d): got %s, want %s",
				c.crit, c.high, c.med, c.low, got, c.expectedColor)
		}
	}
}

func TestLicenseBadgeData(t *testing.T) {
	cases := []struct {
		violations, unknown uint64
		expectedVal         string
		expectedColor       string
	}{
		{0, 0, "compliant", "#44cc11"},
		{0, 1, "1 unknown", "#9f9f9f"},
		{0, 5, "5 unknown", "#9f9f9f"},
		{1, 0, "1 violation", "#cb2431"},
		{4, 2, "4 violations", "#cb2431"},
	}

	for _, c := range cases {
		val, color := licenseBadgeData(c.violations, c.unknown)
		if val != c.expectedVal || color != c.expectedColor {
			t.Errorf("licenseBadgeData(%d, %d): got (%s, %s), want (%s, %s)",
				c.violations, c.unknown, val, color, c.expectedVal, c.expectedColor)
		}
	}
}

func TestBadgeCache(t *testing.T) {
	cache := newBadgeCache(50*time.Millisecond, 50*time.Millisecond)

	cache.Set("test-key", []byte("<svg>badge</svg>"))

	// Immediate hit
	got, found, notFound := cache.Get("test-key")
	if !found || notFound || string(got) != "<svg>badge</svg>" {
		t.Fatalf("expected cache hit with content, got found=%v, notFound=%v, content=%s", found, notFound, string(got))
	}

	// Missing key
	_, found, _ = cache.Get("missing-key")
	if found {
		t.Fatal("expected cache miss for missing key")
	}

	// Negative caching (not-found entry)
	cache.SetNotFound("not-found-key")
	got, found, notFound = cache.Get("not-found-key")
	if !found || !notFound || got != nil {
		t.Fatalf("expected negative cache hit, got found=%v, notFound=%v", found, notFound)
	}

	// Expiration
	time.Sleep(60 * time.Millisecond)
	_, found, _ = cache.Get("test-key")
	if found {
		t.Fatal("expected cache miss after expiration")
	}
	_, found, _ = cache.Get("not-found-key")
	if found {
		t.Fatal("expected negative cache miss after expiration")
	}
}

func TestBadgeCache_EvictionAndCap(t *testing.T) {
	cache := newBadgeCache(10*time.Millisecond, 10*time.Millisecond)

	// Add an entry and wait for it to expire
	cache.Set("expired-1", []byte("<svg>1</svg>"))
	time.Sleep(15 * time.Millisecond)

	// Adding a new entry triggers eviction of expired entries
	cache.Set("active-2", []byte("<svg>2</svg>"))

	cache.RLock()
	_, exists := cache.entries["expired-1"]
	cache.RUnlock()
	if exists {
		t.Errorf("expected expired-1 to be evicted on Set")
	}

	// Test cap reset behavior: simulate map reaching maxBadgeCacheEntries
	cache.Lock()
	for i := 0; i < maxBadgeCacheEntries; i++ {
		cache.entries[fmt.Sprintf("k-%d", i)] = badgeCacheEntry{
			svg:       []byte("svg"),
			expiresAt: time.Now().Add(1 * time.Hour),
		}
	}
	cache.Unlock()

	// Setting one more entry when at maxBadgeCacheEntries should reset and keep only the new entry
	cache.Set("after-cap", []byte("<svg>new</svg>"))

	cache.RLock()
	entryCount := len(cache.entries)
	cache.RUnlock()
	if entryCount != 1 {
		t.Errorf("expected cache to reset to 1 entry after exceeding cap, got %d", entryCount)
	}
}

func TestRenderShieldBadgeEscapesXSS(t *testing.T) {
	svgBytes, err := renderShieldBadge(`<script>alert("xss")</script>`, `foo&bar"baz`, "#cb2431")
	if err != nil {
		t.Fatalf("renderShieldBadge failed: %v", err)
	}
	svg := string(svgBytes)

	if strings.Contains(svg, "<script>") {
		t.Errorf("SVG contains raw unescaped script tag: %s", svg)
	}
	if !strings.Contains(svg, "&lt;script&gt;") {
		t.Errorf("expected escaped XML entities in SVG: %s", svg)
	}
}

func testClickHouseClient(t *testing.T) *clickhouse.Client {
	t.Helper()
	host := os.Getenv("CLICKHOUSE_HOST")
	if host == "" {
		t.Skip("CLICKHOUSE_HOST not set — skipping ClickHouse integration test")
	}
	port := os.Getenv("CLICKHOUSE_PORT")
	if port == "" {
		port = "9000"
	}
	portNum := 9000
	if p, err := strconv.Atoi(port); err == nil {
		portNum = p
	}
	db := os.Getenv("CLICKHOUSE_DATABASE")
	if db == "" {
		db = "bomhort"
	}
	cfg := &config.Config{
		ClickHouseHost:     host,
		ClickHousePort:     portNum,
		ClickHouseUser:     "default",
		ClickHousePassword: os.Getenv("CLICKHOUSE_PASSWORD"),
		ClickHouseDatabase: db,
	}
	c, err := clickhouse.NewClient(cfg)
	if err != nil {
		t.Fatalf("clickhouse.NewClient: %v", err)
	}
	return c
}

// TestResolveProjectStats verifies that default project badges inspect only the latest
// version (so a CVE resolved in a prior version does not taint the badge), and that approved
// license exemptions are excluded from violations so an exempted package evaluates to compliant.
func TestResolveProjectStats(t *testing.T) {
	c := testClickHouseClient(t)
	ctx := context.Background()

	suffix := uuid.New().String()[:8]
	projectName := "badge-test-" + suffix
	sbomV1 := uuid.New().String()
	sbomV2 := uuid.New().String()

	now := time.Now().UTC().Truncate(time.Second)
	hash := func(seed string) string {
		s := seed + suffix
		for len(s) < 64 {
			s += "0"
		}
		return s[:64]
	}

	// Insert v1 (older, has a critical CVE)
	if err := c.Conn.Exec(ctx, `
		INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
			document_namespace, sha256_hash, creation_date, creator_tools,
			cluster, namespace, project, source_repo, source_ref, document_version, tags)
		VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, '', '', '1.0.0', [])`,
		now.Add(-2*time.Hour), sbomV1, "fixtures/"+projectName+"/1.0.0.spdx.json", projectName+" 1.0.0",
		hash(sbomV1), now.Add(-2*time.Hour), projectName,
	); err != nil {
		t.Fatalf("insert sbom v1: %v", err)
	}

	if err := c.Conn.Exec(ctx, `
		INSERT INTO vulnerabilities (discovered_at, sbom_id, source_file, purl, vuln_id,
			severity, summary, affected_versions, fixed_version, osv_json, aliases,
			cluster, namespace, project)
		VALUES (?, ?, '', 'pkg:generic/lib@1.0.0', 'CVE-2024-TEST-V1',
			'CRITICAL', 'fixture', [], '', '{}', [], '', '', '')`,
		now.Add(-2*time.Hour), sbomV1,
	); err != nil {
		t.Fatalf("insert vuln v1: %v", err)
	}

	// Insert v2 (newer/latest, zero CVEs, 1 copyleft package with approved exemption)
	if err := c.Conn.Exec(ctx, `
		INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
			document_namespace, sha256_hash, creation_date, creator_tools,
			cluster, namespace, project, source_repo, source_ref, document_version, tags)
		VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, '', '', '2.0.0', [])`,
		now.Add(-1*time.Hour), sbomV2, "fixtures/"+projectName+"/2.0.0.spdx.json", projectName+" 2.0.0",
		hash(sbomV2), now.Add(-1*time.Hour), projectName,
	); err != nil {
		t.Fatalf("insert sbom v2: %v", err)
	}

	if err := c.Conn.Exec(ctx, `
		INSERT INTO license_compliance (checked_at, sbom_id, source_file, license_id, category,
			package_count, non_compliant_packages, exempted_packages, exemption_reason,
			cluster, namespace, project)
		VALUES (?, ?, '', 'GPL-3.0-only', 'copyleft', 1, [], ['pkg:generic/exempted-tool@1.0'], 'approved tool', '', '', '')`,
		now.Add(-1*time.Hour), sbomV2,
	); err != nil {
		t.Fatalf("insert license_compliance v2: %v", err)
	}

	t.Cleanup(func() {
		ids := []string{sbomV1, sbomV2}
		for _, table := range []string{"sboms", "vulnerabilities", "license_compliance"} {
			_ = c.Conn.Exec(ctx, fmt.Sprintf("ALTER TABLE %s DELETE WHERE sbom_id IN (?) SETTINGS mutations_sync = 1", table), ids)
		}
	})

	// 1. Resolve stats for the default (latest) version: must yield 0 vulns and compliant
	latestStats, err := resolveProjectStats(ctx, c, projectName, "")
	if err != nil {
		t.Fatalf("resolveProjectStats (latest): %v", err)
	}
	if latestStats.CriticalVulns != 0 || latestStats.HighVulns != 0 || latestStats.MediumVulns != 0 || latestStats.LowVulns != 0 {
		t.Errorf("expected 0 vulnerabilities on latest version, got C=%d H=%d M=%d L=%d",
			latestStats.CriticalVulns, latestStats.HighVulns, latestStats.MediumVulns, latestStats.LowVulns)
	}
	if latestStats.Violations != 0 {
		t.Errorf("expected 0 license violations (exempted package), got %d", latestStats.Violations)
	}
	val, color := licenseBadgeData(latestStats.Violations, latestStats.Unknown)
	if val != "compliant" || color != "#44cc11" {
		t.Errorf("expected license badge compliant/#44cc11, got %s/%s", val, color)
	}

	// 2. Resolve stats for version 1.0.0: must reflect the historical critical CVE
	v1Stats, err := resolveProjectStats(ctx, c, projectName, "1.0.0")
	if err != nil {
		t.Fatalf("resolveProjectStats (v1): %v", err)
	}
	if v1Stats.CriticalVulns != 1 {
		t.Errorf("expected 1 critical vuln for version 1.0.0, got %d", v1Stats.CriticalVulns)
	}
}
