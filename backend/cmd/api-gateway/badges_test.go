package main

import (
	"strings"
	"testing"
	"time"
)

func TestRenderShieldBadge(t *testing.T) {
	svgBytes := renderShieldBadge("BOMHort", "0 C · 2 H · 7 M · 11 L", "#e05d44")
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

func TestRenderShieldBadgeEscapesXSS(t *testing.T) {
	svgBytes := renderShieldBadge(`<script>alert("xss")</script>`, `foo&bar"baz`, `"><script>`)
	svg := string(svgBytes)

	if strings.Contains(svg, "<script>") {
		t.Errorf("SVG contains raw unescaped script tag: %s", svg)
	}
	if !strings.Contains(svg, "&lt;script&gt;") {
		t.Errorf("expected escaped XML entities in SVG: %s", svg)
	}
	if strings.Contains(svg, `fill=""><script>"`) {
		t.Errorf("color was not sanitized: %s", svg)
	}
}
