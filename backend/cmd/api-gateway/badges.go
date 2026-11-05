package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

const maxBadgeCacheEntries = 10000

// badgeCache stores rendered badge SVGs in-process with a TTL so
// README views in high-traffic repositories never overload ClickHouse.
// It also provides negative caching (caching 404 not-found entries with
// a short TTL) to mitigate cache-miss Denial of Service floods.
// To prevent memory growth, expired entries are evicted on Set and the
// cache size is capped at maxBadgeCacheEntries.
type badgeCacheEntry struct {
	svg       []byte
	notFound  bool
	expiresAt time.Time
}

type badgeCache struct {
	sync.RWMutex
	entries     map[string]badgeCacheEntry
	ttl         time.Duration
	negativeTTL time.Duration
}

func newBadgeCache(ttl, negativeTTL time.Duration) *badgeCache {
	return &badgeCache{
		entries:     make(map[string]badgeCacheEntry),
		ttl:         ttl,
		negativeTTL: negativeTTL,
	}
}

func (bc *badgeCache) Get(key string) ([]byte, bool, bool) {
	bc.RLock()
	defer bc.RUnlock()
	entry, ok := bc.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false, false
	}
	if entry.notFound {
		return nil, true, true
	}
	return entry.svg, true, false
}

func (bc *badgeCache) setEntry(key string, entry badgeCacheEntry) {
	bc.Lock()
	defer bc.Unlock()

	now := time.Now()
	for k, e := range bc.entries {
		if now.After(e.expiresAt) {
			delete(bc.entries, k)
		}
	}
	if len(bc.entries) >= maxBadgeCacheEntries {
		bc.entries = make(map[string]badgeCacheEntry)
	}

	bc.entries[key] = entry
}

func (bc *badgeCache) Set(key string, svg []byte) {
	bc.setEntry(key, badgeCacheEntry{
		svg:       svg,
		notFound:  false,
		expiresAt: time.Now().Add(bc.ttl),
	})
}

func (bc *badgeCache) SetNotFound(key string) {
	bc.setEntry(key, badgeCacheEntry{
		notFound:  true,
		expiresAt: time.Now().Add(bc.negativeTTL),
	})
}

// Shields-style flat SVG template (zero external dependencies).
const badgeSVGTemplate = `<svg xmlns="http://www.w3.org/2000/svg" width="{{.TotalWidth}}" height="20" role="img" aria-label="{{.Label}}: {{.Value}}">
  <title>{{.Label}}: {{.Value}}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{{.TotalWidth}}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{{.LabelWidth}}" height="20" fill="#555"/>
    <rect x="{{.LabelWidth}}" width="{{.ValueWidth}}" height="20" fill="{{.Color}}"/>
    <rect width="{{.TotalWidth}}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{{.LabelX}}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{{.LabelTextLength}}">{{.Label}}</text>
    <text x="{{.LabelX}}" y="140" transform="scale(.1)" fill="#fff" textLength="{{.LabelTextLength}}">{{.Label}}</text>
    <text aria-hidden="true" x="{{.ValueX}}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{{.ValueTextLength}}">{{.Value}}</text>
    <text x="{{.ValueX}}" y="140" transform="scale(.1)" fill="#fff" textLength="{{.ValueTextLength}}">{{.Value}}</text>
  </g>
</svg>`

var parsedBadgeTmpl = template.Must(template.New("badge").Parse(badgeSVGTemplate))

type badgeView struct {
	Label           string
	Value           string
	Color           string
	LabelWidth      int
	ValueWidth      int
	TotalWidth      int
	LabelX          int
	ValueX          int
	LabelTextLength int
	ValueTextLength int
}

func measureText(text string) int {
	width := 0
	for _, r := range text {
		switch {
		case r >= 'A' && r <= 'Z':
			width += 8
		case r == 'm' || r == 'w' || r == 'M' || r == 'W':
			width += 9
		case r == 'i' || r == 'l' || r == 'j' || r == 't' || r == ' ' || r == '.' || r == '·':
			width += 4
		case r >= '0' && r <= '9':
			width += 7
		default:
			width += 6
		}
	}
	return width
}

func renderShieldBadge(label, value, color string) ([]byte, error) {
	lblTextW := measureText(label)
	valTextW := measureText(value)

	lblW := lblTextW + 10
	valW := valTextW + 10
	totW := lblW + valW

	v := badgeView{
		Label:           html.EscapeString(label),
		Value:           html.EscapeString(value),
		Color:           color,
		LabelWidth:      lblW,
		ValueWidth:      valW,
		TotalWidth:      totW,
		LabelX:          (lblW * 10) / 2,
		ValueX:          lblW*10 + (valW*10)/2,
		LabelTextLength: lblTextW * 10,
		ValueTextLength: valTextW * 10,
	}
	var buf bytes.Buffer
	if err := parsedBadgeTmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("render badge svg: %w", err)
	}
	return buf.Bytes(), nil
}

// vulnBadgeColor returns the background color for the vulnerability badge
// based on the worst non-zero bucket.
func vulnBadgeColor(crit, high, med, low uint64) string {
	switch {
	case crit > 0:
		return "#cb2431" // Red
	case high > 0:
		return "#e05d44" // Orange-red
	case med > 0:
		return "#dfb317" // Yellow
	case low > 0:
		return "#6b7280" // Grey
	default:
		return "#44cc11" // Green
	}
}

// licenseBadgeData returns the label, value, and color for the license compliance badge.
func licenseBadgeData(violations, unknown uint64) (string, string) {
	if violations > 0 {
		val := fmt.Sprintf("%d violations", violations)
		if violations == 1 {
			val = "1 violation"
		}
		return val, "#cb2431" // Red
	}
	if unknown > 0 {
		val := fmt.Sprintf("%d unknown", unknown)
		return val, "#9f9f9f" // Grey
	}
	return "compliant", "#44cc11" // Green
}

// resolveProjectStats fetches the vulnerability and license stats for a project.
func resolveProjectStats(ctx context.Context, chClient *clickhouse.Client, name, version string) (*dto.ProjectBadgeStats, error) {
	return chClient.QueryProjectBadgeStats(ctx, name, version)
}

func handleProjectBadge(
	cfg *config.Config,
	chClient *clickhouse.Client,
	cache *badgeCache,
	kind string,
	badgeData func(cfg *config.Config, stats *dto.ProjectBadgeStats) (label, value, color string),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := sanitizeProjectName(r.PathValue("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, "Invalid project name")
			return
		}
		version := strings.TrimSpace(r.URL.Query().Get("version"))
		cacheKey := fmt.Sprintf("%s:%s:%s", kind, name, version)
		if svg, found, notFound := cache.Get(cacheKey); found {
			if notFound {
				writeError(w, http.StatusNotFound, "Project not found")
				return
			}
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "max-age=3600")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(svg)
			return
		}

		stats, err := resolveProjectStats(r.Context(), chClient, name, version)
		if err != nil {
			if errors.Is(err, clickhouse.ErrSBOMNotFound) {
				cache.SetNotFound(cacheKey)
				writeError(w, http.StatusNotFound, "Project not found")
				return
			}
			log.Printf("ERROR: project badge stats for %s (%s): %v", sanitizeLogParam(name), kind, err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch project badge")
			return
		}

		label, val, color := badgeData(cfg, stats)
		svg, err := renderShieldBadge(label, val, color)
		if err != nil {
			log.Printf("ERROR: render %s badge for %s: %v", kind, sanitizeLogParam(name), err)
			writeError(w, http.StatusInternalServerError, "Failed to render badge")
			return
		}
		cache.Set(cacheKey, svg)

		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(svg)
	}
}
