package main

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seebom-labs/seebom/backend/internal/clickhouse"
	"github.com/seebom-labs/seebom/backend/internal/config"
	"github.com/seebom-labs/seebom/backend/internal/license"
)

// uuidPattern validates UUID path parameters to prevent injection.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// vulnIDPattern validates vulnerability IDs (e.g., CVE-2024-12345, GHSA-xxxx-xxxx-xxxx).
var vulnIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func main() {
	log.Println("SeeBOM API Gateway starting...")

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	chClient, err := clickhouse.NewClient(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}
	defer chClient.Close()

	exceptionsPath := cfg.ExceptionsFile
	sbomDirExceptionsPath := cfg.SBOMDir + "/license-exceptions.json"

	// Load license policy (permissive/copyleft classification).
	if perm, copy, err := license.LoadPolicy(cfg.LicensePolicyFile); err == nil {
		log.Printf("Loaded license policy: %d permissive, %d copyleft", perm, copy)
	} else {
		log.Printf("Using default license policy: %v", err)
	}

	mux := http.NewServeMux()

	// Health check.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// Dashboard stats.
	mux.HandleFunc("GET /api/v1/stats/dashboard", func(w http.ResponseWriter, r *http.Request) {
		stats, err := chClient.QueryDashboardStats(r.Context())
		if err != nil {
			log.Printf("ERROR: dashboard stats: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch dashboard stats")
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})

	// List SBOMs with pagination and optional search.
	mux.HandleFunc("GET /api/v1/sboms", func(w http.ResponseWriter, r *http.Request) {
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))
		search := sanitizeSearchTerm(r.URL.Query().Get("search"))

		resp, err := chClient.QuerySBOMs(r.Context(), page, pageSize, search)
		if err != nil {
			log.Printf("ERROR: list sboms: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch SBOMs")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// List vulnerabilities with pagination and optional VEX filtering.
	mux.HandleFunc("GET /api/v1/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))
		vexFilter := r.URL.Query().Get("vex_filter")
		// Only allow known filter values to prevent unexpected query modification.
		if vexFilter != "" && vexFilter != "effective" {
			vexFilter = ""
		}

		resp, err := chClient.QueryVulnerabilities(r.Context(), page, pageSize, vexFilter)
		if err != nil {
			log.Printf("ERROR: list vulnerabilities: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch vulnerabilities")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// License compliance overview.
	mux.HandleFunc("GET /api/v1/licenses/compliance", func(w http.ResponseWriter, r *http.Request) {
		items, err := chClient.QueryLicenseCompliance(r.Context())
		if err != nil {
			log.Printf("ERROR: license compliance: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch license compliance")
			return
		}
		writeJSON(w, http.StatusOK, items)
	})

	// SBOM dependency tree.
	mux.HandleFunc("GET /api/v1/sboms/{id}/dependencies", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}

		nodes, err := chClient.QuerySBOMDependencies(r.Context(), sbomID)
		if err != nil {
			log.Printf("ERROR: sbom dependencies for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch dependencies")
			return
		}
		writeJSON(w, http.StatusOK, nodes)
	})

	// SBOM detail with severity breakdown.
	mux.HandleFunc("GET /api/v1/sboms/{id}/detail", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		detail, err := chClient.QuerySBOMDetail(r.Context(), sbomID)
		if err != nil {
			log.Printf("ERROR: sbom detail for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch SBOM detail")
			return
		}
		writeJSON(w, http.StatusOK, detail)
	})

	// Vulnerabilities for a specific SBOM.
	mux.HandleFunc("GET /api/v1/sboms/{id}/vulnerabilities", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		vulns, err := chClient.QuerySBOMVulnerabilities(r.Context(), sbomID)
		if err != nil {
			log.Printf("ERROR: sbom vulns for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch SBOM vulnerabilities")
			return
		}
		writeJSON(w, http.StatusOK, vulns)
	})

	// Licenses for a specific SBOM.
	mux.HandleFunc("GET /api/v1/sboms/{id}/licenses", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		licenses, err := chClient.QuerySBOMLicenses(r.Context(), sbomID)
		if err != nil {
			log.Printf("ERROR: sbom licenses for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch SBOM licenses")
			return
		}
		writeJSON(w, http.StatusOK, licenses)
	})

	// Projects with non-compliant licenses (filtered by exceptions).
	mux.HandleFunc("GET /api/v1/projects/license-compliance", func(w http.ResponseWriter, r *http.Request) {
		// Load current exceptions for filtering (try config path, then SBOM dir).
		excIdx, _ := license.LoadExceptionsWithFallback(exceptionsPath, sbomDirExceptionsPath)
		violations, err := chClient.QueryProjectsWithLicenseViolations(r.Context(), excIdx)
		if err != nil {
			log.Printf("ERROR: license violations: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch license violations")
			return
		}
		writeJSON(w, http.StatusOK, violations)
	})

	// Projects affected by a specific CVE (including transitive dependencies).
	mux.HandleFunc("GET /api/v1/vulnerabilities/{id}/affected-projects", func(w http.ResponseWriter, r *http.Request) {
		vulnID := r.PathValue("id")
		if !isValidVulnID(vulnID) {
			writeError(w, http.StatusBadRequest, "Invalid vulnerability ID")
			return
		}
		projects, err := chClient.QueryAffectedProjectsByCVE(r.Context(), vulnID)
		if err != nil {
			log.Printf("ERROR: affected projects for %s: %v", sanitizeLogParam(vulnID), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch affected projects")
			return
		}
		writeJSON(w, http.StatusOK, projects)
	})

	// Dependency usage statistics across all projects.
	mux.HandleFunc("GET /api/v1/stats/dependencies", func(w http.ResponseWriter, r *http.Request) {
		limit := clampPageSize(parseUint64(r.URL.Query().Get("limit"), 50))
		stats, err := chClient.QueryDependencyStats(r.Context(), limit)
		if err != nil {
			log.Printf("ERROR: dependency stats: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch dependency stats")
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})

	// Version skew: packages with inconsistent versions across projects.
	mux.HandleFunc("GET /api/v1/stats/version-skew", func(w http.ResponseWriter, r *http.Request) {
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))
		search := sanitizeSearchTerm(r.URL.Query().Get("search"))
		resp, err := chClient.QueryVersionSkew(r.Context(), page, pageSize, search)
		if err != nil {
			log.Printf("ERROR: version skew: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch version skew data")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// VEX statements list with pagination.
	mux.HandleFunc("GET /api/v1/vex/statements", func(w http.ResponseWriter, r *http.Request) {
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))

		resp, err := chClient.QueryVEXStatements(r.Context(), page, pageSize)
		if err != nil {
			log.Printf("ERROR: list vex statements: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch VEX statements")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// ── License Exceptions (read-only from config file or SBOM dir) ────
	mux.HandleFunc("GET /api/v1/license-exceptions", func(w http.ResponseWriter, r *http.Request) {
		idx, err := license.LoadExceptionsWithFallback(exceptionsPath, sbomDirExceptionsPath)
		if err != nil || idx == nil {
			writeJSON(w, http.StatusOK, license.ExceptionsFile{
				Version:           "1.0.0",
				BlanketExceptions: []license.BlanketException{},
				Exceptions:        []license.Exception{},
			})
			return
		}
		writeJSON(w, http.StatusOK, idx.Raw)
	})

	// ── License Policy (read-only, permissive/copyleft classification) ─
	mux.HandleFunc("GET /api/v1/license-policy", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, license.GetPolicy())
	})

	// ── Archived GitHub Packages ───────────────────────────────────────
	mux.HandleFunc("GET /api/v1/packages/archived", func(w http.ResponseWriter, r *http.Request) {
		packages, err := chClient.QueryArchivedPackages(r.Context())
		if err != nil {
			log.Printf("ERROR: archived packages: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch archived packages")
			return
		}
		writeJSON(w, http.StatusOK, packages)
	})

	// CORS + security middleware for Angular dev server.
	handler := securityHeadersMiddleware(
		rateLimitMiddleware(
			corsMiddleware(cfg.CORSAllowedOrigins, mux),
		),
	)

	addr := ":" + strconv.Itoa(cfg.APIPort)
	log.Printf("API Gateway listening on %s", addr)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ERROR: Failed to encode JSON response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func parseUint64(s string, fallback uint64) uint64 {
	if s == "" {
		return fallback
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fallback
	}
	return v
}

// clampPageSize enforces a maximum page size to prevent abusive queries.
func clampPageSize(v uint64) uint64 {
	const maxPageSize = 500
	if v == 0 {
		return 50
	}
	if v > maxPageSize {
		return maxPageSize
	}
	return v
}

// sanitizeSearchTerm cleans a user-provided search string.
// It trims whitespace, enforces a maximum length, and removes characters
// that could be used for XSS or injection attacks.
func sanitizeSearchTerm(s string) string {
	s = strings.TrimSpace(s)
	// Limit length to prevent abuse.
	const maxLen = 200
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	// Remove characters that have no business in a project name search:
	// HTML tags, script injections, null bytes, etc.
	s = strings.NewReplacer(
		"<", "", ">", "", "&", "", "\"", "", "'", "",
		";", "", "\x00", "", "\\", "",
	).Replace(s)
	return s
}

// isValidUUID checks whether the given string matches UUID format.
func isValidUUID(s string) bool {
	return s != "" && uuidPattern.MatchString(s)
}

// isValidVulnID checks whether the string is a valid vulnerability identifier
// (CVE-xxxx-xxxx, GHSA-xxxx, OSV-xxxx, etc.).
func isValidVulnID(s string) bool {
	return s != "" && vulnIDPattern.MatchString(s)
}

// sanitizeLogParam strips newlines and control characters to prevent log injection.
func sanitizeLogParam(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// securityHeadersMiddleware adds standard security headers to every response.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0") // Modern browsers: CSP replaces this
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// corsMiddleware handles CORS with configurable allowed origins.
func corsMiddleware(allowedOrigins string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if allowedOrigins == "*" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			for _, allowed := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(allowed) == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
					break
				}
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware implements a simple per-IP sliding-window rate limiter.
// Allows 100 requests per 10 seconds per IP.
func rateLimitMiddleware(next http.Handler) http.Handler {
	type visitor struct {
		count    int
		windowAt time.Time
	}
	var (
		mu       sync.Mutex
		visitors = make(map[string]*visitor)
	)

	const (
		maxRequests = 100
		window      = 10 * time.Second
	)

	// Background cleanup every 60 seconds to prevent memory leak.
	go func() {
		for {
			time.Sleep(60 * time.Second)
			mu.Lock()
			now := time.Now()
			for ip, v := range visitors {
				if now.Sub(v.windowAt) > window*6 {
					delete(visitors, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract client IP (prefer X-Forwarded-For behind reverse proxy).
		ip := r.Header.Get("X-Forwarded-For")
		if ip != "" {
			ip = strings.SplitN(ip, ",", 2)[0]
			ip = strings.TrimSpace(ip)
		} else {
			ip = r.RemoteAddr
		}

		mu.Lock()
		v, exists := visitors[ip]
		now := time.Now()
		if !exists || now.Sub(v.windowAt) > window {
			visitors[ip] = &visitor{count: 1, windowAt: now}
			mu.Unlock()
		} else {
			v.count++
			if v.count > maxRequests {
				mu.Unlock()
				w.Header().Set("Retry-After", "10")
				writeError(w, http.StatusTooManyRequests, "Rate limit exceeded")
				return
			}
			mu.Unlock()
		}

		next.ServeHTTP(w, r)
	})
}
