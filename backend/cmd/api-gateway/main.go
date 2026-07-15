package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/seebom-labs/seebom/backend/internal/clickhouse"
	"github.com/seebom-labs/seebom/backend/internal/config"
	"github.com/seebom-labs/seebom/backend/internal/license"
	s3client "github.com/seebom-labs/seebom/backend/internal/s3"
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

	// Initialize S3 client for SBOM download (if S3 sources are configured).
	var s3c *s3client.Client
	if cfg.HasS3Sources() {
		bucketConfigs := make([]s3client.BucketConfig, len(cfg.S3Buckets))
		for i, b := range cfg.S3Buckets {
			bucketConfigs[i] = s3client.BucketConfig{
				Name:         b.Name,
				Endpoint:     b.Endpoint,
				Region:       b.Region,
				AccessKey:    b.AccessKey,
				SecretKey:    b.SecretKey,
				Prefix:       b.Prefix,
				UsePathStyle: b.UsePathStyle,
				UseSSL:       b.UseSSL,
			}
		}
		s3c, err = s3client.NewClient(bucketConfigs)
		if err != nil {
			log.Printf("WARNING: Failed to create S3 client for downloads: %v", err)
		} else {
			log.Printf("S3 client initialized for downloads (%d bucket(s))", len(cfg.S3Buckets))
		}
	}

	exceptionsPath := cfg.ExceptionsFile
	sbomDirExceptionsPath := cfg.SBOMDir + "/license-exceptions.json"

	// Load license policy (permissive/copyleft classification).
	if perm, copy, err := license.LoadPolicy(cfg.LicensePolicyFile); err == nil {
		log.Printf("Loaded license policy: %d permissive, %d copyleft", perm, copy)
	} else {
		log.Printf("Using default license policy: %v", err)
	}

	mux := http.NewServeMux()

	// Health check (legacy/general).
	mux.HandleFunc("GET /healthz", livezHandler())
	// Liveness probe: process is up. Must NOT depend on external systems so a
	// transient DB outage does not cause K8s to kill otherwise-healthy pods.
	mux.HandleFunc("GET /livez", livezHandler())
	// Readiness probe: pod is ready only when ClickHouse is reachable. Returns
	// 503 otherwise so K8s removes the pod from Service endpoints.
	mux.HandleFunc("GET /readyz", readyzHandler(chClient))

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

	// Project list view – groups SBOMs by project with aggregated stats.
	mux.HandleFunc("GET /api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))
		search := sanitizeSearchTerm(r.URL.Query().Get("search"))

		resp, err := chClient.QueryProjects(r.Context(), page, pageSize, search)
		if err != nil {
			log.Printf("ERROR: list projects: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch projects")
			return
		}
		writeJSON(w, http.StatusOK, resp)
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

	mux.HandleFunc("GET /api/v1/packages/search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			writeError(w, http.StatusBadRequest, "Missing required query parameter 'q'")
			return
		}
		q = sanitizeLogParam(q)
		page, _ := strconv.ParseUint(r.URL.Query().Get("page"), 10, 64)
		pageSize, _ := strconv.ParseUint(r.URL.Query().Get("page_size"), 10, 64)
		pageSize = clampPageSize(pageSize)
		result, err := chClient.QueryDependencySearch(r.Context(), q, page, pageSize)
		if err != nil {
			log.Printf("ERROR: package search q=%s: %v", sanitizeLogParam(q), err)
			writeError(w, http.StatusInternalServerError, "Failed to search packages")
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	mux.HandleFunc("GET /api/v1/packages/detail", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			writeError(w, http.StatusBadRequest, "Missing required query parameter 'name'")
			return
		}
		page, _ := strconv.ParseUint(r.URL.Query().Get("page"), 10, 64)
		pageSize, _ := strconv.ParseUint(r.URL.Query().Get("page_size"), 10, 64)
		pageSize = clampPageSize(pageSize)
		result, err := chClient.QueryPackageDetail(r.Context(), name, page, pageSize)
		if err != nil {
			log.Printf("ERROR: package detail name=%s: %v", sanitizeLogParam(name), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch package detail")
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	// ── Global Search ─────────────────────────────────────────────────
	// Faceted search across packages, projects, vulnerabilities, licenses.
	mux.HandleFunc("GET /api/v1/search", func(w http.ResponseWriter, r *http.Request) {
		q := sanitizeSearchTerm(r.URL.Query().Get("q"))
		if len(q) < minSearchQueryLen {
			writeError(w, http.StatusBadRequest, "Query parameter 'q' must be at least 2 characters")
			return
		}
		limit := clampSearchLimit(parseUint64(r.URL.Query().Get("limit"), 5))
		result, err := chClient.QueryGlobalSearch(r.Context(), q, limit)
		if err != nil {
			log.Printf("ERROR: global search q=%s: %v", sanitizeLogParam(q), err)
			writeError(w, http.StatusInternalServerError, "Failed to perform search")
			return
		}
		writeJSON(w, http.StatusOK, result)
	})

	// ── Cluster Endpoints (#132, #133) ────────────────────────────────

	// List all clusters with summary statistics.
	mux.HandleFunc("GET /api/v1/clusters", func(w http.ResponseWriter, r *http.Request) {
		clusters, err := chClient.QueryClusters(r.Context())
		if err != nil {
			log.Printf("ERROR: list clusters: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch clusters")
			return
		}
		writeJSON(w, http.StatusOK, clusters)
	})

	// Cluster detail stats.
	mux.HandleFunc("GET /api/v1/clusters/{name}/stats", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" || len(name) > 200 {
			writeError(w, http.StatusBadRequest, "Invalid cluster name")
			return
		}
		stats, err := chClient.QueryClusterStats(r.Context(), name)
		if err != nil {
			log.Printf("ERROR: cluster stats for %s: %v", sanitizeLogParam(name), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch cluster stats")
			return
		}
		if stats.TotalSBOMs == 0 {
			writeError(w, http.StatusNotFound, "Cluster not found")
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})

	// Cluster SBOMs (paginated).
	mux.HandleFunc("GET /api/v1/clusters/{name}/sboms", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name == "" || len(name) > 200 {
			writeError(w, http.StatusBadRequest, "Invalid cluster name")
			return
		}
		page := parseUint64(r.URL.Query().Get("page"), 1)
		pageSize := clampPageSize(parseUint64(r.URL.Query().Get("page_size"), 50))
		resp, err := chClient.QueryClusterSBOMs(r.Context(), name, page, pageSize)
		if err != nil {
			log.Printf("ERROR: cluster sboms for %s: %v", sanitizeLogParam(name), err)
			writeError(w, http.StatusInternalServerError, "Failed to fetch cluster SBOMs")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	})

	// ── SBOM Download (#144) ──────────────────────────────────────────
	// Streams the original SBOM file from S3 or local filesystem.
	mux.HandleFunc("GET /api/v1/sboms/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}

		sourceFile, err := chClient.QuerySBOMSourceFile(r.Context(), sbomID)
		if err != nil || sourceFile == "" {
			log.Printf("ERROR: sbom download lookup for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusNotFound, "SBOM not found")
			return
		}

		// Determine filename for Content-Disposition.
		filename := filepath.Base(sourceFile)
		if filename == "." || filename == "/" {
			filename = sbomID + ".json"
		}

		// Open the file from S3 or local filesystem.
		var rc io.ReadCloser
		if strings.HasPrefix(sourceFile, "s3://") {
			if s3c == nil {
				writeError(w, http.StatusServiceUnavailable, "S3 not configured for downloads")
				return
			}
			bucket, key, parseErr := s3client.ParseURI(sourceFile)
			if parseErr != nil {
				log.Printf("ERROR: sbom download parse URI %s: %v", sanitizeLogParam(sourceFile), parseErr)
				writeError(w, http.StatusInternalServerError, "Invalid source file path")
				return
			}
			rc, err = s3c.GetObject(r.Context(), bucket, key)
			if err != nil {
				log.Printf("ERROR: sbom download S3 get %s: %v", sanitizeLogParam(sourceFile), err)
				writeError(w, http.StatusNotFound, "SBOM file not found in storage")
				return
			}
		} else {
			// Local filesystem.
			absPath := filepath.Join(cfg.SBOMDir, sourceFile)
			f, openErr := os.Open(absPath)
			if openErr != nil {
				log.Printf("ERROR: sbom download local open %s: %v", sanitizeLogParam(absPath), openErr)
				writeError(w, http.StatusNotFound, "SBOM file not found in storage")
				return
			}
			rc = f
		}
		defer rc.Close()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, rc); err != nil {
			log.Printf("ERROR: sbom download stream for %s: %v", sanitizeLogParam(sbomID), err)
		}
	})

	// CORS + security middleware for Angular dev server.
	// Order (outermost first): security headers → rate limit → CORS → auth → mux.
	// Auth sits closest to the mux so 401s still get CORS + security headers.
	handler := securityHeadersMiddleware(
		rateLimitMiddleware(
			corsMiddleware(cfg.CORSAllowedOrigins,
				authMiddleware(cfg.AuthEnabled, cfg.ServiceToken, cfg.APIKeys, mux),
			),
		),
	)

	addr := ":" + strconv.Itoa(cfg.APIPort)
	if cfg.AuthEnabled {
		modes := []string{}
		if cfg.ServiceToken != "" {
			modes = append(modes, "service-token")
		}
		if len(cfg.APIKeys) > 0 {
			modes = append(modes, "api-keys("+strconv.Itoa(len(cfg.APIKeys))+")")
		}
		if len(modes) == 0 {
			log.Printf("WARNING: AUTH_ENABLED=true but neither SERVICE_TOKEN nor API_KEYS is configured — ALL authenticated requests will be rejected")
		} else {
			log.Printf("API authentication enabled (modes: %s)", strings.Join(modes, ", "))
		}
	} else {
		log.Println("API authentication disabled (set AUTH_ENABLED=true to enforce)")
	}
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

// minSearchQueryLen is the minimum length for a global search query.
const minSearchQueryLen = 2

// clampSearchLimit bounds the per-facet result limit for global search.
func clampSearchLimit(v uint64) uint64 {
	const maxSearchLimit = 50
	if v == 0 {
		return 5
	}
	if v > maxSearchLimit {
		return maxSearchLimit
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Service-Token, X-API-Key")
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

// authPublicPaths lists request paths that bypass authentication even when
// AUTH_ENABLED=true. K8s probes and CORS preflight must always succeed.
var authPublicPaths = map[string]struct{}{
	"/healthz": {},
	"/livez":   {},
	"/readyz":  {},
}

// authMiddleware enforces authentication when enabled. Accepts any of:
//   - Authorization: Bearer <service-token>
//   - X-Service-Token: <service-token>
//   - X-API-Key: <api-key>
//
// All comparisons use constant-time equality to prevent timing attacks.
// When AUTH_ENABLED=false, this middleware is a no-op pass-through.
func authMiddleware(enabled bool, serviceToken string, apiKeys []string, next http.Handler) http.Handler {
	if !enabled {
		return next
	}

	// Pre-compute byte slices for constant-time comparison.
	serviceTokenBytes := []byte(serviceToken)
	apiKeyBytes := make([][]byte, len(apiKeys))
	for i, k := range apiKeys {
		apiKeyBytes[i] = []byte(k)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Public paths bypass auth (health probes).
		if _, ok := authPublicPaths[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		// CORS preflight bypasses auth (cors middleware handles OPTIONS).
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Extract candidate credential from any supported header.
		var presented []byte
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			presented = []byte(strings.TrimPrefix(h, "Bearer "))
		} else if h := r.Header.Get("X-Service-Token"); h != "" {
			presented = []byte(h)
		} else if h := r.Header.Get("X-API-Key"); h != "" {
			presented = []byte(h)
		}

		if len(presented) == 0 {
			log.Printf("AUTH: missing credential on %s %s from %s",
				sanitizeLogParam(r.Method), sanitizeLogParam(r.URL.Path), clientIP(r))
			w.Header().Set("WWW-Authenticate", `Bearer realm="seebom"`)
			writeError(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		// Service token check (constant-time).
		if len(serviceTokenBytes) > 0 && subtle.ConstantTimeCompare(presented, serviceTokenBytes) == 1 {
			next.ServeHTTP(w, r)
			return
		}

		// API key check (constant-time over each configured key).
		for _, k := range apiKeyBytes {
			if subtle.ConstantTimeCompare(presented, k) == 1 {
				next.ServeHTTP(w, r)
				return
			}
		}

		log.Printf("AUTH: invalid credential on %s %s from %s",
			sanitizeLogParam(r.Method), sanitizeLogParam(r.URL.Path), clientIP(r))
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
	})
}

// clientIP extracts the originating IP, preferring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		ip = strings.SplitN(ip, ",", 2)[0]
		return strings.TrimSpace(ip)
	}
	return r.RemoteAddr
}

// pinger is the minimal surface readyzHandler needs, kept small for testing.
type pinger interface {
	Ping(ctx context.Context) error
}

// livezHandler reports process liveness. It never touches external systems.
func livezHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}

// readyzHandler reports readiness based on ClickHouse connectivity.
func readyzHandler(p pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := p.Ping(ctx); err != nil {
			log.Printf("ERROR: readiness check failed: %v", err)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable","reason":"clickhouse"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}
