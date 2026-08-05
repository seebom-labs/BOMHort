package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/repo"
	s3client "github.com/seebom-labs/bomhort/backend/internal/s3"
	"github.com/seebom-labs/bomhort/backend/internal/vex"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// uploadPath is the push-model SBOM/VEX upload route (#135). Defined once so
// the mux registration and the CORS per-route method scoping can't drift.
const uploadPath = "/api/v1/sboms/upload"

// uploadCleanupTimeout bounds the best-effort S3 RemoveObject issued when an
// upload was already staged but its ingestion-job enqueue failed. Runs on a
// fresh context (the request's may be cancelled), so it needs its own deadline.
const uploadCleanupTimeout = 10 * time.Second

// uuidPattern validates UUID path parameters to prevent injection.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// vulnIDPattern validates vulnerability IDs (e.g., CVE-2024-12345, GHSA-xxxx-xxxx-xxxx).
var vulnIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func main() {
	log.Println("BOMHort API Gateway starting...")

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
				SkipScan:     b.SkipScan,
			}
		}
		s3c, err = s3client.NewClient(bucketConfigs)
		if err != nil {
			log.Printf("WARNING: Failed to create S3 client for downloads: %v", err)
		} else {
			log.Printf("S3 client initialized for downloads (%d bucket(s))", len(cfg.S3Buckets))
		}
	}

	// Push-model upload storage (#135): either a dedicated skipScan S3 bucket,
	// or a writable local SBOM_DIR as a fallback. Resolved once at startup —
	// uploadHandler uses this instead of re-probing on every request.
	pushBucket, hasPushBucket := findS3PushBucket(cfg.S3Buckets)
	var uploadS3Store uploadObjectStore
	if hasPushBucket && s3c != nil {
		uploadS3Store = s3c
	} else {
		hasPushBucket = false // S3 client failed to initialize — fall back to local only
	}
	localUploadWritable := isDirWritable(filepath.Join(cfg.SBOMDir, "pushed"))
	if !hasPushBucket && !localUploadWritable {
		log.Printf("WARNING: no upload storage available — POST %s will return 503 until either S3_BUCKETS has a skipScan bucket or SBOM_DIR (%s) is writable", uploadPath, cfg.SBOMDir)
	} else if hasPushBucket {
		log.Printf("Push-model upload storage: S3 bucket %q (skipScan)", pushBucket.Name)
	} else {
		log.Printf("Push-model upload storage: local filesystem (%s/pushed)", cfg.SBOMDir)
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

	// Push-model SBOM upload (#135). Client pushes SBOM/VEX content directly
	// (e.g. from CI/CD) instead of BOMHort pulling from a filesystem/S3 scan.
	// Routed to the skipScan S3 bucket when one is configured, else written
	// under SBOM_DIR/pushed/, and enqueued as a normal IngestionJob — the
	// parsing-worker processes it exactly like any other job, so no ingestion
	// logic is duplicated here.
	mux.HandleFunc("POST "+uploadPath, uploadHandler(uploadDeps{
		cfg:           cfg,
		store:         chClient,
		s3Store:       uploadS3Store,
		pushBucket:    pushBucket,
		useS3Push:     hasPushBucket,
		localWritable: localUploadWritable,
	}))

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

		// POST is only ever valid on the upload route — advertising it on every
		// endpoint would be misleading for what is otherwise a read-only API.
		allowedMethods := "GET, OPTIONS"
		if r.URL.Path == uploadPath {
			allowedMethods = "GET, POST, OPTIONS"
		}
		w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Service-Token, X-API-Key, X-Filename")
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
			w.Header().Set("WWW-Authenticate", `Bearer realm="bomhort"`)
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

// uploadStore is the minimal surface uploadHandler needs, kept small for testing.
type uploadStore interface {
	HashExists(ctx context.Context, hash string) (bool, error)
	EnqueueJobs(ctx context.Context, jobs []models.IngestionJob) error
}

// uploadObjectStore is the minimal S3 write surface uploadHandler needs to
// route push-model uploads (#135) to a skipScan bucket, kept small for
// testing (mirrors uploadStore/pinger).
type uploadObjectStore interface {
	PutObject(ctx context.Context, bucket, key string, body io.Reader, size int64) error
	RemoveObject(ctx context.Context, bucket, key string) error
}

// findS3PushBucket returns the S3 bucket configured as the push-upload target
// (skipScan: true), if any. Only one push bucket is supported; if multiple
// are configured, the first one (in config order) wins and a warning is
// logged so the misconfiguration is visible at startup.
func findS3PushBucket(buckets []config.S3BucketConfig) (config.S3BucketConfig, bool) {
	var found []config.S3BucketConfig
	for _, b := range buckets {
		if b.SkipScan {
			found = append(found, b)
		}
	}
	if len(found) == 0 {
		return config.S3BucketConfig{}, false
	}
	if len(found) > 1 {
		names := make([]string, len(found))
		for i, b := range found {
			names[i] = b.Name
		}
		log.Printf("WARNING: multiple skipScan S3 buckets configured (%s) — only one push-upload target is supported, using %q", strings.Join(names, ", "), found[0].Name)
	}
	return found[0], true
}

// isDirWritable checks whether dir is writable by creating it (if missing)
// and writing + removing a throwaway temp file — the same technique the
// local upload fallback itself uses to persist pushed content, so this
// startup check exercises the exact path a real request would take.
func isDirWritable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// uploadDeps bundles uploadHandler's runtime dependencies and the storage-
// routing decision resolved once at startup (see findS3PushBucket and
// isDirWritable in main()), instead of six positional constructor
// parameters — two of them bools, which read ambiguously and are easy to
// transpose by accident at the call site.
type uploadDeps struct {
	cfg *config.Config

	store   uploadStore
	s3Store uploadObjectStore

	// pushBucket is the resolved skipScan S3 bucket to push uploads to.
	// Only meaningful when useS3Push is true; zero value otherwise.
	pushBucket config.S3BucketConfig
	// useS3Push is true when pushBucket is a valid push target and s3Store
	// is usable — uploads route to S3 instead of the local fallback.
	useS3Push bool
	// localWritable is true when cfg.SBOMDir/pushed is writable — the
	// local-filesystem fallback used when useS3Push is false.
	localWritable bool
}

// uploadHandler implements push-model SBOM/VEX upload (#135). It authenticates
// via the standard middleware chain, hashes and dedups the body against
// ClickHouse, persists it to whichever push-storage backend is configured —
// a dedicated skipScan S3 bucket, or SBOM_DIR/pushed/ as a local fallback —
// and enqueues a normal IngestionJob. The existing parsing-worker picks it up
// unmodified, whether the source is s3:// or a local path — no ingestion
// logic is duplicated here.
func uploadHandler(deps uploadDeps) http.HandlerFunc {
	cfg := deps.cfg
	store := deps.store
	s3Store := deps.s3Store
	pushBucket := deps.pushBucket
	useS3Push := deps.useS3Push
	localWritable := deps.localWritable

	return func(w http.ResponseWriter, r *http.Request) {
		// A write endpoint being open by default is a real risk, independent of
		// authMiddleware's default-off posture (which is an accepted default for
		// a read-only API). Refuse to serve uploads unless AUTH_ENABLED=true,
		// regardless of whether the global middleware would otherwise let the
		// request through.
		if !cfg.AuthEnabled {
			log.Printf("AUTH: rejected upload from %s — AUTH_ENABLED=false", clientIP(r))
			writeError(w, http.StatusForbidden, "Upload requires AUTH_ENABLED=true")
			return
		}

		if !useS3Push && !localWritable {
			writeError(w, http.StatusServiceUnavailable, "No upload storage configured — set S3_BUCKETS with a skipScan bucket, or ensure SBOM_DIR is writable")
			return
		}

		filename := filepath.Base(strings.TrimSpace(r.Header.Get("X-Filename")))
		if filename == "" || filename == "." || filename == "/" {
			writeError(w, http.StatusBadRequest, "X-Filename header is required")
			return
		}

		fileType, ok := repo.ClassifyFileType(filename)
		if !ok {
			writeError(w, http.StatusBadRequest, "Unsupported file type: filename must end in .spdx.json, .cdx.json, .openvex.json, .vex.json, or .json")
			return
		}

		// Stage the body in a local temp file for hashing + content validation
		// regardless of the final destination. When pushing to S3 there's no
		// same-volume rename to worry about, so stage in the OS temp dir; when
		// falling back to local storage, stage inside SBOM_DIR/pushed so the
		// final move is an atomic same-volume os.Rename. The ".tmp" suffix
		// keeps ClassifyFileType from ever matching this file if a concurrent
		// local Scan() walks pushedDir mid-upload.
		stagingDir := ""
		if !useS3Push {
			stagingDir = filepath.Join(cfg.SBOMDir, "pushed")
			if err := os.MkdirAll(stagingDir, 0o755); err != nil {
				log.Printf("ERROR: upload mkdir %s: %v", sanitizeLogParam(stagingDir), err)
				writeError(w, http.StatusInternalServerError, "Failed to store upload")
				return
			}
		}
		tmp, err := os.CreateTemp(stagingDir, "upload-*.tmp")
		if err != nil {
			log.Printf("ERROR: upload tempfile create in %q: %v", sanitizeLogParam(stagingDir), err)
			writeError(w, http.StatusInternalServerError, "Failed to store upload")
			return
		}
		tmpPath := tmp.Name()
		defer func() {
			_ = tmp.Close()
			_ = os.Remove(tmpPath) // no-op once the local fallback has renamed it into place below
		}()

		maxBytes := int64(cfg.MaxUploadSizeMB) * 1024 * 1024
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		hasher := sha256.New()
		n, err := io.Copy(io.MultiWriter(tmp, hasher), r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "Upload exceeds max size of "+strconv.Itoa(cfg.MaxUploadSizeMB)+"MB")
				return
			}
			log.Printf("ERROR: upload read for %s: %v", sanitizeLogParam(filename), err)
			writeError(w, http.StatusInternalServerError, "Failed to read upload body")
			return
		}
		if n == 0 {
			writeError(w, http.StatusBadRequest, "Empty request body")
			return
		}

		hash := hex.EncodeToString(hasher.Sum(nil))

		// Dedup: skip re-ingesting content BOMHort has already processed. This
		// is checked before content validation so repeat pushes of a file
		// that's already been ingested don't pay the parse cost again.
		//
		// Note: this check and the EnqueueJobs below are not atomic. Two
		// concurrent uploads of identical content (across replicas, or on one
		// replica) can both observe "not present" and both enqueue. That's
		// accepted here rather than serialized: the parsing worker is already
		// idempotent on re-ingested content (SBOMExists / VEXDocumentExists),
		// so the worst case is one redundant parse, not duplicated data.
		exists, err := store.HashExists(r.Context(), hash)
		if err != nil {
			log.Printf("ERROR: upload hash check for %s: %v", sanitizeLogParam(filename), err)
			writeError(w, http.StatusInternalServerError, "Failed to check for duplicate upload")
			return
		}
		if exists {
			writeJSON(w, http.StatusOK, map[string]string{
				"status":      "duplicate",
				"sha256_hash": hash,
				"message":     "Content already ingested, skipping",
			})
			return
		}

		// Validate content before persisting/enqueueing so bad uploads fail
		// fast with a 400 instead of a 202 that silently fails in the worker
		// minutes later. This intentionally stays lightweight: a full parse
		// (package/component extraction) belongs to the parsing-worker, not
		// here — duplicating it would undercut the point of the push model,
		// which is to reuse the existing ingestion pipeline unmodified.
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			log.Printf("ERROR: upload seek for %s: %v", sanitizeLogParam(filename), err)
			writeError(w, http.StatusInternalServerError, "Failed to validate upload")
			return
		}
		switch fileType {
		case models.JobTypeVEX:
			if _, err := vex.Parse(tmp, filename); err != nil {
				writeError(w, http.StatusBadRequest, "Invalid VEX content: "+err.Error())
				return
			}
		default: // sbom
			// We don't require a recognized format marker
			// (bomFormat/spdxVersion/predicateType) to be present — sbom.Parse
			// falls back to the SPDX parser for unrecognized shapes and handles
			// unknown input gracefully. We only need to catch content that isn't
			// a well-formed JSON document.
			//
			// Decode into json.RawMessage rather than a typed probe struct:
			// Decode reads exactly one JSON value and silently ignores anything
			// after it, and a bare `null` decodes successfully into any struct.
			// Both would let malformed payloads through with a 202 and defer the
			// failure to the worker — the exact outcome this check exists to
			// prevent. dec.More() + the object-shape check below close that gap.
			dec := json.NewDecoder(tmp)
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				writeError(w, http.StatusBadRequest, "Invalid SBOM content: not valid JSON")
				return
			}
			if dec.More() {
				writeError(w, http.StatusBadRequest, "Invalid SBOM content: unexpected trailing data after the JSON document")
				return
			}
			// Every supported SBOM format (SPDX, CycloneDX, in-toto envelope) is
			// a JSON object at the top level. null / arrays / bare scalars are
			// syntactically valid JSON but can never be a parseable SBOM.
			if len(raw) == 0 || raw[0] != '{' {
				writeError(w, http.StatusBadRequest, "Invalid SBOM content: expected a JSON object at the top level")
				return
			}
		}

		// Cluster: query param overrides this instance's configured default.
		cluster := cfg.ClusterName
		if c := strings.TrimSpace(r.URL.Query().Get("cluster")); c != "" {
			cluster = c
		}

		// Persist to whichever backend is active. Both paths only commit the
		// content to its final, discoverable location after hashing and
		// content validation succeed — the S3 PutObject / local os.Rename
		// below are the first point at which anything else could observe this
		// upload, so nothing ever sees a partial or invalid file/object.
		var sourceFile string
		if useS3Push {
			if _, err := tmp.Seek(0, io.SeekStart); err != nil {
				log.Printf("ERROR: upload seek for %s: %v", sanitizeLogParam(filename), err)
				writeError(w, http.StatusInternalServerError, "Failed to store upload")
				return
			}
			key := path.Join(pushBucket.Prefix, "pushed", uuid.New().String()+"-"+filename)
			if err := s3Store.PutObject(r.Context(), pushBucket.Name, key, tmp, n); err != nil {
				log.Printf("ERROR: upload S3 put %s/%s: %v", sanitizeLogParam(pushBucket.Name), sanitizeLogParam(key), err)
				writeError(w, http.StatusInternalServerError, "Failed to store upload")
				return
			}
			sourceFile = "s3://" + pushBucket.Name + "/" + key
		} else {
			relPath := filepath.Join("pushed", uuid.New().String()+"-"+filename)
			absPath := filepath.Join(cfg.SBOMDir, relPath)
			if err := tmp.Close(); err != nil {
				log.Printf("ERROR: upload close for %s: %v", sanitizeLogParam(relPath), err)
				writeError(w, http.StatusInternalServerError, "Failed to store upload")
				return
			}
			if err := os.Rename(tmpPath, absPath); err != nil {
				log.Printf("ERROR: upload rename %s -> %s: %v", sanitizeLogParam(tmpPath), sanitizeLogParam(relPath), err)
				writeError(w, http.StatusInternalServerError, "Failed to store upload")
				return
			}
			sourceFile = relPath
		}

		job := models.IngestionJob{
			CreatedAt:  time.Now(),
			JobID:      uuid.New(),
			SourceFile: sourceFile,
			SHA256Hash: hash,
			Status:     models.JobStatusPending,
			JobType:    fileType,
			Cluster:    cluster,
		}
		// Single-row insert, deliberately: the API contract returns job_id
		// synchronously, so the row has to be durable before we respond — there
		// is nothing to batch it with. This is the one place that departs from
		// the project-wide "always batch inserts" rule; ingestion_queue is a
		// low-volume control table, not a hot analytics path. If push traffic
		// ever grows enough for the small-parts pressure to matter, enable
		// ClickHouse async_insert=1 with wait_for_async_insert=1 rather than
		// buffering job rows in the gateway.
		if err := store.EnqueueJobs(r.Context(), []models.IngestionJob{job}); err != nil {
			log.Printf("ERROR: upload enqueue for %s: %v", sanitizeLogParam(sourceFile), err)
			// Best-effort cleanup so a failed enqueue doesn't leave an orphaned
			// file/object behind. Deliberately not r.Context(): the request
			// context may already be cancelled (that can be *why* the enqueue
			// failed), which would cancel the cleanup too. Bounded by its own
			// timeout so a hung S3 endpoint can't pin this goroutine forever.
			if useS3Push {
				if _, key, parseErr := s3client.ParseURI(sourceFile); parseErr == nil {
					cleanupCtx, cancel := context.WithTimeout(context.Background(), uploadCleanupTimeout)
					_ = s3Store.RemoveObject(cleanupCtx, pushBucket.Name, key)
					cancel()
				}
			} else {
				_ = os.Remove(filepath.Join(cfg.SBOMDir, sourceFile))
			}
			writeError(w, http.StatusInternalServerError, "Failed to enqueue ingestion job")
			return
		}

		log.Printf("Upload accepted: %s (job=%s, type=%s, cluster=%s, source=%s)", sanitizeLogParam(filename), job.JobID, fileType, sanitizeLogParam(cluster), sanitizeLogParam(sourceFile))

		writeJSON(w, http.StatusAccepted, map[string]string{
			"status":      "pending",
			"job_id":      job.JobID.String(),
			"sha256_hash": hash,
			"job_type":    fileType,
			"cluster":     cluster,
		})
	}
}
