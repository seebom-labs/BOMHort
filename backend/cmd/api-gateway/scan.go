package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/evaluate"
	gh "github.com/seebom-labs/bomhort/backend/internal/github"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/internal/repo"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

type scanDeps struct {
	cfg               *config.Config
	chClient          *clickhouse.Client
	osvClient         evaluate.OSVClient
	ghResolver        *gh.Resolver
	registryResolvers []evaluate.RegistryResolver
	exceptions        func() *license.ExceptionIndex
}

// scanHandler implements stateless SBOM evaluation (POST /api/v1/scan, #513).
// It accepts an SBOM payload, evaluates findings, license compliance, and summary
// statistics in-memory, checks the requested policy threshold (?fail_on=),
// and returns the results synchronously without persisting to ClickHouse.
func scanHandler(deps scanDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// A write or resource-intensive endpoint being open by default is a
		// real risk. Refuse to serve scans unless AUTH_ENABLED=true, matching upload.
		if !deps.cfg.AuthEnabled {
			log.Printf("AUTH: rejected scan from %s - AUTH_ENABLED=false", clientIP(r))
			writeError(w, http.StatusForbidden, "Scan requires AUTH_ENABLED=true")
			return
		}

		filename := r.Header.Get("X-Filename")
		if filename == "" {
			filename = "scan.json"
		}
		if _, ok := repo.ClassifyFileType(filename); !ok {
			writeError(w, http.StatusBadRequest, "Unsupported file type: filename must end in .spdx.json, .cdx.json, .openvex.json, .vex.json, or .json")
			return
		}

		maxBytes := int64(deps.cfg.MaxUploadSizeMB) * 1024 * 1024
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "Scan body exceeds max size of "+strconv.Itoa(deps.cfg.MaxUploadSizeMB)+"MB")
				return
			}
			log.Printf("ERROR: scan read: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to read request body")
			return
		}
		if len(raw) == 0 {
			writeError(w, http.StatusBadRequest, "Empty request body")
			return
		}

		// Validate top-level JSON structure before evaluation.
		dec := json.NewDecoder(bytes.NewReader(raw))
		var jsonProbe json.RawMessage
		if err := dec.Decode(&jsonProbe); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid SBOM content: not valid JSON")
			return
		}
		if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
			writeError(w, http.StatusBadRequest, "Invalid SBOM content: unexpected trailing data after the JSON document")
			return
		}
		if len(jsonProbe) == 0 || jsonProbe[0] != '{' {
			writeError(w, http.StatusBadRequest, "Invalid SBOM content: expected a JSON object at the top level")
			return
		}

		scanTimeout := time.Duration(deps.cfg.ScanTimeout) * time.Second
		if scanTimeout <= 0 {
			scanTimeout = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
		defer cancel()

		var ghLookup evaluate.GitHubLookup
		if deps.ghResolver != nil {
			ghLookup = func(ctx context.Context, purl string) (string, error) {
				meta, err := deps.ghResolver.ResolveWithMetadataErr(ctx, purl)
				if err != nil {
					return "", err
				}
				if meta == nil {
					return "", nil
				}
				return meta.SPDXID, nil
			}
		}

		failOn := r.URL.Query().Get("fail_on")
		hasher := sha256.New()
		hasher.Write(raw)
		hash := hex.EncodeToString(hasher.Sum(nil))

		evalResult, err := evaluate.Evaluate(ctx, bytes.NewReader(raw), evaluate.Options{
			SourceFile:        filename,
			SHA256Hash:        hash,
			MaxPURLs:          deps.cfg.ScanMaxPURLs,
			SkipOSV:           deps.cfg.SkipOSV,
			StrictOSV:         true,
			FailOn:            failOn,
			OSVClient:         deps.osvClient,
			GitHubLookup:      ghLookup,
			RegistryResolvers: deps.registryResolvers,
			Exceptions:        deps.exceptions,
		})
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
				writeError(w, http.StatusGatewayTimeout, "Scan execution timed out")
				return
			}
			if errors.Is(err, evaluate.ErrPURLCapExceeded) {
				writeError(w, http.StatusRequestEntityTooLarge, err.Error())
				return
			}
			if errors.Is(err, evaluate.ErrInvalidFailOn) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			if errors.Is(err, gh.ErrRateLimited) {
				writeError(w, http.StatusTooManyRequests, "GitHub rate limit exceeded during license resolution")
				return
			}
			if errors.Is(err, evaluate.ErrOSVUnavailable) {
				log.Printf("ERROR: scan OSV evaluation for %s: %v", sanitizeLogParam(filename), err)
				writeError(w, http.StatusBadGateway, "Vulnerability check unavailable: "+err.Error())
				return
			}
			log.Printf("ERROR: scan evaluation for %s: %v", sanitizeLogParam(filename), err)
			writeError(w, http.StatusBadRequest, "Failed to evaluate SBOM: "+err.Error())
			return
		}

		// Best-effort cache persistence to ClickHouse.
		if deps.chClient != nil {
			if deps.ghResolver != nil {
				if entries := deps.ghResolver.CacheEntries(); len(entries) > 0 {
					_ = deps.chClient.InsertGitHubLicenseCache(ctx, entries)
				}
				if metaEntries := deps.ghResolver.MetadataCacheEntries(); len(metaEntries) > 0 {
					_ = deps.chClient.InsertGitHubRepoMetadata(ctx, metaEntries)
				}
			}
			evaluate.PersistRegistryCaches(ctx, deps.chClient, deps.registryResolvers)
		}

		response := dto.ScanResponse{
			PolicyResult:      evalResult.PolicyResult,
			PolicyReason:      evalResult.PolicyReason,
			Summary:           evalResult.Summary,
			Vulnerabilities:   evalResult.Findings,
			LicenseCompliance: evalResult.LicenseCompliance,
		}

		writeJSON(w, http.StatusOK, response)
	}
}
