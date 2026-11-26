package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/sourcerepo"
	tagpkg "github.com/seebom-labs/bomhort/backend/internal/tags"
)

// sourceUpdater is the slice of the ClickHouse client the PATCH handler needs;
// an interface so tests exercise the handler without a database. Only non-nil
// fields are modified so concurrent partial updates do not overwrite each other.
type sourceUpdater interface {
	UpdateSBOMSource(ctx context.Context, sbomID string, sourceRepo, sourceRef *string, tags *[]string) error
}

// patchSourceRequest is the PATCH /api/v1/sboms/{id} body. Pointers
// distinguish "field absent — leave it alone" from `""` or `[]` — "clear it":
// both are legitimate requests (fix one field; remove a wrong pin or tag), and
// flat types cannot express the difference.
type patchSourceRequest struct {
	SourceRepo *string   `json:"source_repo"`
	SourceRef  *string   `json:"source_ref"`
	Tags       *[]string `json:"tags"`
}

// patchSourceResponse is returned on successful PATCH /api/v1/sboms/{id}.
// source_repo and source_ref deliberately omit omitempty to preserve the
// API response shape when values are empty.
type patchSourceResponse struct {
	SBOMID     string   `json:"sbom_id"`
	SourceRepo string   `json:"source_repo"`
	SourceRef  string   `json:"source_ref"`
	Tags       []string `json:"tags"`
}

// sourceReader fetches the current values so the response includes all
// attribution fields after mutating the requested columns.
type sourceReader interface {
	QuerySBOMSource(ctx context.Context, sbomID string) (repo, ref string, tags []string, err error)
}

// patchSBOMSourceHandler implements PATCH /api/v1/sboms/{id} (#332, #636): set or
// clear source_repo/source_ref and tags on an existing SBOM. This is the manual escape
// hatch for the documents whose extraction yielded nothing (Syft dir: scans,
// pkg:generic roots) or whose tags changed after ingestion — the alternative is a
// per-repo pin in every consumer's config, which is exactly what #332 exists to remove.
func patchSBOMSourceHandler(cfg *config.Config, store sourceUpdater, reader sourceReader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Same policy as upload: mutating endpoints exist only when the
		// instance actually authenticates callers. An unauthenticated PATCH
		// would let anyone redirect triage tooling to arbitrary repos.
		if !cfg.AuthEnabled {
			writeError(w, http.StatusForbidden, "PATCH requires AUTH_ENABLED=true")
			return
		}

		sbomID := r.PathValue("id")
		if _, err := uuid.Parse(sbomID); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}

		var req patchSourceRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		if req.SourceRepo == nil && req.SourceRef == nil && req.Tags == nil {
			writeError(w, http.StatusBadRequest, "Provide source_repo, source_ref, and/or tags")
			return
		}

		// Validate before writing: reject garbage without a round-trip. Empty
		// string is valid — it clears the field.
		if req.SourceRepo != nil && *req.SourceRepo != "" && !sourcerepo.IsValidRepoURL(*req.SourceRepo) {
			writeError(w, http.StatusBadRequest, "source_repo must be an http(s) repository URL without credentials")
			return
		}
		if req.SourceRef != nil && *req.SourceRef != "" && !sourcerepo.IsValidRef(*req.SourceRef) {
			writeError(w, http.StatusBadRequest, "source_ref must be a git ref without whitespace (max 256 chars)")
			return
		}
		if req.Tags != nil {
			// Tags cannot contain commas because query filters (?tag=...) split
			// on commas; a comma-containing tag could never be filtered.
			for _, t := range *req.Tags {
				if strings.Contains(t, ",") {
					writeError(w, http.StatusBadRequest, "tags cannot contain commas")
					return
				}
			}
		}

		var updateRepo *string
		var updateRef *string
		var updateTags *[]string

		if req.SourceRepo != nil {
			repo := *req.SourceRepo
			// Normalise so a PATCHed value is stored in the same canonical form
			// as an extracted one; keep an inline @ref only if the caller did
			// not state a ref themselves.
			if repo != "" {
				if norm, normRef := sourcerepo.Normalize(repo); norm != "" {
					repo = norm
					if req.SourceRef == nil && normRef != "" {
						updateRef = &normRef
					}
				}
			}
			updateRepo = &repo
		}
		if req.SourceRef != nil {
			ref := *req.SourceRef
			updateRef = &ref
		}
		if req.Tags != nil {
			// Tags replace the SBOM's custom tags, merging with instance-wide TAGS (#636).
			// Passing an empty array clears the SBOM's custom tags while preserving instance tags.
			normalized := tagpkg.Merge(cfg.Tags, tagpkg.Normalize(*req.Tags))
			if normalized == nil {
				normalized = []string{}
			}
			updateTags = &normalized
		}

		if err := store.UpdateSBOMSource(r.Context(), sbomID, updateRepo, updateRef, updateTags); err != nil {
			if errors.Is(err, clickhouse.ErrSBOMNotFound) {
				writeError(w, http.StatusNotFound, "SBOM not found")
				return
			}
			log.Printf("ERROR: patch source update for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to update SBOM")
			return
		}

		repo, ref, tags, err := reader.QuerySBOMSource(r.Context(), sbomID)
		if err != nil {
			if errors.Is(err, clickhouse.ErrSBOMNotFound) {
				writeError(w, http.StatusNotFound, "SBOM not found")
				return
			}
			log.Printf("ERROR: patch source read for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to read SBOM")
			return
		}

		if tags == nil {
			tags = []string{}
		}

		writeJSON(w, http.StatusOK, patchSourceResponse{
			SBOMID:     sbomID,
			SourceRepo: repo,
			SourceRef:  ref,
			Tags:       tags,
		})
	}
}
