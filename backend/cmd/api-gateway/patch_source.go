package main

import (
	"context"
	"errors"
	"log"
	"net/http"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/apikey"
	"github.com/seebom-labs/bomhort/backend/internal/clickhouse"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/sourcerepo"
)

// sourceUpdater is the slice of the ClickHouse client the PATCH handler needs;
// an interface so tests exercise the handler without a database.
type sourceUpdater interface {
	UpdateSBOMSource(ctx context.Context, sbomID, sourceRepo, sourceRef string) error
}

// patchSourceRequest is the PATCH /api/v1/sboms/{id} body. Pointers
// distinguish "field absent — leave it alone" from `""` — "clear it": both
// are legitimate requests (fix one field; remove a wrong pin), and a flat
// string cannot express the difference.
type patchSourceRequest struct {
	SourceRepo *string `json:"source_repo"`
	SourceRef  *string `json:"source_ref"`
}

// sourceReader fetches the current values so a partial PATCH can preserve the
// untouched field, and provides ownership dimensions for authorization checks (#456).
type sourceReader interface {
	QuerySBOMSource(ctx context.Context, sbomID string) (repo, ref, origin, cluster, namespace, project string, err error)
}

// patchSBOMSourceHandler implements PATCH /api/v1/sboms/{id} (#332): set or
// clear source_repo/source_ref on an existing SBOM. This is the manual escape
// hatch for the documents whose extraction yielded nothing (Syft dir: scans,
// pkg:generic roots) — the alternative is a per-repo pin in every consumer's
// config, which is exactly what #332 exists to remove.
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
		if req.SourceRepo == nil && req.SourceRef == nil {
			writeError(w, http.StatusBadRequest, "Provide source_repo and/or source_ref")
			return
		}

		// Validate before reading current state: reject garbage without a
		// round-trip. Empty string is valid — it clears the field.
		if req.SourceRepo != nil && *req.SourceRepo != "" && !sourcerepo.IsValidRepoURL(*req.SourceRepo) {
			writeError(w, http.StatusBadRequest, "source_repo must be an http(s) repository URL without credentials")
			return
		}
		if req.SourceRef != nil && *req.SourceRef != "" && !sourcerepo.IsValidRef(*req.SourceRef) {
			writeError(w, http.StatusBadRequest, "source_ref must be a git ref without whitespace (max 256 chars)")
			return
		}

		// Partial PATCH: absent fields keep their current value.
		repo, ref, origin, cluster, namespace, project, err := reader.QuerySBOMSource(r.Context(), sbomID)
		if err != nil {
			if errors.Is(err, clickhouse.ErrSBOMNotFound) {
				writeError(w, http.StatusNotFound, "SBOM not found")
				return
			}
			log.Printf("ERROR: patch source read for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to read SBOM")
			return
		}

		// Enforce named key scope on target SBOM (#456).
		if authKey := apikey.FromContext(r.Context()); authKey != nil {
			if err := authKey.Scope.CheckUpload(authKey.Name, origin, cluster, namespace, project); err != nil {
				log.Printf("AUTH: patch source forbidden for key %q from %s: %v", authKey.Name, clientIP(r), err)
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
		}

		if req.SourceRepo != nil {
			repo = *req.SourceRepo
			// Normalise so a PATCHed value is stored in the same canonical form
			// as an extracted one; keep an inline @ref only if the caller did
			// not state a ref themselves.
			if repo != "" {
				if norm, normRef := sourcerepo.Normalize(repo); norm != "" {
					repo = norm
					if req.SourceRef == nil && normRef != "" {
						ref = normRef
					}
				}
			}
		}
		if req.SourceRef != nil {
			ref = *req.SourceRef
		}

		if err := store.UpdateSBOMSource(r.Context(), sbomID, repo, ref); err != nil {
			if errors.Is(err, clickhouse.ErrSBOMNotFound) {
				writeError(w, http.StatusNotFound, "SBOM not found")
				return
			}
			log.Printf("ERROR: patch source update for %s: %v", sanitizeLogParam(sbomID), err)
			writeError(w, http.StatusInternalServerError, "Failed to update SBOM")
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"sbom_id":     sbomID,
			"source_repo": repo,
			"source_ref":  ref,
		})
	}
}
