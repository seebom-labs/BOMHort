package tea

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	json "github.com/goccy/go-json"
)

// Handler serves Transparency Exchange API (TEA Beta 2) requests.
type Handler struct {
	svc     *Service
	baseURL string
}

// NewHandler creates a TEA HTTP handler.
func NewHandler(svc *Service, baseURL string) *Handler {
	return &Handler{
		svc:     svc,
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

// ServeHTTP routes and handles TEA requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeTEAError(w, http.StatusMethodNotAllowed, ErrCodeInvalidRequest, "only GET and HEAD methods are supported")
		return
	}

	p := r.URL.Path

	// 1. Direct /.well-known/tea path
	if p == "/.well-known/tea" {
		h.handleWellKnown(w, r)
		return
	}

	// Normalize prefix: strip /api/v1/tea or /tea, and optional /v1.0.0 or /v1
	sub := p
	for _, prefix := range []string{"/api/v1/tea", "/tea"} {
		if strings.HasPrefix(sub, prefix) {
			sub = strings.TrimPrefix(sub, prefix)
			break
		}
	}
	if strings.HasPrefix(sub, "/v1.0.0") {
		sub = strings.TrimPrefix(sub, "/v1.0.0")
	} else if strings.HasPrefix(sub, "/v1") {
		sub = strings.TrimPrefix(sub, "/v1")
	}
	sub = "/" + strings.TrimLeft(sub, "/")

	// Route dispatch
	switch {
	case sub == "/.well-known/tea":
		h.handleWellKnown(w, r)

	case sub == "/discovery":
		h.handleDiscovery(w, r)

	case sub == "/products":
		h.handleProducts(w, r)

	case strings.HasPrefix(sub, "/product/"):
		h.handleProductRoute(w, r, strings.TrimPrefix(sub, "/product/"))

	case sub == "/productReleases":
		h.handleAllProductReleases(w, r)

	case strings.HasPrefix(sub, "/productRelease/"):
		h.handleProductReleaseRoute(w, r, strings.TrimPrefix(sub, "/productRelease/"))

	case sub == "/components":
		h.handleComponents(w, r)

	case strings.HasPrefix(sub, "/component/"):
		h.handleComponentRoute(w, r, strings.TrimPrefix(sub, "/component/"))

	case sub == "/componentReleases":
		h.handleAllComponentReleases(w, r)

	case strings.HasPrefix(sub, "/componentRelease/"):
		h.handleComponentReleaseRoute(w, r, strings.TrimPrefix(sub, "/componentRelease/"))

	case strings.HasPrefix(sub, "/artifact/"):
		h.handleArtifactRoute(w, r, strings.TrimPrefix(sub, "/artifact/"))

	default:
		writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "unknown TEA route")
	}
}

func (h *Handler) effectiveBaseURL(r *http.Request) string {
	if h.baseURL != "" {
		return h.baseURL
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/v1/tea", scheme, r.Host)
}

// GET /.well-known/tea
func (h *Handler) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	doc := h.svc.GetWellKnown(h.effectiveBaseURL(r))
	writeJSON(w, http.StatusOK, doc)
}

// GET /discovery?tei=... or ?purl=...
func (h *Handler) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tei := q.Get("tei")
	purl := q.Get("purl")

	info, err := h.svc.Discover(r.Context(), tei, purl, h.effectiveBaseURL(r))
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			writeTEAError(w, http.StatusBadRequest, ErrCodeInvalidRequest, err.Error())
			return
		}
		if errors.Is(err, ErrNotFound) {
			writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "identifier could not be resolved to any product release")
			return
		}
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, info)
}

// GET /products
func (h *Handler) handleProducts(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	resp, err := h.svc.ListProducts(r.Context(), page, pageSize)
	if err != nil {
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Route under /product/...
func (h *Handler) handleProductRoute(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	idOrUUID := parts[0]

	if len(parts) == 1 {
		// GET /product/{uuid}
		prod, err := h.svc.GetProduct(r.Context(), idOrUUID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "product not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, prod)
		return
	}

	if len(parts) == 2 && parts[1] == "releases" {
		// GET /product/{uuid}/releases
		page, pageSize := parsePagination(r)
		resp, err := h.svc.ListProductReleases(r.Context(), idOrUUID, page, pageSize)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "product not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "unknown product sub-resource")
}

// GET /productReleases
func (h *Handler) handleAllProductReleases(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	resp, err := h.svc.ListAllProductReleases(r.Context(), page, pageSize)
	if err != nil {
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Route under /productRelease/...
func (h *Handler) handleProductReleaseRoute(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	releaseUUID := parts[0]

	if len(parts) == 1 {
		// GET /productRelease/{uuid}
		rel, err := h.svc.GetProductRelease(r.Context(), releaseUUID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "product release not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, rel)
		return
	}

	if parts[1] == "collections" {
		// GET /productRelease/{uuid}/collections
		col, err := h.svc.GetCollection(r.Context(), releaseUUID, 1)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "release not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, PaginatedResponse[Collection]{
			HasNext: false,
			Results: []Collection{*col},
		})
		return
	}

	if parts[1] == "collection" {
		version := 1
		if len(parts) >= 3 && parts[2] != "latest" {
			v, err := strconv.Atoi(parts[2])
			if err == nil && v > 0 {
				version = v
			}
		}

		col, err := h.svc.GetCollection(r.Context(), releaseUUID, version)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "collection not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, col)
		return
	}

	writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "unknown product release sub-resource")
}

// GET /components
func (h *Handler) handleComponents(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	resp, err := h.svc.ListComponents(r.Context(), page, pageSize)
	if err != nil {
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// Route under /component/...
func (h *Handler) handleComponentRoute(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	idOrUUID := parts[0]

	if len(parts) == 1 {
		// GET /component/{uuid}
		comp, err := h.svc.GetComponent(r.Context(), idOrUUID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "component not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, comp)
		return
	}

	if len(parts) == 2 && parts[1] == "releases" {
		// GET /component/{uuid}/releases
		page, pageSize := parsePagination(r)
		resp, err := h.svc.ListComponentReleases(r.Context(), idOrUUID, page, pageSize)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "component not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "unknown component sub-resource")
}

// GET /componentReleases
func (h *Handler) handleAllComponentReleases(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	resp, err := h.svc.ListAllProductReleases(r.Context(), page, pageSize)
	if err != nil {
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}
	results := make([]ComponentRelease, 0, len(resp.Results))
	for _, pr := range resp.Results {
		results = append(results, ComponentRelease{
			UUID:        ComponentReleaseUUID(pr.UUID),
			Component:   ComponentUUID("", pr.ProductName),
			Version:     pr.Version,
			CreatedDate: pr.CreatedDate,
			ReleaseDate: pr.ReleaseDate,
			Identifiers: pr.Identifiers,
		})
	}
	writeJSON(w, http.StatusOK, PaginatedResponse[ComponentRelease]{
		HasNext:       resp.HasNext,
		NextPageToken: resp.NextPageToken,
		Results:       results,
	})
}

// Route under /componentRelease/...
func (h *Handler) handleComponentReleaseRoute(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	releaseUUID := parts[0]

	if len(parts) == 1 {
		// GET /componentRelease/{uuid}
		cr, err := h.svc.GetComponentRelease(r.Context(), releaseUUID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "component release not found")
				return
			}
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, cr)
		return
	}

	if parts[1] == "collections" || parts[1] == "collection" {
		// Map component release collections to its parent product release collection
		rel, err := h.svc.findReleaseByComponentReleaseUUID(r.Context(), releaseUUID)
		if err != nil || rel == nil {
			writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "component release not found")
			return
		}
		col, err := h.svc.GetCollection(r.Context(), rel.SBOMID.String(), 1)
		if err != nil {
			writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
			return
		}
		col.BelongsTo = BelongsToComponentRelease

		if parts[1] == "collections" {
			writeJSON(w, http.StatusOK, PaginatedResponse[Collection]{
				HasNext: false,
				Results: []Collection{*col},
			})
			return
		}
		writeJSON(w, http.StatusOK, col)
		return
	}

	writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "unknown component release sub-resource")
}

// Route under /artifact/...
func (h *Handler) handleArtifactRoute(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	if len(parts) < 2 {
		writeTEAError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid artifact path")
		return
	}

	artifactUUID := parts[0]
	versionStr := parts[1]
	version := 1
	isLatest := versionStr == "latest"
	if !isLatest {
		if v, err := strconv.Atoi(versionStr); err == nil && v > 0 {
			version = v
		}
	}

	isDownload := len(parts) >= 3 && parts[2] == "download"
	isSignature := len(parts) >= 3 && parts[2] == "signature"

	if isSignature {
		writeTEAError(w, http.StatusNotFound, ErrCodeSignatureNotFound, "signature not found for this artifact format")
		return
	}

	if isDownload {
		h.downloadArtifact(w, r, artifactUUID, version, isLatest)
		return
	}

	// GET /artifact/{uuid}/latest or /artifact/{uuid}/{version}
	art, err := h.svc.GetArtifact(r.Context(), artifactUUID, version)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "artifact not found")
			return
		}
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, art)
}

func (h *Handler) downloadArtifact(w http.ResponseWriter, r *http.Request, artifactUUID string, version int, isLatest bool) {
	data, err := h.svc.GetArtifactData(r.Context(), artifactUUID, version)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeTEAError(w, http.StatusNotFound, ErrCodeObjectUnknown, "artifact not found")
			return
		}
		writeTEAError(w, http.StatusInternalServerError, ErrCodeObjectUnknown, err.Error())
		return
	}
	defer data.Body.Close()

	// Handle conditional validation via ETag / If-None-Match
	etag := fmt.Sprintf(`"%s"`, data.SHA256Hash)
	if match := r.Header.Get("If-None-Match"); match != "" {
		if match == etag || match == data.SHA256Hash || match == "*" {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	// Headers required by TEA spec
	w.Header().Set("Content-Type", data.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, data.Filename))
	w.Header().Set("ETag", etag)
	w.Header().Set("Vary", "Accept, Accept-Encoding")

	// Calculate Repr-Digest (RFC 9530): sha-256=:<base64>:
	if rawHash, err := hex.DecodeString(data.SHA256Hash); err == nil && len(rawHash) == 32 {
		w.Header().Set("Repr-Digest", fmt.Sprintf("sha-256=:%s:", base64.StdEncoding.EncodeToString(rawHash)))
	}

	if isLatest {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Location", fmt.Sprintf("%s/artifact/%s/%d/download", h.effectiveBaseURL(r), artifactUUID, version))
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	if data.SizeBytes > 0 {
		w.Header().Set("Content-Length", strconv.FormatUint(data.SizeBytes, 10))
	}

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, data.Body)
}

func parsePagination(r *http.Request) (page, pageSize uint64) {
	page = 1
	pageSize = 50

	q := r.URL.Query()
	if ps := q.Get("pageSize"); ps != "" {
		if v, err := strconv.ParseUint(ps, 10, 64); err == nil && v > 0 {
			if v > 1000 {
				v = 1000
			}
			pageSize = v
		}
	}
	if pt := q.Get("pageToken"); pt != "" {
		if v, err := strconv.ParseUint(pt, 10, 64); err == nil && v > 0 {
			page = v
		}
	}
	return page, pageSize
}

func writeJSON(w http.ResponseWriter, status int, val any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(val)
}

func writeTEAError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:   code,
		Message: msg,
	})
}
