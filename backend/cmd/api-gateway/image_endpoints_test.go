package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/imagedigest"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

func TestImageEndpoints_Validation(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/images/{digest}", func(w http.ResponseWriter, r *http.Request) {
		digest := imagedigest.NormalizeDigest(r.PathValue("digest"))
		if !imagedigest.IsValidDigest(digest) {
			writeError(w, http.StatusBadRequest, "Invalid image digest: must be algorithm:hex (e.g. sha256:...)")
			return
		}
		if digest == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			writeJSON(w, http.StatusOK, dto.ImageDetail{
				ImageDigest: digest,
				ImageRef:    "app:v1",
				TotalSBOMs:  1,
			})
			return
		}
		writeError(w, http.StatusNotFound, "Image not found")
	})

	mux.HandleFunc("HEAD /api/v1/images/{digest}", func(w http.ResponseWriter, r *http.Request) {
		digest := imagedigest.NormalizeDigest(r.PathValue("digest"))
		if !imagedigest.IsValidDigest(digest) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if digest == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	mux.HandleFunc("HEAD /api/v1/sboms", func(w http.ResponseWriter, r *http.Request) {
		digest := imagedigest.NormalizeDigest(r.URL.Query().Get("digest"))
		if digest != "" {
			if digest == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	t.Run("GET_invalid_digest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/images/invalid", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400", rec.Code)
		}
	})

	t.Run("GET_not_found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/images/sha256:0000000000000000000000000000000000000000000000000000000000000000", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", rec.Code)
		}
	})

	t.Run("GET_success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/images/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rec.Code)
		}
	})

	t.Run("HEAD_invalid_digest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/images/not-a-digest", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("got %d, want 400", rec.Code)
		}
	})

	t.Run("HEAD_image_exists", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/images/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rec.Code)
		}
	})

	t.Run("HEAD_image_not_found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/images/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("got %d, want 404", rec.Code)
		}
	})

	t.Run("HEAD_sboms_with_digest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/sboms?digest=sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("got %d, want 200", rec.Code)
		}
	})
}
