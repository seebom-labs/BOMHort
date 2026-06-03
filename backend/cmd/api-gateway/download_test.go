package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDownloadEndpoint_InvalidUUID(t *testing.T) {
	// The download endpoint should reject invalid UUIDs.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/sboms/{id}/download", func(w http.ResponseWriter, r *http.Request) {
		sbomID := r.PathValue("id")
		if !isValidUUID(sbomID) {
			writeError(w, http.StatusBadRequest, "Invalid SBOM ID")
			return
		}
		// Would proceed to lookup if valid
		writeError(w, http.StatusNotFound, "SBOM not found")
	})

	tests := []struct {
		name   string
		id     string
		expect int
	}{
		{"invalid chars", "not-a-uuid!", http.StatusBadRequest},
		{"too short", "12345", http.StatusBadRequest},
		{"path traversal", "..%2F..%2Fetc%2Fpasswd", http.StatusBadRequest},
		{"valid uuid", "550e8400-e29b-41d4-a716-446655440000", http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+tc.id+"/download", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expect {
				t.Errorf("expected %d for id=%q, got %d", tc.expect, tc.id, rec.Code)
			}
		})
	}
}

func TestDownloadEndpoint_ContentDisposition(t *testing.T) {
	// Verify that filepath.Base correctly extracts filenames.
	tests := []struct {
		sourceFile string
		expected   string
	}{
		{"s3://bucket/path/to/my-sbom.spdx.json", "my-sbom.spdx.json"},
		{"relative/path/file.spdx.json", "file.spdx.json"},
		{"simple.spdx.json", "simple.spdx.json"},
	}

	for _, tc := range tests {
		t.Run(tc.sourceFile, func(t *testing.T) {
			// filepath.Base extracts the last element of a path.
			// For S3 URIs we use the path part after parsing.
			result := extractFilename(tc.sourceFile)
			if result != tc.expected {
				t.Errorf("extractFilename(%q) = %q, want %q", tc.sourceFile, result, tc.expected)
			}
		})
	}
}

// extractFilename mirrors the filename extraction logic from the download handler.
func extractFilename(sourceFile string) string {
	// For S3 URIs, strip the scheme+bucket prefix
	if len(sourceFile) > 5 && sourceFile[:5] == "s3://" {
		rest := sourceFile[5:]
		// Find first slash after bucket name
		for i := 0; i < len(rest); i++ {
			if rest[i] == '/' {
				sourceFile = rest[i+1:]
				break
			}
		}
	}
	// Get last path segment
	for i := len(sourceFile) - 1; i >= 0; i-- {
		if sourceFile[i] == '/' {
			return sourceFile[i+1:]
		}
	}
	return sourceFile
}

