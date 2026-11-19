package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestContentDispositionAttachment(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     string
	}{
		{
			name:     "plain ascii filename",
			filename: "bomhort-vulnerabilities-2026-10-14.csv",
			want:     `attachment; filename="bomhort-vulnerabilities-2026-10-14.csv"`,
		},
		{
			name:     "quotes are escaped",
			filename: `my"app.json`,
			want:     `attachment; filename="my\"app.json"`,
		},
		{
			name:     "backslashes are escaped",
			filename: `my\app.json`,
			want:     `attachment; filename="my\\app.json"`,
		},
		{
			name:     "crlf stripped to prevent header injection",
			filename: "foo\r\nHeader: injected.json",
			want:     `attachment; filename="fooHeader: injected.json"`,
		},
		{
			name:     "nul byte stripped",
			filename: "foo\x00bar.json",
			want:     `attachment; filename="foobar.json"`,
		},
		{
			name:     "empty filename defaults to download",
			filename: "",
			want:     `attachment; filename="download"`,
		},
		{
			name:     "utf-8 filename with rfc 5987 parameter",
			filename: "über-service.spdx.json",
			want:     `attachment; filename="_ber-service.spdx.json"; filename*=UTF-8''%C3%BCber-service.spdx.json`,
		},
		{
			name:     "spaces and special characters preserved in ascii",
			filename: "Project (v1.0) & Notes.json",
			want:     `attachment; filename="Project (v1.0) & Notes.json"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contentDispositionAttachment(tt.filename)
			if got != tt.want {
				t.Errorf("contentDispositionAttachment(%q) =\n  %q\nwant:\n  %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestSafeLocalSBOMPath(t *testing.T) {
	baseDir := "/var/sboms"

	tests := []struct {
		name       string
		base       string
		source     string
		wantPath   string
		wantErrMsg string
	}{
		{
			name:     "valid direct file",
			base:     baseDir,
			source:   "app.json",
			wantPath: "/var/sboms/app.json",
		},
		{
			name:     "valid nested file",
			base:     baseDir,
			source:   "cluster/prod/app.spdx.json",
			wantPath: "/var/sboms/cluster/prod/app.spdx.json",
		},
		{
			name:       "empty base directory rejected",
			base:       "",
			source:     "app.json",
			wantErrMsg: "local storage not configured",
		},
		{
			name:       "absolute path rejected",
			base:       baseDir,
			source:     "/etc/passwd",
			wantErrMsg: "invalid source file path",
		},
		{
			name:       "path traversal with dot-dot rejected",
			base:       baseDir,
			source:     "../../etc/passwd",
			wantErrMsg: "invalid source file path",
		},
		{
			name:       "embedded traversal rejected",
			base:       baseDir,
			source:     "cluster/../../etc/passwd",
			wantErrMsg: "invalid source file path",
		},
		{
			name:       "dot path rejected",
			base:       baseDir,
			source:     ".",
			wantErrMsg: "invalid source file path",
		},
		{
			name:       "empty source rejected",
			base:       baseDir,
			source:     "",
			wantErrMsg: "empty source file path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := safeLocalSBOMPath(tt.base, tt.source)
			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatalf("safeLocalSBOMPath(%q, %q) succeeded with %q, want error containing %q", tt.base, tt.source, path, tt.wantErrMsg)
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("safeLocalSBOMPath(%q, %q) error = %q, want containing %q", tt.base, tt.source, err.Error(), tt.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("safeLocalSBOMPath(%q, %q) unexpected error: %v", tt.base, tt.source, err)
			}
			if path != tt.wantPath {
				t.Errorf("safeLocalSBOMPath(%q, %q) = %q, want %q", tt.base, tt.source, path, tt.wantPath)
			}
		})
	}
}
