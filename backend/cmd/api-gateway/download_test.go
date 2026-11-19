package main

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/docstore"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
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

func TestDownloadEndpoint_LocalSBOMPathContainment(t *testing.T) {
	cfg := &config.Config{
		SBOMDir: t.TempDir(),
	}

	for _, bad := range []string{
		"../../etc/passwd",
		"pushed/../../etc/passwd",
		"/etc/passwd",
		"..",
		"",
	} {
		if _, err := cfg.LocalSBOMPath(bad); err == nil {
			t.Errorf("cfg.LocalSBOMPath(%q) should fail with path containment error", bad)
		}
	}

	// Valid relative paths, dot-prefixed names, and space-containing names must succeed
	for _, good := range []string{
		"pushed/sbom.json",
		"..dots.spdx.json",
		" lead.spdx.json",
	} {
		if _, err := cfg.LocalSBOMPath(good); err != nil {
			t.Errorf("cfg.LocalSBOMPath(%q) unexpected error: %v", good, err)
		}
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
			name:     "dot-prefixed filename allowed",
			base:     baseDir,
			source:   "..dots.spdx.json",
			wantPath: "/var/sboms/..dots.spdx.json",
		},
		{
			name:     "space-named file allowed",
			base:     baseDir,
			source:   " lead.spdx.json",
			wantPath: "/var/sboms/ lead.spdx.json",
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
			wantErrMsg: "invalid source file path",
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

type mockStoredDocQuerier struct {
	doc *models.StoredDocument
	err error
}

func (m *mockStoredDocQuerier) QueryStoredDocument(_ context.Context, _ string) (*models.StoredDocument, error) {
	return m.doc, m.err
}

type mockDocStore struct {
	payload []byte
}

func (m *mockDocStore) Backend() string { return "mock" }
func (m *mockDocStore) Put(context.Context, string, []byte) (docstore.PutResult, error) {
	return docstore.PutResult{}, nil
}
func (m *mockDocStore) Get(_ context.Context, _ string) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.payload)), nil
}
func (m *mockDocStore) GetEncoded(_ context.Context, _ string) (io.ReadCloser, string, error) {
	return io.NopCloser(bytes.NewReader(m.payload)), docstore.EncodingGzip, nil
}
func (m *mockDocStore) Delete(context.Context, string) error { return nil }

func TestServeStoredOriginal_ContentDispositionFormatted(t *testing.T) {
	filenames := []string{
		`x"; filename="evil.exe.spdx.json`,
		"über-service.spdx.json",
		"foo\r\nHeader: injected.json",
		"foo\x1b[31mbar.json",
		"simple.spdx.json",
	}

	for _, filename := range filenames {
		t.Run(filename, func(t *testing.T) {
			testUUID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
			sbomID := testUUID.String()
			querier := &mockStoredDocQuerier{
				doc: &models.StoredDocument{
					SBOMID:          testUUID,
					SourceFile:      filename,
					StorageRef:      "fs:sha256:abcd",
					ContentType:     "application/json",
					StoredSizeBytes: 42,
					SizeBytes:       42,
				},
			}
			store := &mockDocStore{payload: []byte(`{"spdxVersion":"SPDX-2.3"}`)}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/sboms/"+sbomID+"/download", nil)
			rec := httptest.NewRecorder()

			served := serveStoredOriginal(rec, req, querier, store, sbomID, filename)
			if !served {
				t.Fatalf("serveStoredOriginal returned false, want true")
			}

			cd := rec.Header().Get("Content-Disposition")
			if strings.ContainsAny(cd, "\r\n\x1b") {
				t.Fatalf("Content-Disposition contains raw control character: %q", cd)
			}

			mediaType, params, err := mime.ParseMediaType(cd)
			if err != nil {
				t.Fatalf("mime.ParseMediaType(%q) failed: %v", cd, err)
			}
			if mediaType != "attachment" {
				t.Errorf("mediaType = %q, want attachment", mediaType)
			}
			if params["filename"] != filename {
				t.Errorf("parsed filename = %q, want %q (raw: %q)", params["filename"], filename, cd)
			}
		})
	}
}

func TestServeLocalDownload_ContentDispositionFormatted(t *testing.T) {
	filenames := []string{
		`x"; filename="evil.exe.spdx.json`,
		"über-service.spdx.json",
		"simple.spdx.json",
	}

	for _, filename := range filenames {
		t.Run(filename, func(t *testing.T) {
			dir := t.TempDir()
			filePath := filepath.Join(dir, filename)
			if err := os.WriteFile(filePath, []byte(`{"spdxVersion":"SPDX-2.3"}`), 0644); err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}

			cfg := &config.Config{SBOMDir: dir}
			sbomID := "11111111-2222-3333-4444-555555555555"

			rec := httptest.NewRecorder()
			served := serveLocalDownload(rec, cfg, sbomID, filename)
			if !served {
				t.Fatalf("serveLocalDownload returned false, want true")
			}

			cd := rec.Header().Get("Content-Disposition")
			mediaType, params, err := mime.ParseMediaType(cd)
			if err != nil {
				t.Fatalf("mime.ParseMediaType(%q) failed: %v", cd, err)
			}
			if mediaType != "attachment" {
				t.Errorf("mediaType = %q, want attachment", mediaType)
			}
			if params["filename"] != filename {
				t.Errorf("parsed filename = %q, want %q (raw: %q)", params["filename"], filename, cd)
			}
		})
	}

	t.Run("path traversal rejected", func(t *testing.T) {
		dir := t.TempDir()
		cfg := &config.Config{SBOMDir: dir}
		sbomID := "11111111-2222-3333-4444-555555555555"
		rec := httptest.NewRecorder()
		if served := serveLocalDownload(rec, cfg, sbomID, "../../etc/passwd"); served {
			t.Errorf("serveLocalDownload with traversal path returned true, want false")
		}
	})
}

func TestTEAStoreAdapter_ReadSourceBytes_PathContainment(t *testing.T) {
	dir := t.TempDir()
	adapter := &teaStoreAdapter{
		sbomDir: dir,
	}

	// Hostile traversal must be rejected
	_, err := adapter.readSourceBytes(context.Background(), "../../etc/passwd")
	if err == nil {
		t.Fatalf("readSourceBytes with traversal path succeeded, want error")
	}
	if !strings.Contains(err.Error(), "invalid local source file path") {
		t.Errorf("expected 'invalid local source file path' error, got: %v", err)
	}

	// Valid relative file must be read successfully
	validFile := "valid.spdx.json"
	wantContent := []byte(`{"spdxVersion":"SPDX-2.3"}`)
	if err := os.WriteFile(filepath.Join(dir, validFile), wantContent, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	got, err := adapter.readSourceBytes(context.Background(), validFile)
	if err != nil {
		t.Fatalf("readSourceBytes(%q) unexpected error: %v", validFile, err)
	}
	if !bytes.Equal(got, wantContent) {
		t.Errorf("readSourceBytes content mismatch: got %q, want %q", got, wantContent)
	}
}
