package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoggingAndRequestIDMiddleware(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOutput)

	handler := loggingAndRequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	t.Run("generates request ID when missing", func(t *testing.T) {
		buf.Reset()
		req := httptest.NewRequest(http.MethodGet, "/test/path", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		reqID := rec.Header().Get("X-Request-ID")
		if reqID == "" {
			t.Fatal("expected X-Request-ID header to be set")
		}
		if len(reqID) < 10 {
			t.Fatalf("expected valid UUID, got %q", reqID)
		}

		logStr := buf.String()
		if !strings.Contains(logStr, "ACCESS: GET /test/path status=200") {
			t.Fatalf("log missing access line: %s", logStr)
		}
		if !strings.Contains(logStr, "req_id="+reqID) {
			t.Fatalf("log missing req_id: %s", logStr)
		}
	})

	t.Run("preserves valid caller-provided request ID", func(t *testing.T) {
		buf.Reset()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
		req.Header.Set("X-Request-ID", "client-trace-12345")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		reqID := rec.Header().Get("X-Request-ID")
		if reqID != "client-trace-12345" {
			t.Fatalf("expected preserved X-Request-ID, got %q", reqID)
		}

		logStr := buf.String()
		if !strings.Contains(logStr, "req_id=client-trace-12345") {
			t.Fatalf("log missing preserved req_id: %s", logStr)
		}
	})

	t.Run("replaces oversized caller-provided request ID", func(t *testing.T) {
		buf.Reset()
		oversized := strings.Repeat("a", 70)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", oversized)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		reqID := rec.Header().Get("X-Request-ID")
		if reqID == oversized || len(reqID) > 64 {
			t.Fatalf("oversized request ID should have been replaced, got %q", reqID)
		}
	})
}
