package main

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

	t.Run("replaces a control-only caller request ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Request-ID", "\x1b\x00")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Request-ID"); got == "" || got == "\x1b\x00" {
			t.Fatalf("expected a generated safe request ID, got %q", got)
		}
	})
}

func TestSanitizeLogParamRemovesControlsAndBoundsRunes(t *testing.T) {
	input := "a\x1b\x7f\x00\n" + strings.Repeat("é", 201)
	want := "a" + strings.Repeat("é", 199) + "..."
	if got := sanitizeLogParam(input); got != want {
		t.Fatalf("sanitizeLogParam result length/content mismatch: got %q", got)
	}
}

func TestAccessLogSanitizesEncodedPathAndProxyIP(t *testing.T) {
	var buf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOutput)

	h := loggingAndRequestIDMiddleware(okHandler())
	path := "/%1b%5b2J" + strings.Repeat("a", 250)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", strings.Repeat("9", 250))
	h.ServeHTTP(httptest.NewRecorder(), req)

	logged := buf.String()
	if strings.ContainsRune(logged, '\x1b') {
		t.Fatalf("access log contains a terminal escape: %q", logged)
	}
	if strings.Contains(logged, strings.Repeat("a", 201)) || strings.Contains(logged, strings.Repeat("9", 201)) {
		t.Fatalf("access log did not bound user-controlled fields: %q", logged)
	}
	if !strings.Contains(logged, "ip="+strings.Repeat("9", 200)+"...") {
		t.Fatalf("proxy-supplied IP was not sanitized and bounded: %q", logged)
	}
}

func TestRequestIDsReachConcurrentErrorLogs(t *testing.T) {
	var buf bytes.Buffer
	origOutput := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(origOutput)

	arrived := sync.WaitGroup{}
	arrived.Add(2)
	release := make(chan struct{})
	h := loggingAndRequestIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived.Done()
		<-release
		logRequestError(r, "ERROR: concurrent request", errors.New(r.Header.Get("X-Test-Error")))
		w.WriteHeader(http.StatusInternalServerError)
	}))

	var done sync.WaitGroup
	for _, tc := range []struct{ id, message string }{
		{"trace-a", "failure-a"}, {"trace-b", "failure-b"},
	} {
		tc := tc
		done.Add(1)
		go func() {
			defer done.Done()
			req := httptest.NewRequest(http.MethodGet, "/same-endpoint", nil)
			req.Header.Set("X-Request-ID", tc.id)
			req.Header.Set("X-Test-Error", tc.message)
			h.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	arrived.Wait()
	close(release)
	done.Wait()

	logged := buf.String()
	for _, want := range []string{
		"ERROR: concurrent request req_id=trace-a: failure-a",
		"ERROR: concurrent request req_id=trace-b: failure-b",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("missing correlated error log %q in %s", want, logged)
		}
	}
}
