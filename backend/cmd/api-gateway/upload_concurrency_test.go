package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type blockingReader struct {
	ready chan struct{}
	done  chan struct{}
	data  *bytes.Reader
}

func (b *blockingReader) Read(p []byte) (n int, err error) {
	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	<-b.done
	return b.data.Read(p)
}

func TestUploadHandler_MaxConcurrentUploads(t *testing.T) {
	cfg := testUploadConfig(t)
	cfg.MaxConcurrentUploads = 1

	store := &fakeUploadStore{}
	h := localUploadHandler(cfg, store)

	ready := make(chan struct{})
	done := make(chan struct{})

	r1Body := &blockingReader{
		ready: ready,
		done:  done,
		data:  bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)),
	}

	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", r1Body)
	req1.Header.Set("X-Filename", "first.spdx.json")
	rec1 := httptest.NewRecorder()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.ServeHTTP(rec1, req1)
	}()

	// Wait until req1 has entered handler and is reading body
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for req1 to start reading")
	}

	// Now try second concurrent request
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
	req2.Header.Set("X-Filename", "second.spdx.json")
	rec2 := httptest.NewRecorder()

	h.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests, got %d (body: %s)", rec2.Code, rec2.Body.String())
	}
	if retryAfter := rec2.Header().Get("Retry-After"); retryAfter == "" {
		t.Error("expected Retry-After header on 429 response")
	}

	// Release first request so it can finish reading
	close(done)
	wg.Wait()
	if rec1.Code != http.StatusAccepted {
		t.Fatalf("expected first request to succeed with 202, got %d (body: %s)", rec1.Code, rec1.Body.String())
	}
}
