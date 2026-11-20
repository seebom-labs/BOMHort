package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/seebom-labs/bomhort/backend/internal/claimlock"
)

type blockingReader struct {
	ready chan struct{}
	done  chan struct{}
	data  *bytes.Reader
}

func TestUploadHandler_StalledBodyReleasesSlotAndProgressingLargeUploadSucceeds(t *testing.T) {
	cfg := testUploadConfig(t)
	cfg.MaxConcurrentUploads = 1
	cfg.MaxUploadSizeMB = 1

	h := uploadHandler(uploadDeps{
		cfg:             cfg,
		store:           &fakeUploadStore{},
		imageDedupLock:  claimlock.LocalKeyed(),
		localWritable:   true,
		bodyReadTimeout: 300 * time.Millisecond,
	})
	server := httptest.NewServer(h)
	defer server.Close()

	type result struct {
		resp *http.Response
		err  error
	}
	client := server.Client()

	stalledBody, stalledWriter := io.Pipe()
	stalledReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/sboms/upload", stalledBody)
	if err != nil {
		t.Fatal(err)
	}
	stalledReq.Header.Set("X-Filename", "stalled.spdx.json")
	stalledResult := make(chan result, 1)
	go func() {
		resp, err := client.Do(stalledReq)
		stalledResult <- result{resp: resp, err: err}
	}()
	if _, err := stalledWriter.Write([]byte(`{"spdxVersion":"SPDX-2.3"`)); err != nil {
		t.Fatalf("write partial upload body: %v", err)
	}

	var stalled result
	select {
	case stalled = <-stalledResult:
	case <-time.After(3 * time.Second):
		_ = stalledWriter.Close()
		t.Fatal("stalled upload did not time out and release its response")
	}
	_ = stalledWriter.Close()
	if stalled.err != nil {
		t.Fatalf("stalled upload request: %v", stalled.err)
	}
	defer stalled.resp.Body.Close()
	if stalled.resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("stalled upload status = %d, want %d", stalled.resp.StatusCode, http.StatusInternalServerError)
	}

	// A request that keeps making progress may exceed the idle timeout in total
	// duration. This 512 KiB upload is sent in paced chunks and should succeed.
	largeBody, largeWriter := io.Pipe()
	largeReq, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/sboms/upload", largeBody)
	if err != nil {
		t.Fatal(err)
	}
	largeReq.Header.Set("X-Filename", "large.spdx.json")
	largeResult := make(chan result, 1)
	go func() {
		resp, err := client.Do(largeReq)
		largeResult <- result{resp: resp, err: err}
	}()
	if _, err := largeWriter.Write([]byte(`{"spdxVersion":"SPDX-2.3"}`)); err != nil {
		t.Fatalf("write large upload prefix: %v", err)
	}
	chunk := []byte(strings.Repeat(" ", 8*1024))
	for i := 0; i < 64; i++ {
		if _, err := largeWriter.Write(chunk); err != nil {
			t.Fatalf("write large upload chunk %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = largeWriter.Close()

	select {
	case large := <-largeResult:
		if large.err != nil {
			t.Fatalf("large upload request: %v", large.err)
		}
		defer large.resp.Body.Close()
		if large.resp.StatusCode != http.StatusAccepted {
			body, _ := io.ReadAll(large.resp.Body)
			t.Fatalf("progressing large upload status = %d, want %d: %s", large.resp.StatusCode, http.StatusAccepted, body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("progressing large upload exceeded test deadline")
	}
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
