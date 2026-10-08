package github

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// newRateLimitedResolver returns a resolver whose API answers every request
// with the given rate-limit response and counts the requests it saw.
func newRateLimitedResolver(t *testing.T, status int, headers map[string]string) (*Resolver, *int32) {
	t.Helper()
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	t.Cleanup(server.Close)

	r := NewResolver("")
	r.apiBase = server.URL
	r.httpClient = server.Client()
	r.limiter = newTokenBucket(1000, 100)
	return r, &hits
}

func TestRateLimit_ReturnsErrorWithoutSleepingOrCaching(t *testing.T) {
	reset := time.Now().Add(45 * time.Minute).Unix()
	r, hits := newRateLimitedResolver(t, http.StatusForbidden, map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     strconv.FormatInt(reset, 10),
	})

	start := time.Now()
	meta, err := r.ResolveWithMetadataErr(context.Background(), "pkg:golang/github.com/google/licenseclassifier/v2@v2.0.0")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if meta != nil {
		t.Errorf("meta = %+v, want nil", meta)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("resolver slept %v on a rate limit; it must return immediately", time.Since(start))
	}

	// Nothing may be cached: the repo was never looked up.
	if _, found := r.metadataCache.Load("google/licenseclassifier"); found {
		t.Error("metadata cache holds an entry for a rate-limited lookup")
	}
	if _, found := r.licenseCache.Load("google/licenseclassifier"); found {
		t.Error("license cache holds an entry for a rate-limited lookup")
	}
	if entries := r.MetadataCacheEntries(); len(entries) != 0 {
		t.Errorf("MetadataCacheEntries() = %d entries, want 0 (nothing to persist)", len(entries))
	}

	// The reset time comes from the header (plus a one second margin).
	until := r.RateLimitResetAt()
	if want := time.Unix(reset, 0).Add(time.Second); !until.Equal(want) {
		t.Errorf("RateLimitResetAt() = %s, want %s", until, want)
	}

	// Subsequent lookups short-circuit without hitting GitHub again.
	before := atomic.LoadInt32(hits)
	if _, err := r.ResolveErr(context.Background(), "pkg:golang/github.com/spf13/cobra@v1.8.0"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("second lookup err = %v, want ErrRateLimited", err)
	}
	if _, err := r.ResolveWithMetadataErr(context.Background(), "pkg:golang/github.com/spf13/viper@v1.18.0"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("third lookup err = %v, want ErrRateLimited", err)
	}
	if after := atomic.LoadInt32(hits); after != before {
		t.Errorf("rate-limited resolver made %d more requests, want 0", after-before)
	}

	// The error-swallowing wrappers stay usable for callers that only want a best effort.
	if got := r.Resolve(context.Background(), "pkg:golang/github.com/spf13/cobra@v1.8.0"); got != "" {
		t.Errorf("Resolve() = %q during rate limit, want empty", got)
	}
	if got := r.ResolveWithMetadata(context.Background(), "pkg:golang/github.com/spf13/cobra@v1.8.0"); got != nil {
		t.Errorf("ResolveWithMetadata() = %+v during rate limit, want nil", got)
	}
}

func TestRateLimit_ExpiryAllowsRequestsAgain(t *testing.T) {
	r, hits := newRateLimitedResolver(t, http.StatusTooManyRequests, map[string]string{
		"Retry-After": "1",
	})

	if _, err := r.ResolveErr(context.Background(), "pkg:golang/github.com/spf13/cobra@v1.8.0"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if until := r.RateLimitResetAt(); until.IsZero() || time.Until(until) > 2*time.Second {
		t.Fatalf("RateLimitResetAt() = %s, want ~1s from now (Retry-After)", until)
	}

	// Simulate the reset having passed.
	r.mu.Lock()
	r.rateLimitedUntil = time.Now().Add(-time.Second)
	r.mu.Unlock()
	if !r.RateLimitResetAt().IsZero() {
		t.Fatal("RateLimitResetAt() should be zero once the reset has passed")
	}

	before := atomic.LoadInt32(hits)
	_, _ = r.ResolveErr(context.Background(), "pkg:golang/github.com/spf13/cobra@v1.8.0")
	if after := atomic.LoadInt32(hits); after != before+1 {
		t.Errorf("after reset the resolver made %d requests, want 1", after-before)
	}
}

func TestRateLimit_FallbackWithoutHeaders(t *testing.T) {
	r, _ := newRateLimitedResolver(t, http.StatusTooManyRequests, nil)

	if _, err := r.ResolveErr(context.Background(), "pkg:golang/github.com/spf13/cobra@v1.8.0"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	until := r.RateLimitResetAt()
	if d := time.Until(until); d < rateLimitFallback-time.Minute || d > rateLimitFallback+time.Minute {
		t.Errorf("RateLimitResetAt() is %v away, want ~%v fallback", d.Round(time.Second), rateLimitFallback)
	}
}

func TestRateLimit_PlainForbiddenIsNotARateLimit(t *testing.T) {
	// A 403 without quota headers is an access problem (private repo, blocked
	// token). That is a real negative answer and must not stall the queue.
	r, _ := newRateLimitedResolver(t, http.StatusForbidden, nil)

	got, err := r.ResolveErr(context.Background(), "pkg:golang/github.com/acme/private@v1.0.0")
	if err != nil || got != "" {
		t.Fatalf("ResolveErr() = %q, %v; want empty, nil", got, err)
	}
	if !r.RateLimitResetAt().IsZero() {
		t.Error("plain 403 must not mark the resolver as rate-limited")
	}
	if _, found := r.licenseCache.Load("acme/private"); !found {
		t.Error("plain 403 should be cached as a negative result")
	}
}
