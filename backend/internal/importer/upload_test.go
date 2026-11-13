package importer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClient_Upload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method != http.MethodPost || r.URL.Path != "/api/v1/sboms/upload":
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		case r.Header.Get("X-API-Key") != "secret" || r.Header.Get("X-Filename") != "app.cdx.json":
			t.Errorf("headers %v", r.Header)
		case r.URL.Query().Get("project") != "payments" || r.URL.Query().Get("tags") != "imported,team-a":
			t.Errorf("query %q", r.URL.RawQuery)
		case string(body) != `{"bomFormat":"CycloneDX"}`:
			t.Errorf("body %q", body)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending","job_id":"job-1","sha256_hash":"abc"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.URL+"/", "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Upload(context.Background(), Upload{
		FileName: "app.cdx.json", Data: []byte(`{"bomFormat":"CycloneDX"}`),
		Project: "payments", Tags: []string{"imported", "team-a"},
	})
	if err != nil || res.JobID != "job-1" || res.Duplicate() {
		t.Fatalf("Upload() = %+v, %v", res, err)
	}
}

func TestClient_UploadDuplicateAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			t.Errorf("empty project/tags must not be sent, got %q", r.URL.RawQuery)
		}
		switch r.Header.Get("X-Filename") {
		case "dup.json":
			_, _ = w.Write([]byte(`{"status":"duplicate","sha256_hash":"abc"}`))
		case "forbidden.json":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"Upload requires AUTH_ENABLED=true"}`))
		}
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}

	res, err := c.Upload(context.Background(), Upload{FileName: "dup.json", Data: []byte("{}")})
	if err != nil || !res.Duplicate() {
		t.Errorf("duplicate: %+v, %v", res, err)
	}
	_, err = c.Upload(context.Background(), Upload{FileName: "forbidden.json", Data: []byte("{}")})
	if err == nil || !strings.Contains(err.Error(), "Upload requires AUTH_ENABLED=true") {
		t.Errorf("403 error = %v, want the gateway's message", err)
	}
}

func TestClient_RetriesRateLimit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending","job_id":"job-1"}`))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var waited []time.Duration
	c.wait = func(_ context.Context, d time.Duration) error { waited = append(waited, d); return nil }

	if _, err := c.Upload(context.Background(), Upload{FileName: "a.json", Data: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 || len(waited) != 2 || waited[0] != 3*time.Second {
		t.Errorf("calls = %d, waited = %v", calls.Load(), waited)
	}

	// The retries are bounded.
	calls.Store(-100)
	if _, err := c.Upload(context.Background(), Upload{FileName: "a.json", Data: []byte("{}")}); err == nil {
		t.Error("a permanent 429 was not reported")
	}
}

// A redirect must not carry the API key to another host, so none is followed.
func TestClient_RefusesRedirects(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "" {
			leaked.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"pending","job_id":"job-1"}`))
	}))
	defer other.Close()

	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+uploadPath, code)
		}))
		c, err := NewClient(srv.URL, "secret", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Upload(context.Background(), Upload{FileName: "a.json", Data: []byte("{}")})
		if err == nil || !strings.Contains(err.Error(), "refusing to follow a redirect") {
			t.Errorf("%d: err = %v, want the redirect refused", code, err)
		}
		srv.Close()
	}
	if n := leaked.Load(); n != 0 {
		t.Errorf("the API key reached the redirect target %d times", n)
	}
}

func TestNewClient_Validates(t *testing.T) {
	for _, u := range []string{"", "bomhort.example.com", "ftp://host", "https://"} {
		if _, err := NewClient(u, "key", time.Second); err == nil {
			t.Errorf("NewClient(%q) accepted", u)
		}
	}
	if _, err := NewClient("https://bomhort.example.com", "", time.Second); err == nil {
		t.Error("NewClient without an API key accepted")
	}
}
