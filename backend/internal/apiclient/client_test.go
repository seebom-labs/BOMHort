package apiclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, h http.Handler, opts Options) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if opts.BaseURL == "" {
		opts.BaseURL = srv.URL
	}
	opts.HTTPClient = srv.Client()
	c, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, srv
}

func TestNewRejectsUnusableBaseURL(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"no scheme":    "bomhort-api:8080",
		"wrong scheme": "ftp://bomhort/api",
		"no host":      "http://",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Options{BaseURL: raw}); err == nil {
				t.Fatalf("New(%q) = nil error, want error", raw)
			}
		})
	}
}

// Operators copy the URL out of a browser tab, which includes /api/v1. Without
// normalisation every request would go to /api/v1/api/v1/... and 404, which
// looks like an empty instance rather than a configuration mistake.
func TestNewNormalizesBaseURL(t *testing.T) {
	for _, raw := range []string{
		"http://bomhort:8080",
		"http://bomhort:8080/",
		"http://bomhort:8080/api/v1",
		"http://bomhort:8080/api/v1/",
	} {
		c, err := New(Options{BaseURL: raw})
		if err != nil {
			t.Fatalf("New(%q): %v", raw, err)
		}
		if got := c.BaseURL(); got != "http://bomhort:8080" {
			t.Errorf("New(%q).BaseURL() = %q, want http://bomhort:8080", raw, got)
		}
	}
}

func TestGetSendsCredentialsAndDecodes(t *testing.T) {
	var gotAuth, gotKey, gotPath, gotQuery, gotAccept string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-API-Key")
		gotAccept = r.Header.Get("Accept")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[{"project_name":"payment-service","sbom_count":3}],"total":1,"page":2,"page_size":10}`))
	}), Options{APIKey: "key-123", ServiceToken: "tok-abc"})

	resp, err := c.ListProjects(context.Background(), 2, 10, "pay", "sandbox")
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}

	if gotAuth != "Bearer tok-abc" {
		t.Errorf("Authorization = %q, want Bearer tok-abc", gotAuth)
	}
	if gotKey != "key-123" {
		t.Errorf("X-API-Key = %q, want key-123", gotKey)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
	if gotPath != "/api/v1/projects" {
		t.Errorf("path = %q, want /api/v1/projects", gotPath)
	}
	if gotQuery != "page=2&page_size=10&search=pay&tag=sandbox" {
		t.Errorf("query = %q", gotQuery)
	}
	if resp.Total != 1 || len(resp.Data) != 1 || resp.Data[0].ProjectName != "payment-service" {
		t.Errorf("decoded response = %+v", resp)
	}
}

// Zero page/page_size must not be sent at all: the API's defaults are part of
// the contract, and pinning them here would freeze them a second time.
func TestPagingZeroValuesAreOmitted(t *testing.T) {
	var gotQuery string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[],"total":0,"page":1,"page_size":50}`))
	}), Options{})

	if _, err := c.ListProjects(context.Background(), 0, 0, "", ""); err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if gotQuery != "" {
		t.Errorf("query = %q, want empty", gotQuery)
	}
}

func TestGetProjectEscapesSlashInName(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// r.URL.Path is already decoded; EscapedPath shows what went on the wire.
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"project_name":"cncf/bomhort"}`))
	}), Options{})

	detail, err := c.GetProject(context.Background(), "cncf/bomhort")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if gotPath != "/api/v1/projects/cncf%2Fbomhort" {
		t.Errorf("escaped path = %q, want /api/v1/projects/cncf%%2Fbomhort", gotPath)
	}
	if detail.ProjectName != "cncf/bomhort" {
		t.Errorf("project_name = %q", detail.ProjectName)
	}
}

func TestStatusErrorCarriesNotFound(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Project not found"}`))
	}), Options{})

	_, err := c.GetProject(context.Background(), "ghost")
	if err == nil {
		t.Fatal("GetProject: want error, got nil")
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *StatusError", err)
	}
	if !se.NotFound() {
		t.Errorf("NotFound() = false, want true (status %d)", se.StatusCode)
	}
	if se.Body == "" {
		t.Error("StatusError.Body is empty, want the upstream message")
	}
}

func TestServerErrorIsNotMistakenForNotFound(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), Options{})

	_, err := c.GetSBOMDetail(context.Background(), "11111111-1111-1111-1111-111111111111")
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *StatusError", err)
	}
	if se.NotFound() {
		t.Error("a 500 must not report NotFound()")
	}
}

func TestListProjectVulnerabilitiesDecodesBareArray(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/projects/payment-service/vulnerabilities" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[{"vuln_id":"CVE-2026-1","severity":"HIGH","vex_status":"not_affected"}]`))
	}), Options{})

	items, err := c.ListProjectVulnerabilities(context.Background(), "payment-service", "")
	if err != nil {
		t.Fatalf("ListProjectVulnerabilities: %v", err)
	}
	if len(items) != 1 || items[0].VulnID != "CVE-2026-1" || items[0].VEXStatus != "not_affected" {
		t.Errorf("decoded = %+v", items)
	}
}

func TestSearchPackagesSetsQuery(t *testing.T) {
	var gotQ string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQ = r.URL.Query().Get("q")
		_, _ = w.Write([]byte(`{"total_results":1,"items":[{"package_name":"log4j-core"}],"page":1,"page_size":25,"query":"log4j"}`))
	}), Options{})

	resp, err := c.SearchPackages(context.Background(), "log4j", 1, 25)
	if err != nil {
		t.Fatalf("SearchPackages: %v", err)
	}
	if gotQ != "log4j" {
		t.Errorf("q = %q, want log4j", gotQ)
	}
	if resp.TotalResults != 1 || len(resp.Items) != 1 {
		t.Errorf("decoded = %+v", resp)
	}
}

func TestHealthUsesRootPath(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}), Options{})

	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
	if gotPath != "/healthz" {
		t.Errorf("path = %q, want /healthz", gotPath)
	}
}

func TestContextCancellationIsPropagated(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}), Options{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListProjects(ctx, 1, 1, "", ""); err == nil {
		t.Fatal("want error from cancelled context, got nil")
	}
}

func TestGetImage(t *testing.T) {
	var gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"image_digest":"sha256:abc","image_ref":"app:v1","total_sboms":1,"sboms":[]}`))
	}), Options{})

	img, err := c.GetImage(context.Background(), "sha256:abc")
	if err != nil {
		t.Fatalf("GetImage: %v", err)
	}
	if gotPath != "/api/v1/images/sha256:abc" {
		t.Errorf("gotPath = %q", gotPath)
	}
	if img.ImageDigest != "sha256:abc" || img.ImageRef != "app:v1" || img.TotalSBOMs != 1 {
		t.Errorf("decoded = %+v", img)
	}
}

func TestCheckImage(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/images/sha256:exists" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}), Options{})

	exists, err := c.CheckImage(context.Background(), "sha256:exists")
	if err != nil || !exists {
		t.Errorf("CheckImage(exists) = %v, %v, want true, nil", exists, err)
	}

	missing, err := c.CheckImage(context.Background(), "sha256:missing")
	if err != nil || missing {
		t.Errorf("CheckImage(missing) = %v, %v, want false, nil", missing, err)
	}
}
