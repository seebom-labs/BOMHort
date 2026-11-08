package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// scanningClusterDoc holds the scanner conformance list. Its table is asserted
// against the upload handler so a third-party scanner can rely on it.
var scanningClusterDoc = filepath.Join("..", "..", "..", "docs", "content", "docs", "scanning-a-cluster", "_index.md")

type conformanceRow struct {
	name, sentAs, status string
}

// Statuses a row may carry; see the docs page for their meaning.
var conformanceStatuses = []string{"required", "recommended", "optional", "planned", "not-applicable"}

func readConformanceTable(t *testing.T) []conformanceRow {
	t.Helper()
	raw, err := os.ReadFile(scanningClusterDoc)
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	doc := string(raw)
	start, end := "<!-- scanner-conformance:start -->", "<!-- scanner-conformance:end -->"
	i, j := strings.Index(doc, start), strings.Index(doc, end)
	if i < 0 || j < i {
		t.Fatal("scanner conformance table: markers not found")
	}
	var rows []conformanceRow
	for _, line := range strings.Split(doc[i+len(start):j], "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for k, c := range cells {
			cells[k] = strings.Trim(strings.TrimSpace(c), "`")
		}
		if len(cells) < 3 {
			t.Fatalf("scanner conformance table: short row %q", line)
		}
		rows = append(rows, conformanceRow{name: cells[0], sentAs: cells[1], status: cells[2]})
	}
	if len(rows) < 3 {
		t.Fatal("scanner conformance table: no rows")
	}
	return rows[2:] // header and separator
}

// uploadHandlerInputs returns the query parameters and headers uploadHandler
// reads, taken from its source. Reading the source rather than probing the
// handler is what catches a parameter added without a docs row: an unknown
// parameter is silently ignored, so no request could tell it apart.
func uploadHandlerInputs(t *testing.T) (query, headers []string) {
	t.Helper()
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(raw)
	i := strings.Index(src, "\nfunc uploadHandler(")
	if i < 0 {
		t.Fatal("uploadHandler not found in main.go")
	}
	body := src[i+1:]
	if j := strings.Index(body, "\nfunc "); j >= 0 {
		body = body[:j]
	}

	collect := func(re string) []string {
		var out []string
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(body, -1) {
			if !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
		sort.Strings(out)
		return out
	}
	query = collect(`queryOverride\(r, "([A-Za-z_]+)"`)
	for _, q := range collect(`URL\.Query\(\)\.Get\("([A-Za-z_]+)"\)`) {
		if !slices.Contains(query, q) {
			query = append(query, q)
		}
	}
	sort.Strings(query)
	headers = collect(`Header\.Get\("([A-Za-z-]+)"\)`)
	if len(query) == 0 || len(headers) == 0 {
		t.Fatalf("found no inputs in uploadHandler (query %v, headers %v): has the source shape changed?", query, headers)
	}
	return query, headers
}

// conformanceSample is the value the behavioural check sends for an accepted
// row, and how to find it on the enqueued job. A new accepted row needs an
// entry here, which is the point: it forces a test that the value arrives.
var conformanceSample = map[string]struct {
	value string
	got   func(models.IngestionJob) string
}{
	// The stored name is "<uuid>-<X-Filename>".
	"X-Filename": {"0123abcd.spdx.json", func(j models.IngestionJob) string {
		return filepath.Base(j.SourceFile)[len("00000000-0000-0000-0000-000000000000-"):]
	}},
	"X-Source-Repo": {"https://github.com/example-org/payment-api", func(j models.IngestionJob) string { return j.SourceRepo }},
	"X-Source-Ref":  {"v1.4.2", func(j models.IngestionJob) string { return j.SourceRef }},
	"cluster":       {"prod-eu", func(j models.IngestionJob) string { return j.Cluster }},
	"namespace":     {"payments", func(j models.IngestionJob) string { return j.Namespace }},
	"project":       {"payment-api", func(j models.IngestionJob) string { return j.Project }},
	"parent":        {"checkout", func(j models.IngestionJob) string { return j.Parent }},
	"tags":          {"runtime", func(j models.IngestionJob) string { return strings.Join(j.Tags, ",") }},
}

// plannedSample is what a scanner sends for a planned row today. It must be
// ignored, never rejected, or a forward-compatible scanner breaks.
var plannedSample = map[string]string{
	"origin":        "cluster-scan",
	"image":         "ghcr.io/example-org/payment-api@sha256:" + strings.Repeat("ab", 32),
	"workload_kind": "Deployment",
	"workload_name": "payment-api",
	"workload_uid":  "3f6b1c2e-9a4d-4f7e-8b1a-2c5d6e7f8a9b",
}

// credentialSample is how a scanner presents a documented credential row,
// and which gateway setting issues the secret. The behavioural check sends it
// through the real authMiddleware, so a header the middleware stops accepting
// fails here instead of passing against a list kept next to the docs.
var credentialSample = map[string]struct {
	format  func(secret string) string
	fromKey bool // true: API_KEYS; false: SERVICE_TOKEN
}{
	"X-API-Key":       {func(s string) string { return s }, true},
	"X-Service-Token": {func(s string) string { return s }, false},
	"Authorization":   {func(s string) string { return "Bearer " + s }, false},
}

func TestDocsScannerConformanceInSync(t *testing.T) {
	rows := readConformanceTable(t)
	readQuery, readHeaders := uploadHandlerInputs(t)

	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.name] {
			t.Errorf("%s: listed twice", r.name)
		}
		seen[r.name] = true
		if !slices.Contains(conformanceStatuses, r.status) {
			t.Errorf("%s: unknown status %q (want one of %v)", r.name, r.status, conformanceStatuses)
		}
	}

	t.Run("every handler input is listed", func(t *testing.T) {
		for _, q := range readQuery {
			if !slices.ContainsFunc(rows, func(r conformanceRow) bool { return r.name == q && r.sentAs == "query" }) {
				t.Errorf("uploadHandler reads ?%s= but the conformance list has no query row for it", q)
			}
		}
		for _, h := range readHeaders {
			if !slices.ContainsFunc(rows, func(r conformanceRow) bool { return r.name == h && r.sentAs == "header" }) {
				t.Errorf("uploadHandler reads header %s but the conformance list has no header row for it", h)
			}
		}
	})

	t.Run("listed rows match the handler", func(t *testing.T) {
		for _, r := range rows {
			var read bool
			switch r.sentAs {
			case "query":
				read = slices.Contains(readQuery, r.name)
			case "header":
				read = slices.Contains(readHeaders, r.name)
			case "credential":
				// Acceptance is checked through authMiddleware below.
				if r.status != "required" {
					t.Errorf("%s: a credential is always required, docs say %q", r.name, r.status)
				}
				continue
			default:
				t.Errorf("%s: unknown transport %q (want query, header or credential)", r.name, r.sentAs)
				continue
			}
			switch {
			case r.status == "planned" && read:
				t.Errorf("%s: uploadHandler reads it now; update its conformance row from planned", r.name)
			case r.status != "planned" && !read:
				t.Errorf("%s: documented as %s but uploadHandler never reads it", r.name, r.status)
			}
		}
	})

	t.Run("credential rows authenticate through authMiddleware", func(t *testing.T) {
		const apiKey, serviceToken = "scanner-api-key", "scanner-service-token"
		var found bool
		for _, r := range rows {
			if r.sentAs != "credential" {
				continue
			}
			found = true
			sample, ok := credentialSample[r.name]
			if !ok {
				t.Errorf("%s: credential row without a sample in credentialSample", r.name)
				continue
			}
			secret := serviceToken
			if sample.fromKey {
				secret = apiKey
			}
			upload := func(value string) (int, int) {
				store := &fakeUploadStore{}
				h := authMiddleware(true, false, serviceToken, []string{apiKey}, localUploadHandler(testUploadConfig(t), store))
				req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
				req.Header.Set("X-Filename", conformanceSample["X-Filename"].value)
				if value != "" {
					req.Header.Set(r.name, value)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				return rec.Code, len(store.enqueuedJobs)
			}
			if code, jobs := upload(sample.format(secret)); code != http.StatusAccepted || jobs != 1 {
				t.Errorf("%s: documented credential got %d with %d jobs enqueued, want 202 and 1", r.name, code, jobs)
			}
			if code, jobs := upload(sample.format("wrong-secret")); code != http.StatusUnauthorized || jobs != 0 {
				t.Errorf("%s: wrong credential got %d with %d jobs enqueued, want 401 and 0", r.name, code, jobs)
			}
			if code, jobs := upload(""); code != http.StatusUnauthorized || jobs != 0 {
				t.Errorf("%s: no credential got %d with %d jobs enqueued, want 401 and 0", r.name, code, jobs)
			}
		}
		if !found {
			t.Error("the conformance list documents no credential row")
		}
	})

	t.Run("accepted rows reach the ingestion job", func(t *testing.T) {
		cfg := testUploadConfig(t)
		store := &fakeUploadStore{}
		h := localUploadHandler(cfg, store)

		q := url.Values{}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sboms/upload", bytes.NewReader([]byte(`{"spdxVersion":"SPDX-2.3"}`)))
		var checks []string
		for _, r := range rows {
			if r.status == "not-applicable" || r.sentAs == "credential" {
				continue
			}
			if r.status == "planned" {
				v, ok := plannedSample[r.name]
				if !ok {
					t.Errorf("%s: planned row without a sample in plannedSample", r.name)
					continue
				}
				q.Set(r.name, v)
				continue
			}
			s, ok := conformanceSample[r.name]
			if !ok {
				t.Errorf("%s: accepted row without a sample in conformanceSample", r.name)
				continue
			}
			if r.sentAs == "query" {
				q.Set(r.name, s.value)
			} else {
				req.Header.Set(r.name, s.value)
			}
			checks = append(checks, r.name)
		}
		req.URL.RawQuery = q.Encode()

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("conformant upload: got %d, want 202: %s", rec.Code, rec.Body.String())
		}
		if len(store.enqueuedJobs) != 1 {
			t.Fatalf("expected 1 enqueued job, got %d", len(store.enqueuedJobs))
		}
		job := store.enqueuedJobs[0]
		for _, name := range checks {
			s := conformanceSample[name]
			if got := s.got(job); got != s.value {
				t.Errorf("%s: job carries %q, want %q", name, got, s.value)
			}
		}
	})
}
