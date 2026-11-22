package vexsub

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestParseCSAF_ProductGroupsIDsAndUnknownFlag(t *testing.T) {
	const csafDoc = `{
		"document": {
			"csaf_version": "2.0",
			"category": "csaf_vex",
			"publisher": {"name": "Vendor Security"},
			"tracking": {"id": "VEX-GROUP-1", "current_release_date": "2026-05-10"}
		},
		"product_tree": {
			"full_product_names": [
				{
					"product_id": "P-1",
					"name": "curl-rhel8",
					"product_identification_helper": {"purl": "pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64"}
				},
				{
					"product_id": "P-2",
					"name": "openssl-rhel8",
					"product_identification_helper": {"purl": "pkg:rpm/redhat/openssl@1.1.1k?arch=x86_64"}
				}
			],
			"product_groups": [
				{"group_id": "G-RHEL8", "product_ids": ["P-1", "P-2"]}
			]
		},
		"vulnerabilities": [
			{
				"ids": [{"system_name": "Red Hat", "text": "CVE-2026-4444"}],
				"product_status": {"known_not_affected": ["P-1"]},
				"flags": [
					{"label": "inline_mitigations_already_exist", "group_ids": ["G-RHEL8"]}
				],
				"threats": [
					{"category": "impact", "details": "Mitigated by policy", "group_ids": ["G-RHEL8"]}
				]
			},
			{
				"cve": "CVE-2026-5555",
				"product_status": {"known_not_affected": ["P-2"]},
				"flags": [
					{"label": "vendor_custom_unrecognized_flag", "product_ids": ["P-2"]}
				]
			}
		]
	}`

	stmts, err := ParseCSAF(strings.NewReader(csafDoc), "https://vendor.example.com/csaf/vex.json")
	if err != nil {
		t.Fatalf("ParseCSAF failed: %v", err)
	}
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	if stmts[0].VulnID != "CVE-2026-4444" {
		t.Errorf("expected vuln ID from ids[] fallback, got %q", stmts[0].VulnID)
	}
	if stmts[0].Justification != models.VEXJustificationInlineMitigationsExist {
		t.Errorf("expected inline_mitigations_already_exist via group_ids, got %q", stmts[0].Justification)
	}
	if stmts[0].ImpactStatement != "Mitigated by policy" {
		t.Errorf("expected impact statement via group_ids, got %q", stmts[0].ImpactStatement)
	}

	if stmts[1].VulnID != "CVE-2026-5555" {
		t.Errorf("expected CVE-2026-5555, got %q", stmts[1].VulnID)
	}
	if stmts[1].Justification != "" {
		t.Errorf("unknown CSAF flag must produce empty justification instead of guessing, got %q", stmts[1].Justification)
	}
}

func TestFetchCSAFProvider_OASISURLAndSidecarFilter(t *testing.T) {
	shaFetched := false
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider-metadata.json":
			_, _ = w.Write([]byte(`{
				"distributions": [
					{
						"rolie": {
							"feeds": [
								{"summary": "VEX feed", "url": "` + srv.URL + `/rolie/vex.json"}
							]
						}
					}
				]
			}`))
		case "/rolie/vex.json":
			_, _ = w.Write([]byte(`{
				"feed": {
					"entry": [
						{
							"id": "adv-1",
							"content": {"type": "application/json", "src": "` + srv.URL + `/advisories/adv-1.json"},
							"link": [
								{"rel": "self", "href": "` + srv.URL + `/advisories/adv-1.json"},
								{"rel": "alternate", "href": "` + srv.URL + `/advisories/adv-1.json.sha256"}
							]
						}
					]
				}
			}`))
		case "/advisories/adv-1.json.sha256":
			shaFetched = true
			_, _ = w.Write([]byte("deadbeef"))
		case "/advisories/adv-1.json":
			_, _ = w.Write([]byte(`{
				"document": {"csaf_version": "2.0", "tracking": {"id": "ADV-1"}},
				"product_tree": {
					"full_product_names": [
						{"product_id": "P-1", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl@7.61.1-22.el8"}}
					]
				},
				"vulnerabilities": [
					{"cve": "CVE-2026-7777", "product_status": {"fixed": ["P-1"]}}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := FetchCSAFProvider(context.Background(), srv.Client(), srv.URL+"/provider-metadata.json", nil)
	if err != nil {
		t.Fatalf("FetchCSAFProvider failed: %v", err)
	}
	if shaFetched {
		t.Fatalf(".sha256 sidecar link must be skipped")
	}
	stmts := res.Statements
	if len(stmts) != 1 || stmts[0].VulnID != "CVE-2026-7777" || stmts[0].Status != models.VEXStatusFixed {
		t.Fatalf("unexpected statements: %+v", stmts)
	}
}

func TestFetchCSAFProvider_DirectoryChangesCSVAndHTTPError(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/provider-metadata.json":
			_, _ = w.Write([]byte(`{"distributions":[{"directory_url":"` + srv.URL + `/csaf/"}]}`))
		case "/csaf/changes.csv":
			_, _ = w.Write([]byte("\"2026/adv-2.json\",\"2026-05-01T00:00:00Z\"\n"))
		case "/csaf/2026/adv-2.json":
			_, _ = w.Write([]byte(`{
				"document": {"csaf_version": "2.0", "tracking": {"id": "ADV-2"}},
				"product_tree": {"full_product_names": [{"product_id": "P-1", "product_identification_helper": {"purl": "pkg:deb/debian/openssl@3.0.11"}}]},
				"vulnerabilities": [{"cve": "CVE-2026-8888", "product_status": {"known_not_affected": ["P-1"]}}]
			}`))
		case "/broken.json":
			http.Error(w, "internal error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := FetchCSAFProvider(context.Background(), srv.Client(), srv.URL+"/provider-metadata.json", nil)
	if err != nil {
		t.Fatalf("directory_url fallback failed: %v", err)
	}
	stmts := res.Statements
	if len(stmts) != 1 || stmts[0].VulnID != "CVE-2026-8888" {
		t.Fatalf("unexpected statements: %+v", stmts)
	}

	if _, err := FetchCSAFProvider(context.Background(), srv.Client(), srv.URL+"/broken.json", nil); err == nil {
		t.Fatalf("expected HTTP 500 error propagation, got nil")
	}
}

func TestFetchOpenVEXHub_IndexJSONFastPath(t *testing.T) {
	unmatchedProbed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			_, _ = w.Write([]byte(`{
				"packages": [
					{"id": "pkg:golang/github.com/gin-gonic/gin", "location": "pkg/golang/github.com/gin-gonic/gin/vex.openvex.json"},
					{"id": "pkg:golang/github.com/unrelated/lib", "location": "pkg/golang/github.com/unrelated/lib/vex.openvex.json"}
				]
			}`))
		case "/pkg/golang/github.com/gin-gonic/gin/vex.openvex.json":
			_, _ = w.Write([]byte(`{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id": "https://vexhub.example.com/gin",
				"statements": [
					{
						"vulnerability": {"name": "CVE-2026-1234"},
						"products": [{"@id": "pkg:golang/github.com/gin-gonic/gin"}],
						"status": "not_affected",
						"justification": "vulnerable_code_not_present"
					}
				]
			}`))
		case "/pkg/golang/github.com/unrelated/lib/vex.openvex.json":
			unmatchedProbed = true
			http.Error(w, "should not fetch unrelated index entries", http.StatusInternalServerError)
		default:
			unmatchedProbed = true
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	engine := &Engine{Client: srv.Client()}
	known := []string{"pkg:golang/github.com/gin-gonic/gin@v1.9.1"}
	res, err := engine.Pull(context.Background(), []config.VEXSourceConfig{
		{Type: SourceTypeOpenVEXHub, URL: srv.URL},
	}, known)
	if err != nil {
		t.Fatalf("Engine.Pull with hub index failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot")
	}
	stmts := res.Statements
	if unmatchedProbed {
		t.Fatalf("index.json fast path unexpectedly probed unrelated paths")
	}
	if len(stmts) != 1 {
		t.Fatalf("expected 1 bound statement, got %d", len(stmts))
	}
	if stmts[0].ProductPURL != known[0] {
		t.Errorf("expected versionless hub PURL to bind to concrete SBOM PURL %q, got %q", known[0], stmts[0].ProductPURL)
	}
}

func TestEnginePull_QualifierBindingAndPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csaf.json":
			_, _ = w.Write([]byte(`{
				"document": {"csaf_version": "2.0", "tracking": {"id": "CSAF-QUAL-1"}},
				"product_tree": {
					"full_product_names": [
						{"product_id": "P-1", "product_identification_helper": {"purl": "pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64"}}
					]
				},
				"vulnerabilities": [
					{"cve": "CVE-2026-3030", "product_status": {"known_not_affected": ["P-1"]}}
				]
			}`))
		case "/down":
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	engine := &Engine{Client: srv.Client()}
	known := []string{
		"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64&distro=rhel-8",
		"pkg:rpm/redhat/curl@7.61.1-22.el8?arch=aarch64&distro=rhel-8",
	}

	// Partial failure: one failing source + one working source still applies valid statements,
	// but Complete must be false so downstream reconciliation does not delete missing statements.
	pullRes, err := engine.Pull(context.Background(), []config.VEXSourceConfig{
		{Type: SourceTypeCSAFProvider, URL: srv.URL + "/down"},
		{Type: SourceTypeCSAFProvider, URL: srv.URL + "/csaf.json"},
	}, known)
	if err != nil {
		t.Fatalf("expected partial success when one source works, got err: %v", err)
	}
	if pullRes.Complete {
		t.Errorf("expected Complete == false when one source failed (/down), got true")
	}
	stmts := pullRes.Statements
	if len(stmts) != 1 {
		t.Fatalf("expected exactly 1 matched arch statement (x86_64 only), got %d: %+v", len(stmts), stmts)
	}
	if stmts[0].ProductPURL != known[0] {
		t.Errorf("expected bound PURL %q, got %q", known[0], stmts[0].ProductPURL)
	}

	// Total failure: when all configured sources fail, Pull returns an error.
	if _, err := engine.Pull(context.Background(), []config.VEXSourceConfig{
		{Type: SourceTypeCSAFProvider, URL: srv.URL + "/down"},
	}, known); err == nil {
		t.Fatalf("expected error when every configured source fails")
	}
}

func TestFetchOpenVEXHub_PartialDocumentFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			_, _ = w.Write([]byte(`{
				"packages": [
					{"id": "pkg:golang/pkg1@1.0.0", "location": "doc1.json"},
					{"id": "pkg:golang/pkg2@1.0.0", "location": "doc2.json"}
				]
			}`))
		case "/doc1.json":
			_, _ = w.Write([]byte(`{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id": "https://example.com/doc1",
				"statements": [
					{"vulnerability": {"name": "CVE-2026-0001"}, "products": [{"@id": "pkg:golang/pkg1@1.0.0"}], "status": "not_affected", "justification": "component_not_present"}
				]
			}`))
		case "/doc2.json":
			http.Error(w, "internal server error", http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	known := []string{"pkg:golang/pkg1@1.0.0", "pkg:golang/pkg2@1.0.0"}
	res, err := FetchOpenVEXHub(context.Background(), srv.Client(), srv.URL, known)
	if err != nil {
		t.Fatalf("expected partial fetch to succeed without fatal error, got %v", err)
	}
	if len(res.Statements) != 1 {
		t.Fatalf("expected 1 statement from reachable doc, got %d", len(res.Statements))
	}
	if res.Complete {
		t.Errorf("expected Complete == false on partial document failure, got true")
	}
}

func TestFetchOpenVEXHub_CappedAtLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.json":
			var pkgs []string
			for i := 0; i <= maxHubDocsPerSync+5; i++ {
				pkgs = append(pkgs, fmt.Sprintf(`{"id": "pkg:golang/pkg%d@1.0.0", "location": "doc%d.json"}`, i, i))
			}
			_, _ = w.Write([]byte(`{"packages": [` + strings.Join(pkgs, ",") + `]}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/doc") {
				_, _ = w.Write([]byte(`{
					"@context": "https://openvex.dev/ns/v0.2.0",
					"@id": "https://example.com/doc",
					"statements": []
				}`))
				return
			}
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := FetchOpenVEXHub(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil {
		t.Fatalf("FetchOpenVEXHub failed: %v", err)
	}
	if res.Complete {
		t.Errorf("expected Complete == false when hub exceeds maxHubDocsPerSync, got true")
	}
}
