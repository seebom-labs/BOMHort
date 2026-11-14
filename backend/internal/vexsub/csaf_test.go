package vexsub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

const sampleCSAFJSON = `{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "title": "Red Hat Security Advisory",
    "publisher": {
      "category": "vendor",
      "name": "Red Hat Product Security",
      "namespace": "https://www.redhat.com"
    },
    "tracking": {
      "id": "RHSA-2024:9999",
      "status": "final",
      "version": "1.0",
      "current_release_date": "2024-05-10T12:00:00Z"
    }
  },
  "product_tree": {
    "full_product_names": [
      {
        "name": "curl-7.61.1-22.el8.x86_64.rpm",
        "product_id": "CSAFPID-0001",
        "product_identification_helper": {
          "purl": "pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64"
        }
      }
    ],
    "branches": [
      {
        "name": "OpenSSL",
        "category": "vendor",
        "branches": [
          {
            "name": "openssl-1.1.1k.rpm",
            "category": "product_name",
            "product": {
              "name": "openssl-1.1.1k",
              "product_id": "CSAFPID-0002",
              "product_identification_helper": {
                "purl": "pkg:rpm/redhat/openssl@1.1.1k"
              }
            }
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-45338",
      "product_status": {
        "known_not_affected": ["CSAFPID-0001"],
        "known_affected": ["CSAFPID-0002"]
      },
      "flags": [
        {
          "label": "vulnerable_code_not_in_execute_path",
          "product_ids": ["CSAFPID-0001"]
        }
      ],
      "threats": [
        {
          "category": "impact",
          "details": "Vulnerable code branch is never reached in the rpm build configuration",
          "product_ids": ["CSAFPID-0001"]
        }
      ]
    }
  ]
}`

func TestParseCSAF(t *testing.T) {
	stmts, err := ParseCSAF(strings.NewReader(sampleCSAFJSON), "https://access.redhat.com/csaf/RHSA-2024:9999.json")
	if err != nil {
		t.Fatalf("ParseCSAF failed: %v", err)
	}

	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(stmts))
	}

	// 1. Check known_not_affected statement for curl rpm
	s1 := stmts[0]
	if s1.ProductPURL != "pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64" {
		t.Errorf("expected curl purl, got %s", s1.ProductPURL)
	}
	if s1.VulnID != "CVE-2024-45338" {
		t.Errorf("expected CVE-2024-45338, got %s", s1.VulnID)
	}
	if s1.Status != models.VEXStatusNotAffected {
		t.Errorf("expected not_affected, got %s", s1.Status)
	}
	if s1.Justification != models.VEXJustificationVulnerableCodeNotInExecutePath {
		t.Errorf("expected vulnerable_code_not_in_execute_path, got %s", s1.Justification)
	}
	if s1.Role != RoleUpstream {
		t.Errorf("expected role upstream, got %s", s1.Role)
	}
	if s1.Author != "Red Hat Product Security" {
		t.Errorf("expected Red Hat Product Security, got %s", s1.Author)
	}
	if s1.Tooling != "https://access.redhat.com/csaf/RHSA-2024:9999.json" {
		t.Errorf("expected tooling url, got %s", s1.Tooling)
	}

	// 2. Check known_affected statement for openssl rpm from nested branch
	s2 := stmts[1]
	if s2.ProductPURL != "pkg:rpm/redhat/openssl@1.1.1k" {
		t.Errorf("expected openssl purl, got %s", s2.ProductPURL)
	}
	if s2.Status != models.VEXStatusAffected {
		t.Errorf("expected affected, got %s", s2.Status)
	}
	if s2.Role != RoleUpstream {
		t.Errorf("expected role upstream, got %s", s2.Role)
	}
}

func TestFetchCSAFProvider_ROLIEFeed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/csaf/provider-metadata.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"canonical_url": "/.well-known/csaf/provider-metadata.json",
				"distributions": [
					{
						"directory_url": "/csaf/",
						"rolie": {
							"feeds": [
								{ "feed_url": "/csaf/rolie.json", "format": "JSON" }
							]
						}
					}
				]
			}`))
		case "/csaf/rolie.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{
				"feed": {
					"id": "csaf-feed",
					"title": "CSAF Feed",
					"entry": [
						{
							"id": "entry-1",
							"title": "Advisory 1",
							"link": [
								{ "href": "/csaf/advisory-1.json", "rel": "service" }
							]
						}
					]
				}
			}`))
		case "/csaf/advisory-1.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(sampleCSAFJSON))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	ctx := context.Background()
	res, err := FetchCSAFProvider(ctx, ts.Client(), ts.URL+"/.well-known/csaf/provider-metadata.json", nil)
	if err != nil {
		t.Fatalf("FetchCSAFProvider failed: %v", err)
	}
	if !res.Complete {
		t.Errorf("expected complete snapshot from CSAF provider")
	}
	stmts := res.Statements
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements from ROLIE feed, got %d", len(stmts))
	}
	if stmts[0].Role != RoleUpstream {
		t.Errorf("expected role upstream, got %s", stmts[0].Role)
	}
}
