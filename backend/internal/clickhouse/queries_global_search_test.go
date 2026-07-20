package clickhouse

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

func TestGlobalSearchDTOs(t *testing.T) {
	resp := dto.GlobalSearchResponse{
		Query:                "grpc",
		Packages:             []dto.GlobalSearchPackage{{PackageName: "google.golang.org/grpc", PURL: "pkg:golang/google.golang.org/grpc@v1.60.0", ProjectCount: 12}},
		TotalPackages:        3,
		Projects:             []dto.GlobalSearchProject{{ProjectName: "grpc/grpc-go", SBOMCount: 4, LatestSBOMID: "11111111-2222-3333-4444-555555555555"}},
		TotalProjects:        1,
		Vulnerabilities:      []dto.GlobalSearchVulnerability{{VulnID: "CVE-2024-1234", Severity: "HIGH", Summary: "gRPC DoS", AffectedSBOMs: 7}},
		TotalVulnerabilities: 1,
		Licenses:             []dto.GlobalSearchLicense{{LicenseID: "Apache-2.0", Category: "permissive", SBOMCount: 100}},
		TotalLicenses:        1,
	}

	if resp.Query != "grpc" {
		t.Errorf("expected query grpc, got %s", resp.Query)
	}
	if len(resp.Packages) != 1 || resp.Packages[0].ProjectCount != 12 {
		t.Errorf("unexpected packages facet: %+v", resp.Packages)
	}
	if resp.Projects[0].LatestSBOMID == "" {
		t.Error("expected latest_sbom_id to be set")
	}
	if resp.Vulnerabilities[0].VulnID != "CVE-2024-1234" {
		t.Errorf("unexpected vuln facet: %+v", resp.Vulnerabilities)
	}
	if resp.Licenses[0].Category != "permissive" {
		t.Errorf("unexpected license facet: %+v", resp.Licenses)
	}
}

func TestQueryGlobalSearchMethodExists(t *testing.T) {
	var c *Client
	var _ func(context.Context, string, uint64) (*dto.GlobalSearchResponse, error) = c.QueryGlobalSearch
}

func TestEscapeLikePattern(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain term unchanged", "grpc", "grpc"},
		{"percent escaped", "100%", `100\%`},
		{"only percent escaped", "%", `\%`},
		{"underscore escaped", "my_pkg", `my\_pkg`},
		{"multiple underscores escaped", "___", `\_\_\_`},
		{"backslash escaped", `a\b`, `a\\b`},
		{"backslash before wildcard escaped first", `\%`, `\\\%`},
		{"mixed wildcards", `x_%\`, `x\_\%\\`},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeLikePattern(tt.in); got != tt.want {
				t.Errorf("escapeLikePattern(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
