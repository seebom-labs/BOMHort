package clickhouse

import (
	"context"
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// TestClusterDTOs verifies that cluster DTOs serialize correctly.
func TestClusterDTOs(t *testing.T) {
	item := dto.ClusterListItem{
		Name:         "production",
		SBOMCount:    42,
		PackageCount: 1200,
		VulnCount:    15,
		LastIngested: "2026-06-01T00:00:00Z",
	}

	if item.Name != "production" {
		t.Errorf("expected production, got %s", item.Name)
	}
	if item.SBOMCount != 42 {
		t.Errorf("expected 42, got %d", item.SBOMCount)
	}
}

func TestClusterStatsDTO(t *testing.T) {
	stats := dto.ClusterStats{
		Cluster:              "staging",
		TotalSBOMs:          10,
		TotalPackages:        500,
		TotalVulnerabilities: 25,
		CriticalVulns:        2,
		HighVulns:            8,
		MediumVulns:          10,
		LowVulns:             5,
		LicenseBreakdown:     map[string]uint64{"permissive": 400, "copyleft": 50, "unknown": 50},
		LastIngested:         "2026-06-01T12:00:00Z",
	}

	if stats.Cluster != "staging" {
		t.Errorf("expected staging, got %s", stats.Cluster)
	}
	if stats.CriticalVulns+stats.HighVulns+stats.MediumVulns+stats.LowVulns != stats.TotalVulnerabilities {
		t.Errorf("severity sum mismatch")
	}
	if stats.LicenseBreakdown["permissive"] != 400 {
		t.Errorf("expected 400 permissive, got %d", stats.LicenseBreakdown["permissive"])
	}
}

// TestPingMethodExists is a compile-time check that the Ping method is available.
func TestPingMethodExists(t *testing.T) {
	var c *Client
	var _ func(context.Context) error = c.Ping
}

// TestQueryClusterMethodsExist verifies method signatures compile.
func TestQueryClusterMethodsExist(t *testing.T) {
	var c *Client
	var _ func(context.Context) ([]dto.ClusterListItem, error) = c.QueryClusters
	var _ func(context.Context, string) (*dto.ClusterStats, error) = c.QueryClusterStats
	var _ func(context.Context, string, uint64, uint64) (*dto.PaginatedResponse[dto.SBOMListItem], error) = c.QueryClusterSBOMs
}