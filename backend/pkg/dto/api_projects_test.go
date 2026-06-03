package dto

import (
	"testing"
)

func TestProjectListItemFields(t *testing.T) {
	item := ProjectListItem{
		ProjectName:    "containerd",
		SBOMCount:      5,
		PackageCount:   120,
		VulnCount:      3,
		LatestIngested: "2026-05-01T12:00:00Z",
		LatestSBOMID:   "abc-123",
	}

	if item.ProjectName != "containerd" {
		t.Errorf("expected ProjectName 'containerd', got %q", item.ProjectName)
	}
	if item.SBOMCount != 5 {
		t.Errorf("expected SBOMCount 5, got %d", item.SBOMCount)
	}
	if item.PackageCount != 120 {
		t.Errorf("expected PackageCount 120, got %d", item.PackageCount)
	}
	if item.VulnCount != 3 {
		t.Errorf("expected VulnCount 3, got %d", item.VulnCount)
	}
}

