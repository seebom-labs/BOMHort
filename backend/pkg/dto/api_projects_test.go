package dto

import (
	"encoding/json"
	"strings"
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

// A tagged project must still report its own name and version count. Tags
// group projects, they do not replace them -- if a tag ever started standing
// in for the project, every project under one grouping would collapse into a
// single row and the version counts would silently merge.
func TestProjectListItemKeepsIdentityWhenTagged(t *testing.T) {
	item := ProjectListItem{
		ProjectName: "k2s",
		SBOMCount:   3,
		Tags:        []string{"sandbox-applications"},
	}
	if item.ProjectName != "k2s" {
		t.Errorf("ProjectName = %q, want k2s", item.ProjectName)
	}
	if item.SBOMCount != 3 {
		t.Errorf("SBOMCount = %d, want 3 (tagging must not merge versions)", item.SBOMCount)
	}
	if len(item.Tags) != 1 || item.Tags[0] != "sandbox-applications" {
		t.Errorf("Tags = %v, want [sandbox-applications]", item.Tags)
	}
}

// tags carries no omitempty: the UI indexes project.tags directly, so the key
// must be present on every item rather than vanishing for untagged projects.
func TestProjectListItemAlwaysSerialisesTags(t *testing.T) {
	data, err := json.Marshal(ProjectListItem{ProjectName: "untagged"})
	if err != nil {
		t.Fatalf("failed to marshal ProjectListItem: %v", err)
	}
	if !strings.Contains(string(data), `"tags"`) {
		t.Errorf("marshalled item = %s, want a tags key even when empty", data)
	}
}

// TagListItem reports both counts because they answer different questions: a
// grouping spanning 41 projects across 312 documents should be presented as
// 41, not 312.
func TestTagListItemFields(t *testing.T) {
	item := TagListItem{Tag: "sandbox-applications", SBOMCount: 312, ProjectCount: 41}
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal TagListItem: %v", err)
	}
	for _, key := range []string{`"tag"`, `"sbom_count"`, `"project_count"`} {
		if !strings.Contains(string(data), key) {
			t.Errorf("marshalled item = %s, missing %s", data, key)
		}
	}
}
