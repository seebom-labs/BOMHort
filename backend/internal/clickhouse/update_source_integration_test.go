package clickhouse

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// TestUpdateSBOMSourceIntegration verifies that UpdateSBOMSource and QuerySBOMSource
// work against a real ClickHouse instance (#332, #636).
//
// Specifically, it verifies that:
// 1. Tags, source_repo, and source_ref can be updated independently.
// 2. Partial updates only mutate the specified columns, without overwriting other columns.
// 3. Tags can be updated and cleared, and read back via QuerySBOMSource.
// 4. Unknown SBOM ID returns ErrSBOMNotFound.
//
// Skipped unless CLICKHOUSE_HOST is set (see testClient).
func TestUpdateSBOMSourceIntegration(t *testing.T) {
	c := testClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sbomID := uuid.New()
	if err := c.InsertSBOM(ctx, &models.SBOM{
		IngestedAt:   time.Now(),
		SBOMID:       sbomID,
		SourceFile:   "integration-test/update-source.spdx.json",
		SPDXVersion:  "SPDX-2.3",
		DocumentName: "update-source-test",
		SHA256Hash:   uuid.NewString(),
		CreationDate: time.Now(),
	}); err != nil {
		t.Fatalf("InsertSBOM: %v", err)
	}

	// Initial state: empty source_repo, empty source_ref, empty tags.
	repo, ref, tags, err := c.QuerySBOMSource(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMSource initial: %v", err)
	}
	if repo != "" || ref != "" || len(tags) != 0 {
		t.Fatalf("initial source = (%q, %q, %v), want empty", repo, ref, tags)
	}

	// Update tags only.
	newTags := []string{"alpha", "beta"}
	if err := c.UpdateSBOMSource(ctx, sbomID.String(), nil, nil, &newTags); err != nil {
		t.Fatalf("UpdateSBOMSource (tags only): %v", err)
	}

	repo, ref, tags, err = c.QuerySBOMSource(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMSource after tags update: %v", err)
	}
	if repo != "" || ref != "" {
		t.Errorf("repo/ref changed unexpectedly on tags-only update: repo=%q, ref=%q", repo, ref)
	}
	if !slices.Equal(tags, newTags) {
		t.Errorf("tags = %v, want %v", tags, newTags)
	}

	// Update repo only: tags must not be overwritten.
	newRepo := "https://github.com/example-org/example-app"
	if err := c.UpdateSBOMSource(ctx, sbomID.String(), &newRepo, nil, nil); err != nil {
		t.Fatalf("UpdateSBOMSource (repo only): %v", err)
	}

	repo, ref, tags, err = c.QuerySBOMSource(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMSource after repo update: %v", err)
	}
	if repo != newRepo {
		t.Errorf("repo = %q, want %q", repo, newRepo)
	}
	if ref != "" {
		t.Errorf("ref = %q, want empty", ref)
	}
	if !slices.Equal(tags, newTags) {
		t.Errorf("tags were overwritten by repo update! got %v, want %v", tags, newTags)
	}

	// Update ref only: repo and tags must not be overwritten.
	newRef := "v1.2.3"
	if err := c.UpdateSBOMSource(ctx, sbomID.String(), nil, &newRef, nil); err != nil {
		t.Fatalf("UpdateSBOMSource (ref only): %v", err)
	}

	repo, ref, tags, err = c.QuerySBOMSource(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMSource after ref update: %v", err)
	}
	if repo != newRepo {
		t.Errorf("repo was overwritten by ref update! got %q, want %q", repo, newRepo)
	}
	if ref != newRef {
		t.Errorf("ref = %q, want %q", ref, newRef)
	}
	if !slices.Equal(tags, newTags) {
		t.Errorf("tags were overwritten by ref update! got %v, want %v", tags, newTags)
	}

	// Clear tags by passing empty slice: repo and ref must not be overwritten.
	emptyTags := []string{}
	if err := c.UpdateSBOMSource(ctx, sbomID.String(), nil, nil, &emptyTags); err != nil {
		t.Fatalf("UpdateSBOMSource (clear tags): %v", err)
	}

	repo, ref, tags, err = c.QuerySBOMSource(ctx, sbomID.String())
	if err != nil {
		t.Fatalf("QuerySBOMSource after clearing tags: %v", err)
	}
	if repo != newRepo || ref != newRef {
		t.Errorf("repo/ref changed when clearing tags: repo=%q, ref=%q", repo, ref)
	}
	if len(tags) != 0 {
		t.Errorf("tags = %v, want empty after clearing", tags)
	}

	// Non-existent SBOM ID returns ErrSBOMNotFound.
	unknownID := uuid.New().String()
	if err := c.UpdateSBOMSource(ctx, unknownID, &newRepo, nil, nil); !errors.Is(err, ErrSBOMNotFound) {
		t.Errorf("UpdateSBOMSource for unknown ID = %v, want ErrSBOMNotFound", err)
	}
	if _, _, _, err := c.QuerySBOMSource(ctx, unknownID); !errors.Is(err, ErrSBOMNotFound) {
		t.Errorf("QuerySBOMSource for unknown ID = %v, want ErrSBOMNotFound", err)
	}
}
