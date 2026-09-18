package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// mockRescueStore records the rescue flow against an in-memory statement set.
type mockRescueStore struct {
	unscoped  []models.VEXStatement
	resolves  map[string]string // product ref -> sbom id
	inserted  []models.VEXStatement
	deleted   []string
	queryErr  error
	insertErr error
}

func (m *mockRescueStore) QueryUnscopedVEXStatements(_ context.Context) ([]models.VEXStatement, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	out := make([]models.VEXStatement, len(m.unscoped))
	copy(out, m.unscoped)
	return out, nil
}

func (m *mockRescueStore) InsertVEXStatements(_ context.Context, stmts []models.VEXStatement) error {
	if m.insertErr != nil {
		return m.insertErr
	}
	m.inserted = append(m.inserted, stmts...)
	return nil
}

func (m *mockRescueStore) DeleteUnscopedVEXStatements(_ context.Context, ids []string) error {
	m.deleted = append(m.deleted, ids...)
	return nil
}

func (m *mockRescueStore) ResolveSBOMByProductRef(_ context.Context, ref string) (string, error) {
	return m.resolves[ref], nil
}

// The core ordering bug (#350): a VEX document processed before its SBOM was
// stored unscoped and, because the ref was discarded and the idempotency guard
// skipped the document afterwards, stayed inert forever. The rescue pass runs
// after each SBOM ingest and must scope such statements.
func TestRescueScopesProductWideStatement(t *testing.T) {
	ref := "https://example.com/sbom/payment-api-1.4.2"
	id := uuid.New()
	store := &mockRescueStore{
		unscoped: []models.VEXStatement{{
			VEXID:       id,
			ProductRef:  ref,
			ProductPURL: ref, // still the raw ref = no subcomponent = product-wide
			VulnID:      "CVE-2020-8203",
			Status:      "not_affected",
		}},
		resolves: map[string]string{ref: "7298e78d-1fc7-577e-a19c-3b211be17aa6"},
	}

	rescueUnscopedVEX(context.Background(), store, "payment-api-1.4.2.spdx.json")

	if len(store.inserted) != 1 {
		t.Fatalf("inserted %d statements, want 1", len(store.inserted))
	}
	got := store.inserted[0]
	if got.SBOMID != "7298e78d-1fc7-577e-a19c-3b211be17aa6" {
		t.Errorf("SBOMID = %q, want the resolved SBOM", got.SBOMID)
	}
	if got.ProductPURL != models.VEXProductWide {
		t.Errorf("ProductPURL = %q, want %q (product-wide once the ref resolves)", got.ProductPURL, models.VEXProductWide)
	}
	if len(store.deleted) != 1 || store.deleted[0] != id.String() {
		t.Errorf("deleted = %v, want the unscoped original %s", store.deleted, id)
	}
}

// A subcomponent-pinned statement keeps its component purl on rescue: the
// product resolves the scope, the subcomponent stays the match target.
func TestRescueKeepsSubcomponentPURL(t *testing.T) {
	ref := "https://example.com/sbom/payment-api-1.4.2"
	store := &mockRescueStore{
		unscoped: []models.VEXStatement{{
			VEXID:       uuid.New(),
			ProductRef:  ref,
			ProductPURL: "pkg:npm/lodash@4.17.15", // pinned by subcomponents[]
			VulnID:      "CVE-2020-8203",
		}},
		resolves: map[string]string{ref: "7298e78d-1fc7-577e-a19c-3b211be17aa6"},
	}

	rescueUnscopedVEX(context.Background(), store, "x.spdx.json")

	if len(store.inserted) != 1 {
		t.Fatalf("inserted %d statements, want 1", len(store.inserted))
	}
	if got := store.inserted[0].ProductPURL; got != "pkg:npm/lodash@4.17.15" {
		t.Errorf("ProductPURL = %q, want the subcomponent purl untouched", got)
	}
}

// Statements that still do not resolve stay untouched — no insert, no delete.
// Rescuing must be a no-op for the component shape (Trivy et al.), whose ref
// is a purl that matches no SBOM.
func TestRescueLeavesUnresolvableAlone(t *testing.T) {
	store := &mockRescueStore{
		unscoped: []models.VEXStatement{{
			VEXID:       uuid.New(),
			ProductRef:  "pkg:golang/github.com/sirupsen/logrus@v1.9.0",
			ProductPURL: "pkg:golang/github.com/sirupsen/logrus@v1.9.0",
			VulnID:      "CVE-2022-0001",
		}},
		resolves: map[string]string{},
	}

	rescueUnscopedVEX(context.Background(), store, "x.spdx.json")

	if len(store.inserted) != 0 || len(store.deleted) != 0 {
		t.Errorf("inserted=%d deleted=%d, want 0/0 for an unresolvable ref",
			len(store.inserted), len(store.deleted))
	}
}

// A rescue failure must never propagate: the SBOM ingest that triggered it has
// already succeeded.
func TestRescueSwallowsErrors(t *testing.T) {
	store := &mockRescueStore{queryErr: errors.New("clickhouse down")}
	// Must not panic and has no error to return.
	rescueUnscopedVEX(context.Background(), store, "x.spdx.json")

	store2 := &mockRescueStore{
		unscoped: []models.VEXStatement{{
			VEXID:       uuid.New(),
			ProductRef:  "https://example.com/sbom/app",
			ProductPURL: "https://example.com/sbom/app",
		}},
		resolves:  map[string]string{"https://example.com/sbom/app": "some-sbom"},
		insertErr: errors.New("insert failed"),
	}
	rescueUnscopedVEX(context.Background(), store2, "x.spdx.json")
	if len(store2.deleted) != 0 {
		t.Error("originals were deleted although the scoped copies failed to insert — statements would be lost")
	}
}
