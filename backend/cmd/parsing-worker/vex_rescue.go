package main

import (
	"context"
	"log"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// vexRescuer is the storage surface rescueUnscopedVEX needs; satisfied by
// *clickhouse.Client and mockable in tests.
type vexRescuer interface {
	sbomResolver
	QueryUnscopedVEXStatements(ctx context.Context) ([]models.VEXStatement, error)
	InsertVEXStatements(ctx context.Context, stmts []models.VEXStatement) error
	DeleteUnscopedVEXStatements(ctx context.Context, vexIDs []string) error
}

// rescueUnscopedVEX re-resolves statements that were stored without an SBOM
// scope and scopes those whose product now exists.
//
// VEX and SBOM files land in arbitrary order. A statement whose product SBOM
// had not been ingested yet failed resolution, was stored with sbom_id = ”
// and suppressed nothing — and because the idempotency guard skipped the
// document on every later encounter, it stayed inert forever. This pass runs
// after each successful SBOM ingest, when exactly one new resolution target
// exists, and turns the ordering problem into a short delay.
//
// Product-wide detection mirrors ingest: a statement whose stored purl still
// equals the raw product ref carried no subcomponent, so once the ref resolves
// it covers the whole product and the purl becomes models.VEXProductWide. A
// subcomponent-pinned statement keeps its component purl.
//
// The corrected copy is inserted before the unscoped original is deleted:
// product_purl is part of the table's ORDER BY key, so the new row cannot
// replace the old one — and crashing between the two steps must leave the
// statement duplicated (harmless: both now match or not identically), never
// lost. Failures only log; a VEX bookkeeping problem must not fail the SBOM
// ingest that triggered it.
func rescueUnscopedVEX(ctx context.Context, store vexRescuer, sourceFile string) {
	stmts, err := store.QueryUnscopedVEXStatements(ctx)
	if err != nil {
		log.Printf("  WARNING: VEX rescue after %s: %v", sourceFile, err)
		return
	}
	if len(stmts) == 0 {
		return
	}

	for i := range stmts {
		stmts[i].ProductWide = stmts[i].ProductRef == stmts[i].ProductPURL
	}

	// Same resolution rules as ingest (memoised per ref, sourcerepo-normalised
	// retry); an empty job means no explicit ?sbom_id= mapping.
	scopeVEXStatements(ctx, store, models.IngestionJob{}, stmts)

	var rescued []models.VEXStatement
	var oldIDs []string
	now := time.Now()
	for i := range stmts {
		if stmts[i].SBOMID == "" {
			continue
		}
		stmts[i].IngestedAt = now
		rescued = append(rescued, stmts[i])
		oldIDs = append(oldIDs, stmts[i].VEXID.String())
	}
	if len(rescued) == 0 {
		return
	}

	if err := store.InsertVEXStatements(ctx, rescued); err != nil {
		log.Printf("  WARNING: VEX rescue after %s: insert failed: %v", sourceFile, err)
		return
	}
	if err := store.DeleteUnscopedVEXStatements(ctx, oldIDs); err != nil {
		log.Printf("  WARNING: VEX rescue after %s: cleanup failed (scoped copies are in place, unscoped originals linger): %v", sourceFile, err)
		return
	}
	log.Printf("  Rescued %d previously unscoped VEX statement(s) after ingesting %s", len(rescued), sourceFile)
}
