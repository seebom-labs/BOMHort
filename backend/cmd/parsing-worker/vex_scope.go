package main

import (
	"context"
	"log"

	"github.com/seebom-labs/bomhort/backend/internal/sourcerepo"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// sbomResolver is the lookup surface scopeVEXStatements needs; satisfied by
// *clickhouse.Client and mockable in tests.
type sbomResolver interface {
	ResolveSBOMByProductRef(ctx context.Context, ref string) (string, error)
}

// scopeVEXStatements assigns each parsed VEX statement to the SBOM whose
// product it describes (#350).
//
// Precedence:
//
//  1. Explicit mapping: the upload carried ?sbom_id= (job.TargetSBOMID) —
//     every statement in the document is scoped to that SBOM.
//  2. Automatic: the statement's product @id is resolved against the sboms
//     table (sbom_id, source_repo, document_namespace, document_name).
//     Repo-URL product IRIs are normalised first so
//     "git+https://…/repo.git@v1" matches the stored source_repo form.
//  3. Fallback: no match — the statement is stored unscoped (sbom_id ”). Per
//     the OpenVEX spec "a valid statement MUST identify a product", so an
//     unresolved product means the statement applies to no SBOM here: it is
//     kept for audit/listing but never suppresses findings (the resolution
//     queries only consider statements scoped to the SBOM being viewed). A
//     warning is logged so the operator can re-upload with ?sbom_id=.
//
// Resolution results are memoised per product ref: documents typically repeat
// the same product across statements.
//
// Resolving the ref is also what tells a product-wide statement (products[]
// with no subcomponents[]) apart from the component shape where the product @id
// *is* the vulnerable purl: only the sboms table knows whether a ref names a
// product. A ref that resolves is a product, so the statement covers every
// component of it and ProductPURL becomes models.VEXProductWide.
func scopeVEXStatements(ctx context.Context, resolver sbomResolver, job models.IngestionJob, stmts []models.VEXStatement) {
	if job.TargetSBOMID != "" {
		for i := range stmts {
			stmts[i].SBOMID = job.TargetSBOMID
			// An explicit ?sbom_id= names the product outright, so a statement
			// without subcomponents covers that product as a whole.
			if stmts[i].ProductWide {
				stmts[i].ProductPURL = models.VEXProductWide
			}
		}
		return
	}

	cache := make(map[string]string)
	unresolved := make(map[string]struct{})

	for i := range stmts {
		ref := stmts[i].ProductRef
		if ref == "" {
			continue
		}
		sbomID, seen := cache[ref]
		if !seen {
			var err error
			sbomID, err = resolver.ResolveSBOMByProductRef(ctx, ref)
			if err != nil {
				log.Printf("  WARNING: VEX %s: failed to resolve product %q: %v", job.SourceFile, ref, err)
				sbomID = ""
			}
			// Retry with the normalised repo-URL form: product IRIs like
			// "git+https://host/org/repo.git@v1.2.3" should match the
			// source_repo column, which stores the normalised URL (#332).
			if sbomID == "" {
				if norm, _ := sourcerepo.Normalize(ref); norm != "" && norm != ref {
					sbomID, err = resolver.ResolveSBOMByProductRef(ctx, norm)
					if err != nil {
						log.Printf("  WARNING: VEX %s: failed to resolve product %q: %v", job.SourceFile, norm, err)
						sbomID = ""
					}
				}
			}
			cache[ref] = sbomID
		}
		if sbomID == "" {
			unresolved[ref] = struct{}{}
			continue
		}
		stmts[i].SBOMID = sbomID
		// The ref names a product, so a statement carrying no subcomponents
		// applies to every component of that product. Left as the raw ref when
		// unresolved: it is inert either way, and keeping the original value
		// makes the warning above actionable.
		if stmts[i].ProductWide {
			stmts[i].ProductPURL = models.VEXProductWide
		}
	}

	for ref := range unresolved {
		log.Printf("  WARNING: VEX %s: product %q matches no SBOM — statements stored unscoped and will not suppress any findings. Map explicitly with ?sbom_id= on upload.", job.SourceFile, ref)
	}
}
