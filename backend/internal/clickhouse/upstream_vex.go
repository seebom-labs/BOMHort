package clickhouse

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/config"
	"github.com/seebom-labs/bomhort/backend/internal/vexsub"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// SyncUpstreamVEX pulls upstream VEX statements from configured sources,
// matches them to stored SBOM packages by PURL, scopes them to the matching
// SBOMs, and inserts them into ClickHouse (#538).
func (c *Client) SyncUpstreamVEX(ctx context.Context, sources []config.VEXSourceConfig) (int, error) {
	if len(sources) == 0 {
		return 0, nil
	}

	purls, err := c.QueryDistinctPURLs(ctx)
	if err != nil {
		return 0, fmt.Errorf("querying distinct PURLs for VEX sync: %w", err)
	}

	var rawStmts []models.VEXStatement
	pullComplete := false
	if len(purls) > 0 {
		engine := vexsub.NewEngine()
		result, err := engine.Pull(ctx, sources, purls)
		if err != nil {
			return 0, fmt.Errorf("pulling upstream VEX: %w", err)
		}
		rawStmts = result.Statements
		pullComplete = result.Complete
	}

	// Group statements by ProductPURL.
	purlToStmts := make(map[string][]models.VEXStatement)
	for _, s := range rawStmts {
		purlToStmts[s.ProductPURL] = append(purlToStmts[s.ProductPURL], s)
	}

	uniquePURLs := make([]string, 0, len(purlToStmts))
	for p := range purlToStmts {
		uniquePURLs = append(uniquePURLs, p)
	}

	// Map each PURL to the SBOMs containing it.
	const purlChunk = 2000
	sbomPURLMap := make(map[string][]SBOMRef)
	for i := 0; i < len(uniquePURLs); i += purlChunk {
		chunk := uniquePURLs[i:min(i+purlChunk, len(uniquePURLs))]
		found, err := c.QuerySBOMsByPURLs(ctx, chunk)
		if err != nil {
			return 0, fmt.Errorf("querying SBOMs for VEX PURLs: %w", err)
		}
		for p, refs := range found {
			sbomPURLMap[p] = refs
		}
	}

	var toInsert []models.VEXStatement
	seenVEXID := make(map[uuid.UUID]struct{})
	now := time.Now()

	for purl, stmts := range purlToStmts {
		refs := sbomPURLMap[purl]
		for _, ref := range refs {
			for _, s := range stmts {
				// Generate deterministic VEXID scoped to this SBOM.
				vexID := uuid.NewSHA1(uuid.NameSpaceDNS, []byte(ref.SBOMID.String()+"|"+s.DocumentID+"|"+s.VulnID+"|"+s.ProductPURL))

				scoped := s
				scoped.IngestedAt = now
				scoped.VEXID = vexID
				scoped.SBOMID = ref.SBOMID.String()
				scoped.Cluster = ref.Cluster
				scoped.Namespace = ref.Namespace
				scoped.Project = ref.Project
				scoped.SourceFile = ref.SourceFile
				scoped.Role = vexsub.RoleUpstream
				if scoped.Author == "" {
					scoped.Author = vexsub.AuthorUpstream
				}

				if _, dup := seenVEXID[scoped.VEXID]; !dup {
					seenVEXID[scoped.VEXID] = struct{}{}
					toInsert = append(toInsert, scoped)
				}
			}
		}
	}

	if len(toInsert) > 0 {
		if err := c.InsertVEXStatements(ctx, toInsert); err != nil {
			return 0, fmt.Errorf("inserting upstream VEX statements: %w", err)
		}
		log.Printf("Applied %d upstream VEX statements across matching SBOMs", len(toInsert))
	}

	// Reconcile removed upstream statements: retire previously stored statements
	// with role='upstream' that are absent from this successful feed snapshot.
	// Only reconcile after verifying every source produced a complete snapshot;
	// keep the old snapshot on capped or partial pulls (#538).
	if pullComplete {
		if err := c.retireRemovedUpstreamStatements(ctx, seenVEXID); err != nil {
			return len(toInsert), fmt.Errorf("retiring removed upstream VEX statements: %w", err)
		}
	} else {
		log.Printf("Skipping upstream VEX reconciliation: snapshot was partial or capped")
	}

	return len(toInsert), nil
}

// retireRemovedUpstreamStatements deletes previously stored statements with role='upstream'
// that are not in activeIDs.
func (c *Client) retireRemovedUpstreamStatements(ctx context.Context, activeIDs map[uuid.UUID]struct{}) error {
	rows, err := c.Conn.Query(ctx, "SELECT DISTINCT toString(vex_id) FROM vex_statements FINAL WHERE role = ?", vexsub.RoleUpstream)
	if err != nil {
		return fmt.Errorf("querying existing upstream vex_ids: %w", err)
	}
	defer rows.Close()

	var staleIDs []string
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return fmt.Errorf("scanning upstream vex_id: %w", err)
		}
		parsedID, err := uuid.Parse(idStr)
		if err != nil {
			continue
		}
		if _, keep := activeIDs[parsedID]; !keep {
			staleIDs = append(staleIDs, idStr)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating upstream vex_ids: %w", err)
	}

	if len(staleIDs) == 0 {
		return nil
	}

	const deleteChunk = 1000
	for i := 0; i < len(staleIDs); i += deleteChunk {
		chunk := staleIDs[i:min(i+deleteChunk, len(staleIDs))]
		if err := c.Conn.Exec(ctx,
			"ALTER TABLE vex_statements DELETE WHERE role = ? AND toString(vex_id) IN (?) SETTINGS mutations_sync = 1",
			vexsub.RoleUpstream, chunk,
		); err != nil {
			return fmt.Errorf("deleting removed upstream statements: %w", err)
		}
	}

	log.Printf("Retired %d removed upstream VEX statement(s)", len(staleIDs))
	return nil
}
