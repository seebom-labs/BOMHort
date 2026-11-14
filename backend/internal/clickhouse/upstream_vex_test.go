package clickhouse

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestUpstreamVEXPrecedence(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	sbomID := uuid.New()
	project := fmt.Sprintf("fx-upstream-vex-%s", sbomID.String()[:8])
	purl := "pkg:rpm/redhat/curl@7.61.1-22.el8?arch=x86_64"
	vulnID := fmt.Sprintf("CVE-2099-%s", sbomID.String()[:6])
	now := time.Now().UTC().Truncate(time.Second)
	hash := fmt.Sprintf("%064x", sbomID[:16])

	if err := c.Conn.Exec(ctx, `
		INSERT INTO sboms (ingested_at, sbom_id, source_file, spdx_version, document_name,
			document_namespace, sha256_hash, creation_date, creator_tools,
			cluster, namespace, project, source_repo, source_ref, document_version, tags)
		VALUES (?, ?, ?, 'SPDX-2.3', ?, '', ?, ?, [], '', '', ?, '', '', '1.0.0', [])`,
		now, sbomID.String(), "fixtures/"+project+".spdx.json", project, hash, now, project); err != nil {
		t.Fatalf("Insert test SBOM failed: %v", err)
	}
	if err := c.Conn.Exec(ctx, `
		INSERT INTO sbom_packages (ingested_at, sbom_id, source_file, package_spdx_ids,
			package_names, package_versions, package_purls, package_licenses,
			rel_source_indices, rel_target_indices, rel_types, cluster, namespace, project)
		VALUES (?, ?, ?, ['SPDXRef-0'], ['curl'], ['7.61.1-22.el8'], [?], ['MIT'], [], [], [], '', '', ?)`,
		now, sbomID.String(), "fixtures/"+project+".spdx.json", purl, project); err != nil {
		t.Fatalf("Insert test packages failed: %v", err)
	}

	t.Cleanup(func() {
		for _, table := range []string{"sboms", "sbom_packages", "vulnerabilities", "vex_statements"} {
			_ = c.Conn.Exec(context.Background(),
				fmt.Sprintf("ALTER TABLE %s DELETE WHERE toString(sbom_id) = ? SETTINGS mutations_sync = 1", table),
				sbomID.String())
		}
	})

	if err := c.InsertVulnerabilities(ctx, []models.Vulnerability{
		{
			DiscoveredAt: now,
			SBOMID:       sbomID,
			SourceFile:   "fixtures/" + project + ".spdx.json",
			PURL:         purl,
			VulnID:       vulnID,
			Severity:     "HIGH",
			Summary:      "test upstream vex precedence",
			Project:      project,
		},
	}); err != nil {
		t.Fatalf("InsertVulnerabilities failed: %v", err)
	}

	// 1. Insert upstream statement with status not_affected published later.
	upstreamTime := now.Add(2 * time.Hour)
	if err := c.InsertVEXStatements(ctx, []models.VEXStatement{
		{
			IngestedAt:    now,
			VEXID:         uuid.New(),
			DocumentID:    "upstream-doc-1",
			SourceFile:    "https://vex.example.com/csaf/curl.json",
			SBOMID:        sbomID.String(),
			ProductPURL:   purl,
			VulnID:        vulnID,
			Status:        models.VEXStatusNotAffected,
			Justification: models.VEXJustificationVulnerableCodeNotPresent,
			VEXTimestamp:  upstreamTime,
			Author:        "Upstream Security Team",
			Role:          models.VEXRoleUpstream,
			Tooling:       "https://vex.example.com/csaf",
		},
	}); err != nil {
		t.Fatalf("Insert upstream VEX failed: %v", err)
	}

	filter := VulnFilter{Projects: []string{project}}

	vulns, err := c.QuerySBOMVulnerabilities(ctx, sbomID.String(), "", "")
	if err != nil {
		t.Fatalf("QuerySBOMVulnerabilities failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].VEXStatus != models.VEXStatusNotAffected || vulns[0].VEXRole != models.VEXRoleUpstream {
		t.Fatalf("expected upstream not_affected, got status=%q role=%q", vulns[0].VEXStatus, vulns[0].VEXRole)
	}
	if vulns[0].VEXTimestamp != upstreamTime.Format(time.RFC3339) {
		t.Errorf("expected upstream timestamp %s, got %s", upstreamTime.Format(time.RFC3339), vulns[0].VEXTimestamp)
	}

	stats, err := c.QueryDashboardStats(ctx, filter)
	if err != nil {
		t.Fatalf("QueryDashboardStats failed: %v", err)
	}
	if stats.SuppressedByVEX != 1 {
		t.Errorf("expected SuppressedByVEX=1 from upstream, got %d", stats.SuppressedByVEX)
	}

	listResp, err := c.QueryVulnerabilities(ctx, 1, 50, "", filter)
	if err != nil {
		t.Fatalf("QueryVulnerabilities failed: %v", err)
	}
	if len(listResp.Data) != 1 || listResp.Data[0].VEXStatus != models.VEXStatusNotAffected || listResp.Data[0].VEXRole != models.VEXRoleUpstream {
		t.Errorf("QueryVulnerabilities unexpected result: %+v", listResp.Data)
	}

	projVulns, err := c.QueryProjectVulnerabilities(ctx, project, "")
	if err != nil {
		t.Fatalf("QueryProjectVulnerabilities failed: %v", err)
	}
	if len(projVulns) != 1 || projVulns[0].VEXStatus != models.VEXStatusNotAffected || projVulns[0].VEXRole != models.VEXRoleUpstream {
		t.Errorf("QueryProjectVulnerabilities unexpected result: %+v", projVulns)
	}

	affected, err := c.QueryAffectedProjectsByCVE(ctx, vulnID, filter)
	if err != nil {
		t.Fatalf("QueryAffectedProjectsByCVE failed: %v", err)
	}
	if len(affected) != 1 || affected[0].VEXStatus != models.VEXStatusNotAffected {
		t.Errorf("QueryAffectedProjectsByCVE unexpected result: %+v", affected)
	}

	// 2. Insert local statement with status affected and an older timestamp.
	// Local statements must win on status, role, and timestamp across every view.
	localTime := now.Add(1 * time.Hour)
	if err := c.InsertVEXStatements(ctx, []models.VEXStatement{
		{
			IngestedAt:   now.Add(1 * time.Minute),
			VEXID:        uuid.New(),
			DocumentID:   "local-doc-1",
			SourceFile:   "local.openvex.json",
			SBOMID:       sbomID.String(),
			ProductPURL:  purl,
			VulnID:       vulnID,
			Status:       models.VEXStatusAffected,
			VEXTimestamp: localTime,
			Author:       "Security Lead",
			Role:         "security-lead",
			Tooling:      "manual-triage",
		},
	}); err != nil {
		t.Fatalf("Insert local VEX failed: %v", err)
	}

	vulns, err = c.QuerySBOMVulnerabilities(ctx, sbomID.String(), "", "")
	if err != nil {
		t.Fatalf("QuerySBOMVulnerabilities failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vuln, got %d", len(vulns))
	}
	if vulns[0].VEXStatus != models.VEXStatusAffected || vulns[0].VEXRole != "security-lead" {
		t.Errorf("expected local affected to outrank upstream, got status=%q role=%q", vulns[0].VEXStatus, vulns[0].VEXRole)
	}
	if vulns[0].VEXTimestamp != localTime.Format(time.RFC3339) {
		t.Errorf("expected winning local timestamp %s, got %s", localTime.Format(time.RFC3339), vulns[0].VEXTimestamp)
	}

	stats, err = c.QueryDashboardStats(ctx, filter)
	if err != nil {
		t.Fatalf("QueryDashboardStats failed: %v", err)
	}
	if stats.SuppressedByVEX != 0 {
		t.Errorf("expected SuppressedByVEX=0 after local affected override, got %d", stats.SuppressedByVEX)
	}

	listResp, err = c.QueryVulnerabilities(ctx, 1, 50, "", filter)
	if err != nil {
		t.Fatalf("QueryVulnerabilities failed: %v", err)
	}
	if len(listResp.Data) != 1 || listResp.Data[0].VEXStatus != models.VEXStatusAffected || listResp.Data[0].VEXRole != "security-lead" {
		t.Errorf("QueryVulnerabilities did not override with local: %+v", listResp.Data)
	}

	projVulns, err = c.QueryProjectVulnerabilities(ctx, project, "")
	if err != nil {
		t.Fatalf("QueryProjectVulnerabilities failed: %v", err)
	}
	if len(projVulns) != 1 || projVulns[0].VEXStatus != models.VEXStatusAffected || projVulns[0].VEXRole != "security-lead" {
		t.Errorf("QueryProjectVulnerabilities did not override with local: %+v", projVulns)
	}
	if len(projVulns) == 1 && projVulns[0].VEXTimestamp != localTime.Format(time.RFC3339) {
		t.Errorf("expected winning local timestamp %s in project vulns, got %s", localTime.Format(time.RFC3339), projVulns[0].VEXTimestamp)
	}

	affected, err = c.QueryAffectedProjectsByCVE(ctx, vulnID, filter)
	if err != nil {
		t.Fatalf("QueryAffectedProjectsByCVE failed: %v", err)
	}
	if len(affected) != 1 || affected[0].VEXStatus != models.VEXStatusAffected {
		t.Errorf("QueryAffectedProjectsByCVE did not override with local: %+v", affected)
	}
}

func TestRetireRemovedUpstreamStatements(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	sbomID := uuid.New()
	purl := "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
	vulnID := fmt.Sprintf("CVE-2099-%s", sbomID.String()[:6])
	now := time.Now().UTC().Truncate(time.Second)

	retainedUpstreamID := uuid.New()
	staleUpstreamID := uuid.New()
	localID := uuid.New()

	stmts := []models.VEXStatement{
		{
			IngestedAt:    now,
			VEXID:         retainedUpstreamID,
			DocumentID:    "upstream-doc-keep",
			SourceFile:    "https://vex.example.com/keep.json",
			SBOMID:        sbomID.String(),
			ProductPURL:   purl,
			VulnID:        vulnID,
			Status:        models.VEXStatusNotAffected,
			Justification: models.VEXJustificationVulnerableCodeNotPresent,
			VEXTimestamp:  now,
			Author:        "Upstream Security Team",
			Role:          models.VEXRoleUpstream,
		},
		{
			IngestedAt:    now,
			VEXID:         staleUpstreamID,
			DocumentID:    "upstream-doc-stale",
			SourceFile:    "https://vex.example.com/stale.json",
			SBOMID:        sbomID.String(),
			ProductPURL:   purl,
			VulnID:        vulnID,
			Status:        models.VEXStatusNotAffected,
			Justification: models.VEXJustificationVulnerableCodeNotPresent,
			VEXTimestamp:  now,
			Author:        "Upstream Security Team",
			Role:          models.VEXRoleUpstream,
		},
		{
			IngestedAt:    now,
			VEXID:         localID,
			DocumentID:    "local-doc",
			SourceFile:    "local.openvex.json",
			SBOMID:        sbomID.String(),
			ProductPURL:   purl,
			VulnID:        vulnID,
			Status:        models.VEXStatusAffected,
			VEXTimestamp:  now,
			Author:        "Security Lead",
			Role:          "security-lead",
		},
	}

	if err := c.InsertVEXStatements(ctx, stmts); err != nil {
		t.Fatalf("InsertVEXStatements failed: %v", err)
	}

	t.Cleanup(func() {
		_ = c.Conn.Exec(context.Background(),
			"ALTER TABLE vex_statements DELETE WHERE toString(sbom_id) = ? SETTINGS mutations_sync = 1",
			sbomID.String())
	})

	activeIDs := map[uuid.UUID]struct{}{
		retainedUpstreamID: {},
	}

	if err := c.retireRemovedUpstreamStatements(ctx, activeIDs); err != nil {
		t.Fatalf("retireRemovedUpstreamStatements failed: %v", err)
	}

	var countRetained uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM vex_statements FINAL WHERE toString(vex_id) = ?", retainedUpstreamID.String()).Scan(&countRetained); err != nil {
		t.Fatalf("querying retained upstream statement: %v", err)
	}
	if countRetained != 1 {
		t.Errorf("expected retained upstream statement count = 1, got %d", countRetained)
	}

	var countStale uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM vex_statements FINAL WHERE toString(vex_id) = ?", staleUpstreamID.String()).Scan(&countStale); err != nil {
		t.Fatalf("querying stale upstream statement: %v", err)
	}
	if countStale != 0 {
		t.Errorf("expected stale upstream statement count = 0, got %d", countStale)
	}

	var countLocal uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM vex_statements FINAL WHERE toString(vex_id) = ?", localID.String()).Scan(&countLocal); err != nil {
		t.Fatalf("querying local statement: %v", err)
	}
	if countLocal != 1 {
		t.Errorf("expected local statement count = 1, got %d", countLocal)
	}
}
