package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// InsertSBOM inserts a single SBOM metadata row.
func (c *Client) InsertSBOM(ctx context.Context, sbom *models.SBOM) error {
	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO sboms (
			ingested_at, sbom_id, source_file, spdx_version,
			document_name, document_namespace, sha256_hash,
			creation_date, creator_tools, cluster, namespace, project,
			source_repo, source_ref, document_version, tags
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare sbom batch: %w", err)
	}

	if err := batch.Append(
		sbom.IngestedAt,
		sbom.SBOMID,
		sbom.SourceFile,
		sbom.SPDXVersion,
		sbom.DocumentName,
		sbom.DocumentNamespace,
		sbom.SHA256Hash,
		sbom.CreationDate,
		sbom.CreatorTools,
		sbom.Cluster,
		sbom.Namespace,
		sbom.Project,
		sbom.SourceRepo,
		sbom.SourceRef,
		sbom.DocumentVersion,
		sbom.Tags,
	); err != nil {
		return fmt.Errorf("failed to append sbom: %w", err)
	}

	return batch.Send()
}

// InsertSBOMPackages inserts the parallel-array package row for an SBOM.
func (c *Client) InsertSBOMPackages(ctx context.Context, pkg *models.SBOMPackages) error {
	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO sbom_packages (
			ingested_at, sbom_id, source_file,
			package_spdx_ids, package_names, package_versions,
			package_purls, package_licenses,
			rel_source_indices, rel_target_indices, rel_types,
			cluster, namespace, project
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare sbom_packages batch: %w", err)
	}

	if err := batch.Append(
		pkg.IngestedAt,
		pkg.SBOMID,
		pkg.SourceFile,
		pkg.PackageSPDXIDs,
		pkg.PackageNames,
		pkg.PackageVersions,
		pkg.PackagePURLs,
		pkg.PackageLicenses,
		pkg.RelSourceIndices,
		pkg.RelTargetIndices,
		pkg.RelTypes,
		pkg.Cluster,
		pkg.Namespace,
		pkg.Project,
	); err != nil {
		return fmt.Errorf("failed to append sbom_packages: %w", err)
	}

	return batch.Send()
}

// InsertVulnerabilities batch-inserts vulnerability rows for an SBOM.
func (c *Client) InsertVulnerabilities(ctx context.Context, vulns []models.Vulnerability) error {
	if len(vulns) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO vulnerabilities (
			discovered_at, sbom_id, source_file, purl, vuln_id,
			severity, summary, affected_versions, fixed_version, osv_json, aliases,
			cluster, namespace, project
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare vulnerabilities batch: %w", err)
	}

	for _, v := range vulns {
		if err := batch.Append(
			v.DiscoveredAt,
			v.SBOMID,
			v.SourceFile,
			v.PURL,
			v.VulnID,
			v.Severity,
			v.Summary,
			v.AffectedVersions,
			v.FixedVersion,
			v.OSVJSON,
			v.Aliases,
			v.Cluster,
			v.Namespace,
			v.Project,
		); err != nil {
			return fmt.Errorf("failed to append vulnerability %s: %w", v.VulnID, err)
		}
	}

	return batch.Send()
}

// InsertLicenseCompliance batch-inserts license compliance rows for an SBOM.
func (c *Client) InsertLicenseCompliance(ctx context.Context, items []models.LicenseCompliance) error {
	if len(items) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO license_compliance (
			checked_at, sbom_id, source_file, license_id,
			category, package_count, non_compliant_packages,
			exempted_packages, exemption_reason,
			cluster, namespace, project
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare license_compliance batch: %w", err)
	}

	now := time.Now()
	for _, item := range items {
		exempted := item.ExemptedPackages
		if exempted == nil {
			exempted = []string{}
		}
		if err := batch.Append(
			now,
			item.SBOMID,
			item.SourceFile,
			item.LicenseID,
			item.Category,
			item.PackageCount,
			item.NonCompliantPackages,
			exempted,
			item.ExemptionReason,
			item.Cluster,
			item.Namespace,
			item.Project,
		); err != nil {
			return fmt.Errorf("failed to append license_compliance: %w", err)
		}
	}

	return batch.Send()
}

// InsertVEXStatements batch-inserts VEX statement rows.
func (c *Client) InsertVEXStatements(ctx context.Context, stmts []models.VEXStatement) error {
	if len(stmts) == 0 {
		return nil
	}

	batch, err := c.Conn.PrepareBatch(ctx,
		`INSERT INTO vex_statements (
			ingested_at, vex_id, document_id, source_file, sbom_id,
			product_ref, product_purl, vuln_id, status, justification,
			impact_statement, action_statement, vex_timestamp,
			author, role, tooling, status_notes,
			cluster, namespace, project
		)`)
	if err != nil {
		return fmt.Errorf("failed to prepare vex_statements batch: %w", err)
	}

	for _, s := range stmts {
		if err := batch.Append(
			s.IngestedAt,
			s.VEXID,
			s.DocumentID,
			s.SourceFile,
			s.SBOMID,
			s.ProductRef,
			s.ProductPURL,
			s.VulnID,
			s.Status,
			s.Justification,
			s.ImpactStatement,
			s.ActionStatement,
			s.VEXTimestamp,
			s.Author,
			s.Role,
			s.Tooling,
			s.StatusNotes,
			s.Cluster,
			s.Namespace,
			s.Project,
		); err != nil {
			return fmt.Errorf("failed to append vex_statement: %w", err)
		}
	}

	return batch.Send()
}
