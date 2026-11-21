package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// LicenseRecheckState is the most recent license_recheck job in the queue.
// Its digest is the exceptions version the stored compliance rows were last
// brought up to (or are about to be, while it is pending).
type LicenseRecheckState struct {
	JobID  uuid.UUID
	Digest string
	Status string
	// UpdatedAt is when the job's latest status row was written.
	UpdatedAt time.Time
}

// LatestLicenseRecheck returns the newest license_recheck job, or nil if none
// was ever enqueued.
func (c *Client) LatestLicenseRecheck(ctx context.Context) (*LicenseRecheckState, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT job_id,
		       argMax(sha256_hash, created_at) AS digest,
		       argMax(status, created_at)      AS status,
		       max(created_at)                 AS updated_at
		FROM ingestion_queue
		WHERE job_type = ?
		GROUP BY job_id
		ORDER BY min(created_at) DESC, job_id DESC
		LIMIT 1`, models.JobTypeLicenseRecheck)
	if err != nil {
		return nil, fmt.Errorf("query latest license recheck: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var st LicenseRecheckState
	if err := rows.Scan(&st.JobID, &st.Digest, &st.Status, &st.UpdatedAt); err != nil {
		return nil, fmt.Errorf("scan latest license recheck: %w", err)
	}
	return &st, rows.Err()
}

// StoredLicenseCompliance is a license_compliance row together with the
// document name of its SBOM, which project-scoped exceptions match against.
type StoredLicenseCompliance struct {
	models.LicenseCompliance
	DocumentName          string
	RootPURL              string
	PackageNames          []string
	PackagePURLs          []string
	PackageLicenseSources []string
}

// EachLicenseCompliance streams the current license_compliance rows.
func (c *Client) EachLicenseCompliance(ctx context.Context, fn func(StoredLicenseCompliance) error) error {
	rows, err := c.Conn.Query(ctx, `
		SELECT lc.sbom_id, lc.source_file, lc.license_id, lc.category, lc.package_count,
		       lc.non_compliant_packages, lc.exempted_packages, lc.exemption_reason,
		       lc.cluster, lc.namespace, lc.project,
		       if(lc.category = 'permissive',
		           arrayMap(pair -> pair.1,
		               arrayFilter(pair -> pair.2 = lc.license_id,
		                   arrayZip(p.package_names, p.package_licenses, p.package_purls, p.package_license_sources))),
		           CAST([], 'Array(String)')) AS package_names,
		       if(lc.category = 'permissive',
		           arrayMap(pair -> pair.3,
		               arrayFilter(pair -> pair.2 = lc.license_id,
		                   arrayZip(p.package_names, p.package_licenses, p.package_purls, p.package_license_sources))),
		           CAST([], 'Array(String)')) AS package_purls,
		       if(lc.category = 'permissive',
		           arrayMap(pair -> pair.4,
		               arrayFilter(pair -> pair.2 = lc.license_id,
		                   arrayZip(p.package_names, p.package_licenses, p.package_purls, p.package_license_sources))),
		           CAST([], 'Array(String)')) AS package_license_sources,
		       s.root_purl, s.document_name
		FROM license_compliance AS lc FINAL
		LEFT JOIN (
		    SELECT sbom_id,
		           package_names,
		           arrayResize(package_licenses, length(package_names)) AS package_licenses,
		           arrayResize(package_purls, length(package_names)) AS package_purls,
		           arrayResize(package_license_sources, length(package_names)) AS package_license_sources
		    FROM sbom_packages FINAL
		) AS p ON p.sbom_id = lc.sbom_id
		LEFT JOIN (
		    SELECT sbom_id, any(document_name) AS document_name, any(root_purl) AS root_purl
		    FROM sboms
		    GROUP BY sbom_id
		) AS s ON s.sbom_id = lc.sbom_id`)
	if err != nil {
		return fmt.Errorf("query license compliance: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var r StoredLicenseCompliance
		if err := rows.Scan(&r.SBOMID, &r.SourceFile, &r.LicenseID, &r.Category, &r.PackageCount,
			&r.NonCompliantPackages, &r.ExemptedPackages, &r.ExemptionReason,
			&r.Cluster, &r.Namespace, &r.Project, &r.PackageNames, &r.PackagePURLs,
			&r.PackageLicenseSources, &r.RootPURL, &r.DocumentName); err != nil {
			return fmt.Errorf("scan license compliance: %w", err)
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}
