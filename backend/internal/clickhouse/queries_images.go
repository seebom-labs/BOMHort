package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

var ErrImageNotFound = errors.New("image not found")

type ImageSBOMRef struct {
	SBOMID             uuid.UUID
	Cluster, Namespace string
	Project            string
	ImageRef           string
	Origin             string
}

func (c *Client) QueryImages(ctx context.Context, page, pageSize uint64) (*dto.PaginatedResponse[dto.ImageListItem], error) {
	if page == 0 {
		page = 1
	}
	var total uint64
	if err := c.Conn.QueryRow(ctx, "SELECT uniqExact(tuple(image_ref, image_digest)) FROM sboms FINAL WHERE image_digest != ''").Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count images: %w", err)
	}
	offset, ok := imagePageOffset(page, pageSize)
	if !ok {
		return &dto.PaginatedResponse[dto.ImageListItem]{Data: []dto.ImageListItem{}, Total: total, Page: page, PageSize: pageSize}, nil
	}
	rows, err := c.Conn.Query(ctx, `
		SELECT s.image_ref, s.image_digest, count(), max(s.ingested_at), min(s.ingested_at),
		       multiIf(max(ifNull(v.severity_rank, 0)) >= 5, 'CRITICAL',
		               max(ifNull(v.severity_rank, 0)) = 4, 'HIGH',
		               max(ifNull(v.severity_rank, 0)) = 3, 'MEDIUM',
		               max(ifNull(v.severity_rank, 0)) = 2, 'LOW',
		               max(ifNull(v.severity_rank, 0)) = 1, 'UNKNOWN', 'NONE')
		FROM (SELECT * FROM sboms FINAL) AS s
		LEFT JOIN (
			SELECT image_digest, max(multiIf(severity = 'CRITICAL', 5, severity = 'HIGH', 4,
				severity = 'MEDIUM', 3, severity = 'LOW', 2, 1)) AS severity_rank
			FROM vulnerabilities FINAL WHERE image_digest != '' GROUP BY image_digest
		) AS v ON s.image_digest = v.image_digest
		WHERE s.image_digest != ''
		GROUP BY s.image_ref, s.image_digest
		ORDER BY max(s.ingested_at) DESC, s.image_ref, s.image_digest
		LIMIT ? OFFSET ?`, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query images: %w", err)
	}
	defer rows.Close()
	items := make([]dto.ImageListItem, 0)
	for rows.Next() {
		var item dto.ImageListItem
		var lastSeen, firstSeen time.Time
		if err := rows.Scan(&item.ImageRef, &item.Digest, &item.SBOMCount, &lastSeen, &firstSeen, &item.WorstSeverity); err != nil {
			return nil, fmt.Errorf("failed to scan image: %w", err)
		}
		item.FirstSeenAt = firstSeen.Format(time.RFC3339)
		item.LastSeenAt = lastSeen.Format(time.RFC3339)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read images: %w", err)
	}
	return &dto.PaginatedResponse[dto.ImageListItem]{Data: items, Total: total, Page: page, PageSize: pageSize}, nil
}

func (c *Client) QueryImage(ctx context.Context, digest string, page, pageSize uint64) (*dto.ImageDetail, error) {
	if page == 0 {
		page = 1
	}
	var total uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL WHERE image_digest = ?", digest).Scan(&total); err != nil {
		return nil, fmt.Errorf("failed to count image SBOMs: %w", err)
	}
	if total == 0 {
		return nil, ErrImageNotFound
	}
	offset, ok := imagePageOffset(page, pageSize)
	if !ok {
		return &dto.ImageDetail{Digest: digest, SBOMs: []dto.ImageSBOM{}, Total: total, Page: page, PageSize: pageSize}, nil
	}
	rows, err := c.Conn.Query(ctx, `
		SELECT sbom_id, source_file, document_name, document_version, image_ref, origin,
		       cluster, namespace, project, ingested_at
		FROM sboms FINAL
		WHERE image_digest = ?
		ORDER BY ingested_at DESC
		LIMIT ? OFFSET ?`, digest, pageSize, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to query image %s: %w", digest, err)
	}
	defer rows.Close()
	detail := &dto.ImageDetail{Digest: digest, SBOMs: make([]dto.ImageSBOM, 0), Total: total, Page: page, PageSize: pageSize}
	for rows.Next() {
		var item dto.ImageSBOM
		var id uuid.UUID
		var ingestedAt time.Time
		if err := rows.Scan(&id, &item.SourceFile, &item.DocumentName, &item.DocumentVersion, &item.ImageRef, &item.Origin,
			&item.Cluster, &item.Namespace, &item.Project, &ingestedAt); err != nil {
			return nil, fmt.Errorf("failed to scan image SBOM: %w", err)
		}
		item.SBOMID = id.String()
		item.IngestedAt = ingestedAt.Format(time.RFC3339)
		detail.SBOMs = append(detail.SBOMs, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read image SBOMs: %w", err)
	}
	return detail, nil
}

func imagePageOffset(page, pageSize uint64) (uint64, bool) {
	if page == 0 || pageSize != 0 && page-1 > ^uint64(0)/pageSize {
		return 0, false
	}
	return (page - 1) * pageSize, true
}

func (c *Client) ImageExists(ctx context.Context, digest string) (bool, error) {
	var count uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL WHERE image_digest = ?", digest).Scan(&count); err != nil {
		return false, fmt.Errorf("failed to check image existence: %w", err)
	}
	return count > 0, nil
}

func (c *Client) QueryImageOwner(ctx context.Context, digest string) (*ImageSBOMRef, error) {
	var ref ImageSBOMRef
	err := c.Conn.QueryRow(ctx, `
		SELECT sbom_id, cluster, namespace, project, image_ref, origin
		FROM sboms FINAL
		WHERE image_digest = ?
		ORDER BY ingested_at DESC
		LIMIT 1`, digest).Scan(&ref.SBOMID, &ref.Cluster, &ref.Namespace, &ref.Project, &ref.ImageRef, &ref.Origin)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query image owner: %w", err)
	}
	return &ref, nil
}

func (c *Client) FindImageByDigest(ctx context.Context, digest string) (*ImageSBOMRef, error) {
	return c.QueryImageOwner(ctx, digest)
}

func (c *Client) FindSBOMByHash(ctx context.Context, hash string) (*ImageSBOMRef, error) {
	var ref ImageSBOMRef
	err := c.Conn.QueryRow(ctx, `
		SELECT sbom_id, cluster, namespace, project
		FROM sboms FINAL
		WHERE sha256_hash = ?
		ORDER BY ingested_at DESC
		LIMIT 1`, hash).Scan(&ref.SBOMID, &ref.Cluster, &ref.Namespace, &ref.Project)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query SBOM by content hash: %w", err)
	}
	return &ref, nil
}

func (c *Client) FindPendingImageJob(ctx context.Context, digest, imageRef, cluster, namespace, project, origin string) (*models.IngestionJob, error) {
	jobs, err := c.selectJobs(ctx,
		"latest_status IN ('pending', 'processing') AND image_digest = ? AND image_ref = ? AND cluster = ? AND namespace = ? AND project = ? AND origin = ?",
		1, digest, imageRef, cluster, namespace, project, origin)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending image job: %w", err)
	}
	if len(jobs) == 0 {
		return nil, nil
	}
	return &jobs[0], nil
}

func (c *Client) FindImageByDigestOwner(ctx context.Context, digest, imageRef, cluster, namespace, project, origin string) (*ImageSBOMRef, error) {
	var ref ImageSBOMRef
	err := c.Conn.QueryRow(ctx, `
		SELECT sbom_id, cluster, namespace, project, image_ref, origin
		FROM sboms FINAL
		WHERE image_digest = ? AND image_ref = ? AND cluster = ? AND namespace = ? AND project = ? AND origin = ?
		ORDER BY ingested_at DESC
		LIMIT 1`, digest, imageRef, cluster, namespace, project, origin).Scan(&ref.SBOMID, &ref.Cluster, &ref.Namespace, &ref.Project, &ref.ImageRef, &ref.Origin)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query image by ownership: %w", err)
	}
	return &ref, nil
}

// CloneImageSBOM reuses the already-parsed SBOM data for another ownership
// tuple. The deterministic target id makes retries replace partial child rows.
func (c *Client) CloneImageSBOM(ctx context.Context, source ImageSBOMRef, digest, imageRef, sourceRepo, sourceRef, cluster, namespace, project, parent, origin string, tags []string) (string, error) {
	identity, err := json.Marshal([]string{digest, imageRef, cluster, namespace, project, origin})
	if err != nil {
		return "", fmt.Errorf("failed to encode cloned image identity: %w", err)
	}
	targetID := uuid.NewSHA1(uuid.NameSpaceURL, identity)
	var sourceExists uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL WHERE sbom_id = ?", source.SBOMID).Scan(&sourceExists); err != nil {
		return "", fmt.Errorf("failed to verify source SBOM: %w", err)
	}
	if sourceExists == 0 {
		return "", ErrImageNotFound
	}
	cloneStatements := []struct {
		table string
		query string
		args  []any
	}{
		{"sbom_packages", `
			INSERT INTO sbom_packages (
				ingested_at, sbom_id, source_file, package_spdx_ids, package_names,
				package_versions, package_purls, package_licenses, package_license_sources,
				rel_source_indices, rel_target_indices, rel_types, package_depths,
				cluster, namespace, project, image_digest
			)
			SELECT now(), ?, source_file, package_spdx_ids, package_names,
			       package_versions, package_purls, package_licenses, package_license_sources,
			       rel_source_indices, rel_target_indices, rel_types, package_depths,
			       ?, ?, ?, ?
			FROM sbom_packages FINAL WHERE sbom_id = ?`,
			[]any{targetID, cluster, namespace, project, digest, source.SBOMID}},
		{"vulnerabilities", `
			INSERT INTO vulnerabilities (
				discovered_at, sbom_id, source_file, purl, vuln_id, severity, summary,
				affected_versions, fixed_version, osv_json, aliases, dependency_depth,
				advisory_source, advisory_status, component_location,
				cluster, namespace, project, image_digest,
				reachability, evidence_source, evidence_ref, evidence_at
			)
			SELECT now(), ?, source_file, purl, vuln_id, severity, summary,
			       affected_versions, fixed_version, osv_json, aliases, dependency_depth,
			       advisory_source, advisory_status, component_location,
			       ?, ?, ?, ?, reachability, evidence_source, evidence_ref, evidence_at
			FROM vulnerabilities FINAL WHERE sbom_id = ?`,
			[]any{targetID, cluster, namespace, project, digest, source.SBOMID}},
		{"license_compliance", `
			INSERT INTO license_compliance (
				checked_at, sbom_id, source_file, license_id, category, package_count,
				non_compliant_packages, exempted_packages, exemption_reason,
				cluster, namespace, project
			)
			SELECT now(), ?, source_file, license_id, category, package_count,
			       non_compliant_packages, exempted_packages, exemption_reason,
			       ?, ?, ?
			FROM license_compliance FINAL WHERE sbom_id = ?`,
			[]any{targetID, cluster, namespace, project, source.SBOMID}},
		{"document_store", `
			INSERT INTO document_store (
				stored_at, sbom_id, cluster, namespace, project, source_file,
				storage_backend, storage_ref, sha256_hash, size_bytes, content_type,
				content_encoding, stored_size_bytes
			)
			SELECT now(), ?, ?, ?, ?, source_file, storage_backend, storage_ref,
			       sha256_hash, size_bytes, content_type, content_encoding, stored_size_bytes
			FROM document_store FINAL WHERE sbom_id = ?`,
			[]any{targetID, cluster, namespace, project, source.SBOMID}},
	}
	for _, stmt := range cloneStatements {
		if err := c.Conn.Exec(ctx, stmt.query, stmt.args...); err != nil {
			return "", fmt.Errorf("failed to clone %s for image: %w", stmt.table, err)
		}
	}

	if err := c.cloneScopedVEX(ctx, source.SBOMID, targetID, cluster, namespace, project); err != nil {
		return "", err
	}

	if err := c.Conn.Exec(ctx, `
		INSERT INTO sboms (
			ingested_at, sbom_id, source_file, spdx_version, document_name, document_namespace,
			sha256_hash, creation_date, creator_tools, cluster, namespace, project,
			source_repo, source_ref, document_version, tags, parent, root_purl, supplier,
			origin, image_ref, image_digest, quality_score, quality_flags
		)
		SELECT now(), ?, source_file, spdx_version, document_name, document_namespace,
		       sha256_hash, creation_date, creator_tools, ?, ?, ?,
		       if(? != '', ?, source_repo), if(? != '', ?, source_ref),
		       document_version, arraySort(arrayDistinct(arrayConcat(tags, ?))),
		       if(? != '', ?, parent), root_purl, supplier, ?,
		       ?, ?, quality_score, quality_flags
		FROM sboms FINAL WHERE sbom_id = ?`,
		targetID, cluster, namespace, project,
		sourceRepo, sourceRepo, sourceRef, sourceRef, tags, parent, parent,
		origin, imageRef, digest, source.SBOMID); err != nil {
		return "", fmt.Errorf("failed to commit cloned SBOM metadata: %w", err)
	}
	var targetExists uint64
	if err := c.Conn.QueryRow(ctx, "SELECT count() FROM sboms FINAL WHERE sbom_id = ?", targetID).Scan(&targetExists); err != nil {
		return "", fmt.Errorf("failed to verify cloned SBOM: %w", err)
	}
	if targetExists == 0 {
		return "", ErrImageNotFound
	}
	return targetID.String(), nil
}

func (c *Client) cloneScopedVEX(ctx context.Context, sourceID, targetID uuid.UUID, cluster, namespace, project string) error {
	rows, err := c.Conn.Query(ctx, "SELECT DISTINCT vex_id FROM vex_statements FINAL WHERE sbom_id = ?", sourceID.String())
	if err != nil {
		return fmt.Errorf("failed to query source VEX statements: %w", err)
	}
	var oldIDs []uuid.UUID
	for rows.Next() {
		var oldID uuid.UUID
		if err := rows.Scan(&oldID); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan source VEX statement: %w", err)
		}
		oldIDs = append(oldIDs, oldID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to read source VEX statements: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close source VEX statements: %w", err)
	}
	for _, oldID := range oldIDs {
		newID := uuid.NewSHA1(targetID, oldID[:])
		if err := c.Conn.Exec(ctx, `
			INSERT INTO vex_statements (
				ingested_at, vex_id, document_id, source_file, sbom_id, product_ref,
				product_purl, vuln_id, status, justification, impact_statement,
				action_statement, vex_timestamp, author, role, tooling, status_notes,
				cluster, namespace, project
			)
			SELECT now(), ?, document_id, source_file, ?, product_ref, product_purl,
			       vuln_id, status, justification, impact_statement, action_statement,
			       vex_timestamp, author, role, tooling, status_notes, ?, ?, ?
			FROM vex_statements FINAL WHERE vex_id = ? AND sbom_id = ?`,
			newID, targetID.String(), cluster, namespace, project, oldID, sourceID.String()); err != nil {
			return fmt.Errorf("failed to clone scoped VEX statement: %w", err)
		}
	}
	return nil
}
