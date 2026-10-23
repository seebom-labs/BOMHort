package clickhouse

import (
	"context"
	"fmt"
	"log"

	"github.com/seebom-labs/bomhort/backend/internal/depgraph"
	"github.com/seebom-labs/bomhort/backend/internal/license"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// scopeBatchSize is how many SBOMs one batched query covers. It keeps the
// interpolated `sbom_id IN (...)` lists far below ClickHouse's max_query_size
// (256 KiB: a single list of every violating SBOM failed with a syntax error
// at position 262108 in production); 1000 ids are ~40 KiB per list. Measured
// on 6000 SBOMs, batches of 200 were ~40% slower than 1000 (per-query overhead).
const scopeBatchSize = 1000

// violationsQuery lists non-compliant license rows, ordered by SBOM so a
// caller can finish one SBOM before the next starts. %s is empty or an
// `AND sbom_id IN (?)` filter, applied to both sides of the JOIN; all three
// tables are ordered by sbom_id, so a filtered query reads only those ranges.
// Only document_name is taken from sboms: the right side of a JOIN is built
// in memory, and `SELECT *` would load every sboms column for it.
const violationsQuery = `
	SELECT
		lc.sbom_id,
		lc.source_file,
		ifNull(s.document_name, lc.source_file) AS document_name,
		lc.license_id,
		lc.category,
		lc.package_count,
		lc.non_compliant_packages
	FROM (SELECT * FROM license_compliance FINAL WHERE category IN ('copyleft', 'unapproved', 'unknown') %[1]s) AS lc
	LEFT JOIN (SELECT sbom_id, document_name FROM sboms FINAL WHERE 1 %[1]s) AS s ON s.sbom_id = lc.sbom_id
	ORDER BY lc.sbom_id, lc.license_id
`

// violatingSBOMsQuery lists the SBOMs violationsQuery can return, in the same
// order.
const violatingSBOMsQuery = `
	SELECT toString(sbom_id)
	FROM license_compliance FINAL
	WHERE category IN ('copyleft', 'unapproved', 'unknown')
	GROUP BY sbom_id
	ORDER BY sbom_id
`

// violatingSBOMsSearchQuery narrows violatingSBOMsQuery to SBOMs whose
// project, document name or source file contains the term (#492): the
// unfiltered summary is 8 MB on a 13k-SBOM instance, too much to filter in
// the browser.
const violatingSBOMsSearchQuery = `
	SELECT toString(lc.sbom_id)
	FROM license_compliance AS lc FINAL
	INNER JOIN (
		SELECT sbom_id FROM sboms FINAL
		WHERE positionCaseInsensitive(project, ?) > 0
		   OR positionCaseInsensitive(document_name, ?) > 0
		   OR positionCaseInsensitive(source_file, ?) > 0
	) AS s ON s.sbom_id = lc.sbom_id
	WHERE lc.category IN ('copyleft', 'unapproved', 'unknown')
	GROUP BY lc.sbom_id
	ORDER BY lc.sbom_id
`

// violationRow is one row of violationsQuery.
type violationRow struct {
	sbomID, sourceFile, documentName string
	licenseID, category              string
	packages                         []string
}

// sbomViolations is the exception-filtered aggregate of one SBOM's rows.
type sbomViolations struct {
	sbomID       string
	sourceFile   string
	documentName string
	copyleft     uint64
	unapproved   uint64
	unknown      uint64
	licenses     []string
	packages     []string
}

// violationAccumulator folds rows ordered by SBOM into one sbomViolations per
// SBOM, dropping what the exceptions cover. emit is called once per SBOM that
// still has a violating package, as soon as its last row has been seen, so a
// streaming caller holds one SBOM's package names at a time.
type violationAccumulator struct {
	exceptions *license.ExceptionIndex
	emit       func(*sbomViolations) error
	current    *sbomViolations
}

func (a *violationAccumulator) add(r violationRow) error {
	if a.current != nil && a.current.sbomID != r.sbomID {
		if err := a.flush(); err != nil {
			return err
		}
	}

	if a.exceptions != nil {
		if exempt, _ := a.exceptions.IsExempt("", r.licenseID); exempt {
			return nil
		}
	}
	var violating []string
	for _, pkg := range r.packages {
		if a.exceptions != nil {
			if exempt, _ := a.exceptions.IsExempt(pkg, r.licenseID, r.documentName); exempt {
				continue
			}
		}
		violating = append(violating, pkg)
	}
	if len(violating) == 0 {
		return nil
	}

	if a.current == nil {
		a.current = &sbomViolations{sbomID: r.sbomID, sourceFile: r.sourceFile, documentName: r.documentName}
	}
	e := a.current
	switch r.category {
	case "copyleft":
		e.copyleft += uint64(len(violating))
	case "unapproved":
		e.unapproved += uint64(len(violating))
	default:
		e.unknown += uint64(len(violating))
	}
	if !containsString(e.licenses, r.licenseID) {
		e.licenses = append(e.licenses, r.licenseID)
	}
	// Deduplicated per license row, not per SBOM: a package listed under two
	// licenses is listed twice, as it always has been.
	seen := make(map[string]bool, len(violating))
	for _, pkg := range violating {
		if !seen[pkg] && pkg != "" {
			seen[pkg] = true
			e.packages = append(e.packages, pkg)
		}
	}
	return nil
}

// flush emits the SBOM in progress, if any.
func (a *violationAccumulator) flush() error {
	e := a.current
	a.current = nil
	if e == nil {
		return nil
	}
	return a.emit(e)
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// scanLicenseViolations runs violationsQuery — over every SBOM when ids is
// nil, otherwise over those SBOMs only — and feeds every row through the
// accumulator; emit sees each SBOM with at least one violating package once,
// in sbom_id order. emit runs while the rows are still open: it must not
// query ClickHouse itself.
func (c *Client) scanLicenseViolations(ctx context.Context, exceptions *license.ExceptionIndex, ids []string, emit func(*sbomViolations) error) error {
	query, args := fmt.Sprintf(violationsQuery, ""), []any(nil)
	if ids != nil {
		query, args = fmt.Sprintf(violationsQuery, "AND sbom_id IN (?)"), []any{ids, ids}
	}
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to query license violations: %w", err)
	}
	defer rows.Close()

	acc := &violationAccumulator{exceptions: exceptions, emit: emit}
	for rows.Next() {
		var r violationRow
		var packageCount uint32
		if err := rows.Scan(&r.sbomID, &r.sourceFile, &r.documentName, &r.licenseID, &r.category, &packageCount, &r.packages); err != nil {
			return fmt.Errorf("failed to scan violation row: %w", err)
		}
		if err := acc.add(r); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return acc.flush()
}

// violatingSBOMs returns the ids of all SBOMs with a non-compliant license row,
// before exceptions are applied.
func (c *Client) violatingSBOMs(ctx context.Context, search string) ([]string, error) {
	query, args := violatingSBOMsQuery, []any{}
	if search != "" {
		query, args = violatingSBOMsSearchQuery, []any{search, search, search}
	}
	rows, err := c.Conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query violating sboms: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan violating sbom: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// QueryProjectsWithLicenseViolations finds all SBOMs that have copyleft, unapproved or unknown licenses,
// excluding any licenses/packages covered by exceptions.
//
// Every package name is part of the response, so the whole result is held in
// memory; on a large instance that is tens of megabytes. Pages that only show
// counts use QueryProjectLicenseViolationSummaries.
func (c *Client) QueryProjectsWithLicenseViolations(ctx context.Context, exceptions *license.ExceptionIndex) ([]dto.ProjectLicenseViolation, error) {
	var all []*sbomViolations
	err := c.scanLicenseViolations(ctx, exceptions, nil, func(e *sbomViolations) error {
		all = append(all, e)
		return nil
	})
	if err != nil {
		return nil, err
	}

	ids := make([]string, 0, len(all))
	for _, e := range all {
		ids = append(ids, e.sbomID)
	}
	scopes, err := c.violationScopesFor(ctx, ids)
	if err != nil {
		log.Printf("WARNING: package scopes for license violations: %v", err)
	}

	items := make([]dto.ProjectLicenseViolation, 0, len(all))
	for _, e := range all {
		items = append(items, dto.ProjectLicenseViolation{
			SBOMID:               e.sbomID,
			SourceFile:           e.sourceFile,
			DocumentName:         e.documentName,
			CopyleftCount:        e.copyleft,
			UnapprovedCount:      e.unapproved,
			UnknownCount:         e.unknown,
			ViolatingLicenses:    e.licenses,
			NonCompliantPackages: e.packages,
			PackageScopes:        pickScopes(scopes[e.sbomID], e.packages),
		})
	}
	return items, nil
}

// QueryProjectLicenseViolationSummaries is QueryProjectsWithLicenseViolations
// without the package lists: per SBOM the counts, the licenses and how many
// non-compliant packages are direct or transitive dependencies. SBOMs are
// read in batches of scopeBatchSize — violations, then their scopes — so
// memory is bounded by one batch, not by the instance, and only one query is
// open at a time. search, when non-empty, keeps only SBOMs whose project,
// document name or source file contains it (case-insensitive).
func (c *Client) QueryProjectLicenseViolationSummaries(ctx context.Context, exceptions *license.ExceptionIndex, search string) ([]dto.ProjectLicenseViolationSummary, error) {
	ids, err := c.violatingSBOMs(ctx, search)
	if err != nil {
		return nil, err
	}

	items := []dto.ProjectLicenseViolationSummary{}
	scopesFailed := false
	for _, chunk := range chunkStrings(ids, scopeBatchSize) {
		var batch []*sbomViolations
		err := c.scanLicenseViolations(ctx, exceptions, chunk, func(e *sbomViolations) error {
			batch = append(batch, e)
			return nil
		})
		if err != nil {
			return nil, err
		}

		var scopes map[string]map[string]string
		if !scopesFailed && len(batch) > 0 {
			batchIDs := make([]string, 0, len(batch))
			for _, e := range batch {
				batchIDs = append(batchIDs, e.sbomID)
			}
			scopes, err = c.violationScopesFor(ctx, batchIDs)
			if err != nil {
				// Best effort, as in the full listing; one warning, not one per batch.
				log.Printf("WARNING: package scopes for license violation summaries: %v", err)
				scopesFailed = true
			}
		}
		for _, e := range batch {
			items = append(items, summarizeViolations(e, scopes[e.sbomID]))
		}
	}
	return items, nil
}

// chunkStrings splits list into consecutive chunks of at most size elements.
func chunkStrings(list []string, size int) [][]string {
	var chunks [][]string
	for start := 0; start < len(list); start += size {
		chunks = append(chunks, list[start:min(start+size, len(list))])
	}
	return chunks
}

// summarizeViolations reduces one SBOM's violations to counts. scopes maps
// package name → scope; packages without an entry count as neither direct
// nor transitive.
func summarizeViolations(e *sbomViolations, scopes map[string]string) dto.ProjectLicenseViolationSummary {
	s := dto.ProjectLicenseViolationSummary{
		SBOMID:                   e.sbomID,
		SourceFile:               e.sourceFile,
		DocumentName:             e.documentName,
		CopyleftCount:            e.copyleft,
		UnapprovedCount:          e.unapproved,
		UnknownCount:             e.unknown,
		ViolatingLicenses:        e.licenses,
		NonCompliantPackageCount: uint64(len(e.packages)),
	}
	for _, pkg := range e.packages {
		switch scopes[pkg] {
		case depgraph.ScopeDirect:
			s.DirectCount++
		case depgraph.ScopeTransitive:
			s.TransitiveCount++
		}
	}
	return s
}

// violationScopesQuery returns, per SBOM, only the packages that appear in
// one of its violating license_compliance rows, each with its nearest depth.
// The narrowing happens in ClickHouse: sbom_packages holds every package of
// an SBOM, and shipping all of them to the gateway to keep a few was most of
// the endpoint's time. The (sbom_id, name) IN subquery is a hash lookup;
// has() over the wanted names per package was measured ~10x slower.
// arrayResize pads short depth arrays with depgraph.Unknown (65535), as
// depgraph.DepthOf does.
const violationScopesQuery = `
	SELECT toString(sbom_id), groupArray(name), groupArray(depth)
	FROM (
		SELECT sbom_id, name, min(depth) AS depth
		FROM (
			SELECT sbom_id, package_names, arrayResize(package_depths, length(package_names), 65535) AS depths
			FROM sbom_packages FINAL
			WHERE sbom_id IN (?) AND notEmpty(package_depths)
		)
		ARRAY JOIN package_names AS name, depths AS depth
		WHERE (sbom_id, name) IN (
			SELECT sbom_id, arrayJoin(non_compliant_packages)
			FROM license_compliance FINAL
			WHERE sbom_id IN (?) AND category IN ('copyleft', 'unapproved', 'unknown')
		)
		GROUP BY sbom_id, name
	)
	GROUP BY sbom_id
`

// violationScopesFor returns, per SBOM id, the scope of each package named in
// its violating license rows, in batches of scopeBatchSize SBOMs. SBOMs
// without recorded depths (ingested before migration 025) are absent.
func (c *Client) violationScopesFor(ctx context.Context, ids []string) (map[string]map[string]string, error) {
	out := make(map[string]map[string]string, len(ids))
	for _, chunk := range chunkStrings(ids, scopeBatchSize) {
		if err := c.violationScopesBatch(ctx, chunk, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (c *Client) violationScopesBatch(ctx context.Context, ids []string, out map[string]map[string]string) error {
	rows, err := c.Conn.Query(ctx, violationScopesQuery, ids, ids)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var names []string
		var depths []uint16
		if err := rows.Scan(&id, &names, &depths); err != nil {
			return err
		}
		if m := packageScopes(names, depths); m != nil {
			out[id] = m
		}
	}
	return rows.Err()
}

// packageScopesFor returns, per SBOM id, the scope of each wanted package
// name, derived from sbom_packages.package_depths. Only wanted names are kept,
// so the result is as large as the input, not as the SBOMs. SBOMs without
// recorded depths (ingested before migration 025) are absent. The lookup runs
// in batches of scopeBatchSize SBOMs.
func (c *Client) packageScopesFor(ctx context.Context, want map[string][]string) (map[string]map[string]string, error) {
	out := make(map[string]map[string]string, len(want))
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	for _, chunk := range chunkStrings(ids, scopeBatchSize) {
		if err := c.packageScopesBatch(ctx, chunk, want, out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (c *Client) packageScopesBatch(ctx context.Context, ids []string, want map[string][]string, out map[string]map[string]string) error {
	rows, err := c.Conn.Query(ctx, `
		SELECT toString(sbom_id), package_names, package_depths
		FROM sbom_packages FINAL
		WHERE sbom_id IN (?) AND notEmpty(package_depths)
	`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var names []string
		var depths []uint16
		if err := rows.Scan(&id, &names, &depths); err != nil {
			return err
		}
		if m := pickScopes(packageScopes(names, depths), want[id]); m != nil {
			out[id] = m
		}
	}
	return rows.Err()
}
