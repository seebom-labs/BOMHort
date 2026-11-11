package clickhouse

import (
	"context"
	"fmt"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/advisory"
	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

// advisoryLookupChunk bounds the package keys sent in one lookup.
const advisoryLookupChunk = 1000

// LookupAdvisoryRecords returns the stored records of the given feeds that
// have an affected entry for any of keys. A record that no longer parses is
// skipped: one bad record must not cost an SBOM all its findings.
func (c *Client) LookupAdvisoryRecords(ctx context.Context, sources, keys []string) ([]advisory.StoredRecord, error) {
	if len(sources) == 0 || len(keys) == 0 {
		return nil, nil
	}
	var out []advisory.StoredRecord
	seen := map[string]struct{}{}
	for i := 0; i < len(keys); i += advisoryLookupChunk {
		chunk := keys[i:min(i+advisoryLookupChunk, len(keys))]
		rows, err := c.Conn.Query(ctx, `
			SELECT source, id, record_json
			FROM advisory_records FINAL
			WHERE source IN ? AND hasAny(package_keys, ?)
		`, sources, chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to query advisory records: %w", err)
		}
		for rows.Next() {
			var source, id, raw string
			if err := rows.Scan(&source, &id, &raw); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to scan advisory record: %w", err)
			}
			if raw == "" {
				continue // tombstone: the feed no longer publishes it
			}
			if _, dup := seen[source+"\x00"+id]; dup {
				continue
			}
			seen[source+"\x00"+id] = struct{}{}
			var rec osv.VulnEntry
			if err := json.Unmarshal([]byte(raw), &rec); err != nil {
				continue
			}
			out = append(out, advisory.StoredRecord{Source: source, Record: rec})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read advisory records: %w", err)
		}
	}
	return out, nil
}

// AdvisoryRecordVersions returns the stored modified time of every live
// record of one feed, so a sync fetches only what changed. The latest row
// per id wins (as FINAL would pick it); a tombstone (empty record_json, see
// advisory.Sync) hides the id, so a record published again is re-fetched.
func (c *Client) AdvisoryRecordVersions(ctx context.Context, source string) (map[string]time.Time, error) {
	rows, err := c.Conn.Query(ctx, `
		SELECT id, argMax(modified, synced_at) AS mod
		FROM advisory_records
		WHERE source = ?
		GROUP BY id
		HAVING argMax(record_json, synced_at) != ''
	`, source)
	if err != nil {
		return nil, fmt.Errorf("failed to query advisory record versions: %w", err)
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var id string
		var mod time.Time
		if err := rows.Scan(&id, &mod); err != nil {
			return nil, fmt.Errorf("failed to scan advisory record version: %w", err)
		}
		out[id] = mod.UTC()
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read advisory record versions: %w", err)
	}
	return out, nil
}

// advisoryComponents decodes vulnerabilities.component_location. A value
// that does not decode is dropped: it is display context, not the finding.
func advisoryComponents(raw string) []dto.AdvisoryComponent {
	if raw == "" {
		return nil
	}
	var out []dto.AdvisoryComponent
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// StoredFindingRow is one SBOM's copy of a finding, as reconciliation needs
// it: enough to close it, or to scope a VEX statement to that SBOM.
type StoredFindingRow struct {
	SBOMID         uuid.UUID
	PURL           string
	VulnID         string
	Aliases        []string
	AdvisorySource string
	AdvisoryStatus string
	Cluster        string
	Namespace      string
	Project        string
}

// QueryFindingsUnderPrefixes returns the stored findings whose PURL starts
// with any of the (lower-case) prefixes: the findings an authoritative feed
// may close. The path-boundary rule is applied by the caller.
func (c *Client) QueryFindingsUnderPrefixes(ctx context.Context, prefixes []string) ([]StoredFindingRow, error) {
	if len(prefixes) == 0 {
		return nil, nil
	}
	rows, err := c.Conn.Query(ctx, `
		SELECT sbom_id, purl, vuln_id, aliases, advisory_source, advisory_status,
			cluster, namespace, project
		FROM vulnerabilities FINAL
		WHERE arrayExists(p -> startsWith(lower(purl), p), ?)
	`, prefixes)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings under advisory prefixes: %w", err)
	}
	defer rows.Close()
	var out []StoredFindingRow
	for rows.Next() {
		var r StoredFindingRow
		if err := rows.Scan(&r.SBOMID, &r.PURL, &r.VulnID, &r.Aliases, &r.AdvisorySource, &r.AdvisoryStatus,
			&r.Cluster, &r.Namespace, &r.Project); err != nil {
			return nil, fmt.Errorf("failed to scan stored finding: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read stored findings: %w", err)
	}
	return out, nil
}

// closeFindingsChunk bounds the keys of one DELETE mutation.
const closeFindingsChunk = 1000

// CloseFindings removes the stored findings an authoritative feed now says
// are fixed, in every SBOM that carries them. keys are vuln_id + "\x00" +
// purl. Synchronous like the VEX rescue cleanup, so the next query no longer
// counts them.
func (c *Client) CloseFindings(ctx context.Context, keys []string) error {
	for i := 0; i < len(keys); i += closeFindingsChunk {
		chunk := keys[i:min(i+closeFindingsChunk, len(keys))]
		purls := make([]string, 0, len(chunk))
		for _, k := range chunk {
			if _, purl, ok := strings.Cut(k, "\x00"); ok {
				purls = append(purls, purl)
			}
		}
		if err := c.Conn.Exec(ctx,
			"ALTER TABLE vulnerabilities DELETE WHERE purl IN (?) AND concat(vuln_id, char(0), purl) IN (?) SETTINGS mutations_sync = 1",
			purls, chunk,
		); err != nil {
			return fmt.Errorf("failed to close fixed findings: %w", err)
		}
	}
	return nil
}
