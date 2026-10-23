package osvutil

import (
	"time"

	"github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// BuildVulnerability turns a hydrated OSV entry into the row both the parsing
// worker and the cve-refresher insert. Callers must only pass entries that
// hydration actually returned: a stub without severity/aliases would be
// deduplicated on (vuln_id, purl) forever and never repaired (#485).
func BuildVulnerability(entry osv.VulnEntry, sbomID uuid.UUID, sourceFile, purl string, depth uint16) models.Vulnerability {
	rawJSON, _ := json.Marshal(entry)
	return models.Vulnerability{
		DiscoveredAt:     time.Now(),
		SBOMID:           sbomID,
		SourceFile:       sourceFile,
		PURL:             purl,
		VulnID:           entry.ID,
		Severity:         ClassifySeverity(entry),
		Summary:          entry.Summary,
		Aliases:          entry.Aliases,
		AffectedVersions: ExtractAffectedVersions(entry),
		FixedVersion:     ExtractFixedVersion(entry),
		OSVJSON:          string(rawJSON),
		DependencyDepth:  depth,
	}
}
