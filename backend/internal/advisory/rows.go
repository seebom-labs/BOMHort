package advisory

import (
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
	"github.com/seebom-labs/bomhort/backend/internal/osvutil"
	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// FromOSV wraps osv.dev hits as findings, for callers without feeds.
func FromOSV(purl string, hits []osv.VulnEntry) []Finding {
	out := make([]Finding, len(hits))
	for i, h := range hits {
		out[i] = Finding{PURL: purl, Entry: h, Source: OSVSource}
	}
	return out
}

// Vulnerability builds the vulnerabilities row of a finding for one SBOM.
func (f Finding) Vulnerability(sbomID uuid.UUID, sourceFile string, depth uint16) models.Vulnerability {
	v := osvutil.BuildVulnerability(f.Entry, sbomID, sourceFile, f.PURL, depth)
	v.AdvisorySource = f.Source
	if v.AdvisorySource == "" {
		v.AdvisorySource = OSVSource
	}
	v.AdvisoryStatus = f.Status
	if f.Source != OSVSource && f.Source != "" {
		// The feed's fixed version is the one that applies to this
		// package: osv.dev's is the upstream fix, which a distro may
		// never ship under that version string.
		v.FixedVersion = f.FixedVersion
	}
	if len(f.Components) > 0 {
		if raw, err := json.Marshal(f.Components); err == nil {
			v.ComponentLocation = string(raw)
		}
	}
	return v
}

// vexNamespace derives stable statement ids: re-deriving a statement on the
// next refresh replaces it instead of adding a duplicate.
var vexNamespace = uuid.MustParse("6f3c1d52-5c1e-4c7e-9b8a-2a4f0e1d9c11")

// NotAffectedStatement is the VEX statement that records a feed's
// "not affected" verdict, so the finding is suppressed by the same rules as
// any OpenVEX statement. ok is false for any other status.
func (f Finding) NotAffectedStatement(v models.Vulnerability) (models.VEXStatement, bool) {
	if f.Status != StatusNotAffected || f.Source == "" || f.Source == OSVSource {
		return models.VEXStatement{}, false
	}
	ts := time.Now().UTC()
	if t, ok := parseTime(f.Entry.Modified); ok {
		ts = t
	}
	sbom := v.SBOMID.String()
	return models.VEXStatement{
		IngestedAt:      time.Now(),
		VEXID:           uuid.NewSHA1(vexNamespace, []byte(f.Source+"\x00"+sbom+"\x00"+v.PURL+"\x00"+v.VulnID)),
		DocumentID:      "advisory:" + f.Source,
		SourceFile:      "advisory:" + f.Source,
		SBOMID:          sbom,
		ProductPURL:     v.PURL,
		VulnID:          v.VulnID,
		Status:          models.VEXStatusNotAffected,
		ImpactStatement: "Advisory feed " + f.Source + " reports this package as not affected.",
		VEXTimestamp:    ts,
		Author:          f.Source,
		Role:            "advisory-feed",
		Tooling:         "bomhort advisory feed",
		Cluster:         v.Cluster,
		Namespace:       v.Namespace,
		Project:         v.Project,
	}, true
}
