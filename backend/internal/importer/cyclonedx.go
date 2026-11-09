package importer

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	json "github.com/goccy/go-json"
)

// errNotCycloneDX marks a JSON document that is not a CycloneDX BOM.
var errNotCycloneDX = errors.New("not a CycloneDX document")

// cdxDocument is the part of a CycloneDX JSON document the importer reads:
// the serial number that links the generated VEX to the SBOM, the components
// that turn a bom-ref into a purl, and the vulnerabilities with their
// analysis. Everything else is uploaded as is and parsed by the worker.
type cdxDocument struct {
	BOMFormat    string `json:"bomFormat"`
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Component *cdxComponent `json:"component"`
	} `json:"metadata"`
	Components      []cdxComponent     `json:"components"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	Name       string         `json:"name"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

type cdxVulnerability struct {
	ID         string `json:"id"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Analysis *cdxAnalysis `json:"analysis"`
	Affects  []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type cdxAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification"`
	Response      []string `json:"response"`
	Detail        string   `json:"detail"`
	FirstIssued   string   `json:"firstIssued"`
	LastUpdated   string   `json:"lastUpdated"`
}

// parseCycloneDX decodes data and checks that it is a CycloneDX BOM.
func parseCycloneDX(data []byte) (*cdxDocument, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	if !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return nil, errNotCycloneDX
	}
	return &doc, nil
}

// name is the project name mapping entries match on: the root component's
// name, or "" when the document does not name one.
func (d *cdxDocument) name() string {
	if d.Metadata.Component == nil {
		return ""
	}
	return strings.TrimSpace(d.Metadata.Component.Name)
}

// analyses returns the triage decisions recorded in the document. A
// vulnerability without an analysis state is a finding, not a decision, and
// is left out: BOMHort computes findings itself. notes lists what could not be
// imported and why.
func (d *cdxDocument) analyses() (out []Analysis, notes []string) {
	purls := make(map[string]string)
	var index func([]cdxComponent)
	index = func(cs []cdxComponent) {
		for _, c := range cs {
			if c.BOMRef != "" && c.PURL != "" {
				purls[c.BOMRef] = c.PURL
			}
			index(c.Components)
		}
	}
	if d.Metadata.Component != nil {
		index([]cdxComponent{*d.Metadata.Component})
	}
	index(d.Components)

	for _, v := range d.Vulnerabilities {
		if v.Analysis == nil || strings.TrimSpace(v.Analysis.State) == "" {
			continue
		}
		id := strings.TrimSpace(v.ID)
		if id == "" {
			notes = append(notes, "skipped an analysis without a vulnerability id")
			continue
		}
		a := Analysis{
			VulnID:        id,
			State:         v.Analysis.State,
			Justification: v.Analysis.Justification,
			Responses:     v.Analysis.Response,
			Detail:        v.Analysis.Detail,
			Updated:       latestTime(v.Analysis.LastUpdated, v.Analysis.FirstIssued),
		}
		for _, r := range v.References {
			if ref := strings.TrimSpace(r.ID); ref != "" && ref != id {
				a.Aliases = append(a.Aliases, ref)
			}
		}
		for _, af := range v.Affects {
			if p := resolveRef(af.Ref, purls); p != "" {
				a.PURLs = append(a.PURLs, p)
				continue
			}
			notes = append(notes, fmt.Sprintf("%s: affected component %q has no purl", id, af.Ref))
		}
		if len(a.PURLs) == 0 {
			notes = append(notes, fmt.Sprintf("skipped %s: no affected component with a purl", id))
			continue
		}
		out = append(out, a)
	}
	return out, notes
}

// resolveRef turns an affects[].ref into the component's purl. The ref is a
// bom-ref, possibly written as a BOM-Link (urn:cdx:serial/version#bom-ref). A
// ref that is not a known bom-ref but is itself a purl is used as is: some
// producers use the purl as the bom-ref and omit the component list.
func resolveRef(ref string, purls map[string]string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "urn:cdx:") {
		if i := strings.IndexByte(ref, '#'); i >= 0 {
			ref = ref[i+1:]
			if unescaped, err := url.PathUnescape(ref); err == nil {
				ref = unescaped
			}
		}
	}
	if p, ok := purls[ref]; ok {
		return p
	}
	if strings.HasPrefix(ref, "pkg:") {
		return ref
	}
	return ""
}

// latestTime returns the later of the parseable timestamps, or the zero time.
func latestTime(values ...string) time.Time {
	var latest time.Time
	for _, v := range values {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
		if err == nil && t.After(latest) {
			latest = t
		}
	}
	return latest
}
