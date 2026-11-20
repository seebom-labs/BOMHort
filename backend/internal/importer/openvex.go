package importer

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	json "github.com/goccy/go-json"
	"github.com/google/uuid"
)

const (
	openVEXContext = "https://openvex.dev/ns/v0.2.0"
	// importAuthor marks statements that came from another tool's analysis.
	importAuthor  = "imported"
	importTooling = "bomhort-import"
)

// errNoSerial is reported when an SBOM has analyses but no serialNumber to
// link the generated VEX document to.
var errNoSerial = errors.New("the SBOM has no serialNumber to link the VEX document to")

// stateStatus maps CycloneDX analysis states onto OpenVEX statuses.
// not_set, or a state the vocabulary does not have, is not imported.
var stateStatus = map[string]string{
	"not_affected":           "not_affected",
	"false_positive":         "not_affected",
	"resolved":               "fixed",
	"resolved_with_pedigree": "fixed",
	"exploitable":            "affected",
	"in_triage":              "under_investigation",
}

// justificationMap maps CycloneDX justifications onto the closest OpenVEX
// justification. The vocabularies do not line up one to one, so the original
// value is also kept in status_notes.
var justificationMap = map[string]string{
	"code_not_present":                "vulnerable_code_not_present",
	"code_not_reachable":              "vulnerable_code_not_in_execute_path",
	"requires_configuration":          "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_dependency":             "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_environment":            "vulnerable_code_cannot_be_controlled_by_adversary",
	"protected_by_compiler":           "inline_mitigations_already_exist",
	"protected_at_runtime":            "inline_mitigations_already_exist",
	"protected_at_perimeter":          "inline_mitigations_already_exist",
	"protected_by_mitigating_control": "inline_mitigations_already_exist",
}

type vexDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Tooling    string         `json:"tooling"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexVulnerability `json:"vulnerability"`
	Timestamp       string           `json:"timestamp"`
	Products        []vexProduct     `json:"products"`
	Status          string           `json:"status"`
	StatusNotes     string           `json:"status_notes,omitempty"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
}

type vexVulnerability struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

type vexProduct struct {
	ID            string         `json:"@id"`
	Subcomponents []vexComponent `json:"subcomponents"`
}

type vexComponent struct {
	ID string `json:"@id"`
}

// VEX is the OpenVEX document generated for one SBOM.
type VEX struct {
	// Data is the document; nil when there was nothing to import.
	Data []byte
	// ByStatus counts the statements per OpenVEX status.
	ByStatus map[string]int
	// Notes lists analyses that were not imported and why.
	Notes []string
	// DatedBySBOM counts the statements whose analysis records no time and
	// that carry the SBOM's metadata.timestamp instead.
	DatedBySBOM int
}

// Statements returns the number of statements in the document.
func (v VEX) Statements() int {
	n := 0
	for _, c := range v.ByStatus {
		n += c
	}
	return n
}

// BuildVEX turns the analyses of one SBOM into an OpenVEX document whose
// product is the SBOM's serialNumber. The worker resolves that against the
// stored document_namespace, so the statements are scoped to the SBOM
// whichever of the two is processed first.
//
// Every statement carries an explicit time, so the document timestamp that
// OpenVEX requires (the newest of them) is never what a statement falls back
// to, and an undated analysis never inherits another finding's date. The
// time is the analysis's own (lastUpdated, else firstIssued); an analysis
// that records none is dated by the SBOM it was exported with
// (metadata.timestamp: the assessment existed by then), which DatedBySBOM
// counts for the plan; without either it is skipped and noted.
//
// The output is a pure function of its input: no clock, no random IDs. @id is
// derived from the content, so uploading the same analyses again is a hash
// duplicate, while a changed analysis yields a new document.
func BuildVEX(serial string, analyses []Analysis, sbomTime time.Time) (VEX, error) {
	out := VEX{ByStatus: map[string]int{}}
	stmts := make([]vexStatement, 0, len(analyses))
	var latest time.Time
	for _, a := range analyses {
		at := a.Updated
		dated := false
		if at.IsZero() {
			if sbomTime.IsZero() {
				out.Notes = append(out.Notes, fmt.Sprintf("skipped %s: neither the analysis nor the SBOM (metadata.timestamp) records a time", a.VulnID))
				continue
			}
			at, dated = sbomTime, true
		}
		stmt, err := statement(serial, a, at)
		if err != nil {
			out.Notes = append(out.Notes, fmt.Sprintf("skipped %s: %v", a.VulnID, err))
			continue
		}
		if dated {
			out.DatedBySBOM++
		}
		if at.After(latest) {
			latest = at
		}
		stmts = append(stmts, stmt)
		out.ByStatus[stmt.Status]++
	}
	if len(stmts) == 0 {
		return out, nil
	}
	if strings.TrimSpace(serial) == "" {
		return out, errNoSerial
	}

	// Sources may list analyses in any order; sort on the encoded statement
	// (which starts with the vulnerability name) so the bytes do not depend
	// on it.
	keys := make([]string, len(stmts))
	order := make([]int, len(stmts))
	for i, s := range stmts {
		b, err := json.Marshal(s)
		if err != nil {
			return VEX{}, err
		}
		keys[i], order[i] = string(b), i
	}
	sort.Slice(order, func(i, j int) bool { return keys[order[i]] < keys[order[j]] })
	sorted := make([]vexStatement, len(stmts))
	body := []byte(serial + "\n")
	for i, idx := range order {
		sorted[i] = stmts[idx]
		body = append(body, keys[idx]...)
	}
	stmts = sorted
	doc := vexDocument{
		Context:    openVEXContext,
		ID:         "urn:uuid:" + uuid.NewSHA1(uuid.NameSpaceURL, body).String(),
		Author:     importAuthor,
		Timestamp:  latest.UTC().Format(time.RFC3339),
		Version:    1,
		Tooling:    importTooling,
		Statements: stmts,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return VEX{}, err
	}
	out.Data = append(data, '\n')
	return out, nil
}

// statement converts one analysis, dated at.
func statement(serial string, a Analysis, at time.Time) (vexStatement, error) {
	state := normalize(a.State)
	status, ok := stateStatus[state]
	if !ok {
		return vexStatement{}, fmt.Errorf("analysis state %q has no OpenVEX equivalent", a.State)
	}
	justification := normalize(a.Justification)
	responses := make([]string, 0, len(a.Responses))
	for _, r := range a.Responses {
		if r = normalize(r); r != "" {
			responses = append(responses, r)
		}
	}
	detail := strings.TrimSpace(a.Detail)

	purls := uniqueSorted(a.PURLs)
	subs := make([]vexComponent, len(purls))
	for i, p := range purls {
		subs[i] = vexComponent{ID: p}
	}

	stmt := vexStatement{
		Vulnerability: vexVulnerability{Name: a.VulnID, Aliases: uniqueSorted(a.Aliases)},
		Products:      []vexProduct{{ID: serial, Subcomponents: subs}},
		Status:        status,
		StatusNotes:   sourceNotes(state, justification, responses),
		Timestamp:     at.UTC().Format(time.RFC3339),
	}

	// OpenVEX requires a justification or an impact statement for
	// not_affected, and an action statement for affected.
	switch status {
	case "not_affected":
		stmt.Justification = justificationMap[justification]
		stmt.ImpactStatement = detail
		if stmt.Justification == "" && stmt.ImpactStatement == "" {
			stmt.ImpactStatement = "Marked " + state + " in the imported analysis."
		}
	case "affected":
		stmt.ActionStatement = detail
		if stmt.ActionStatement == "" {
			stmt.ActionStatement = "No action recorded in the imported analysis."
		}
	default:
		if detail != "" {
			stmt.StatusNotes += " " + detail
		}
	}
	return stmt, nil
}

// sourceNotes records the source analysis in its own vocabulary, so nothing
// is lost in the mapping.
func sourceNotes(state, justification string, responses []string) string {
	parts := []string{"state=" + state}
	if justification != "" {
		parts = append(parts, "justification="+justification)
	}
	if len(responses) > 0 {
		parts = append(parts, "response="+strings.Join(responses, ","))
	}
	return "Imported CycloneDX analysis: " + strings.Join(parts, ", ") + "."
}

func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
