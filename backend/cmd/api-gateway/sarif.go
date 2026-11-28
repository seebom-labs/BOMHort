package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/seebom-labs/bomhort/backend/pkg/dto"
)

var version = "dev"

const (
	sarifSchemaVersion = "2.1.0"
	sarifSchemaURI     = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	sarifToolName      = "BOMHort"
	sarifInfoURI       = "https://github.com/seebom-labs/BOMHort"
	sarifContentType   = "application/sarif+json"
)

// SARIFLog represents the top-level SARIF 2.1.0 document.
type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single static analysis run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the tool driver component.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule describes a vulnerability rule.
type SARIFRule struct {
	ID               string                         `json:"id"`
	ShortDescription *SARIFMultiformatMessageString `json:"shortDescription,omitempty"`
	HelpURI          string                         `json:"helpUri,omitempty"`
	Properties       map[string]interface{}         `json:"properties,omitempty"`
}

// SARIFMultiformatMessageString encapsulates formatted or plain text messages.
type SARIFMultiformatMessageString struct {
	Text string `json:"text"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID          string                        `json:"ruleId"`
	Level           string                        `json:"level,omitempty"`
	CorrelationGUID string                        `json:"correlationGuid,omitempty"`
	Message         SARIFMultiformatMessageString `json:"message"`
	Locations       []SARIFLocation               `json:"locations,omitempty"`
	Properties      map[string]interface{}        `json:"properties,omitempty"`
	Suppressions    []SARIFSuppression            `json:"suppressions,omitempty"`
}

// SARIFLocation describes the physical location of a finding.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation describes the file or artifact.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation specifies the URI of the artifact.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFSuppression records a suppression (e.g. from VEX).
type SARIFSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "none"
	}
}

func severityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// stableCorrelationGUID generates a deterministic GUID for a finding based on
// its vulnerability identifier and target package URL.
func stableCorrelationGUID(ruleID, purl string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(ruleID+":"+purl)).String()
}

// cleanArtifactLocation extracts a stable repository-relative path from a
// finding's source file path. Pushed upload prefixes (such as pushed/<uuid>-...)
// and S3 push URI prefixes are stripped so the result corresponds to the file
// within the repository checkout. If no valid repository path can be derived
// (e.g. non-pushed S3 object URI or absolute path), ok is false.
func cleanArtifactLocation(sourceFile string) (string, bool) {
	if sourceFile == "" {
		return "", false
	}
	s := strings.TrimSpace(sourceFile)
	s = strings.ReplaceAll(s, "\\", "/")

	if strings.HasPrefix(s, "s3://") {
		idx := strings.Index(s, "/pushed/")
		if idx >= 0 {
			s = s[idx+1:]
		} else {
			return "", false
		}
	}

	if strings.HasPrefix(s, "pushed/") {
		s = strings.TrimPrefix(s, "pushed/")
		if len(s) > 37 && s[36] == '-' && isValidUUID(s[:36]) {
			s = s[37:]
		}
	}

	s = path.Clean(s)
	if s == "" || s == "." || s == "/" || path.IsAbs(s) || strings.HasPrefix(s, "../") || strings.Contains(s, "://") || strings.HasPrefix(s, "pkg:") {
		return "", false
	}
	return s, true
}

func parsePURLPkg(purl string) (name, ver string) {
	if purl == "" {
		return "", ""
	}
	s := purl
	if idx := strings.IndexAny(s, "?#"); idx >= 0 {
		s = s[:idx]
	}
	if strings.HasPrefix(s, "pkg:") {
		s = s[4:]
		if slash := strings.Index(s, "/"); slash >= 0 {
			s = s[slash+1:]
		}
	}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		name = s[:at]
		ver = s[at+1:]
	} else {
		name = s
	}
	return name, ver
}

func formatPackage(purl string) string {
	name, ver := parsePURLPkg(purl)
	if name != "" && ver != "" {
		return name + "@" + ver
	}
	if name != "" {
		return name
	}
	if purl != "" {
		return purl
	}
	return "unknown package"
}

func isVEXSuppressed(status string) bool {
	return status == "not_affected" || status == "fixed"
}

// isSuppressed checks whether a finding should be marked suppressed in SARIF.
// For project-level aggregates across multiple SBOM versions, suppression is
// only granted if all affected versions are covered by a suppressing VEX statement.
func isSuppressed(v dto.VulnerabilityListItem) bool {
	if !isVEXSuppressed(v.VEXStatus) {
		return false
	}
	if v.AffectedSBOMs > 1 && v.VEXAffectedSBOMs < v.AffectedSBOMs {
		return false
	}
	return true
}

type ruleAgg struct {
	ruleID   string
	summary  string
	maxCVSS  *float64
	maxLevel int
}

func aggregateRules(items []dto.VulnerabilityListItem) []SARIFRule {
	rulesMap := make(map[string]*ruleAgg)
	for _, v := range items {
		ruleID := v.VulnID
		if ruleID == "" {
			ruleID = "UNKNOWN"
		}
		summary := v.Summary
		if summary == "" {
			summary = ruleID
		}
		sevRank := severityRank(v.Severity)
		if agg, ok := rulesMap[ruleID]; !ok {
			rulesMap[ruleID] = &ruleAgg{
				ruleID:   ruleID,
				summary:  summary,
				maxCVSS:  v.CVSSScore,
				maxLevel: sevRank,
			}
		} else {
			if (agg.summary == "" || agg.summary == ruleID) && summary != ruleID {
				agg.summary = summary
			}
			if v.CVSSScore != nil {
				if agg.maxCVSS == nil || *v.CVSSScore > *agg.maxCVSS {
					agg.maxCVSS = v.CVSSScore
				}
			}
			if sevRank > agg.maxLevel {
				agg.maxLevel = sevRank
			}
		}
	}

	ruleKeys := make([]string, 0, len(rulesMap))
	for k := range rulesMap {
		ruleKeys = append(ruleKeys, k)
	}
	sort.Strings(ruleKeys)

	rules := make([]SARIFRule, 0, len(ruleKeys))
	for _, k := range ruleKeys {
		agg := rulesMap[k]
		r := SARIFRule{
			ID: agg.ruleID,
			ShortDescription: &SARIFMultiformatMessageString{
				Text: agg.summary,
			},
			HelpURI: "https://osv.dev/vulnerability/" + agg.ruleID,
		}
		if agg.maxCVSS != nil {
			r.Properties = map[string]interface{}{
				"security-severity": fmt.Sprintf("%.1f", *agg.maxCVSS),
			}
		}
		rules = append(rules, r)
	}
	return rules
}

func buildSARIFResult(v dto.VulnerabilityListItem) SARIFResult {
	ruleID := v.VulnID
	if ruleID == "" {
		ruleID = "UNKNOWN"
	}
	pkg := formatPackage(v.PURL)
	var msgText string
	if v.FixedVersion != "" {
		msgText = fmt.Sprintf("%s is affected by %s (fixed in: %s)", pkg, ruleID, v.FixedVersion)
	} else {
		msgText = fmt.Sprintf("%s is affected by %s (no fix available)", pkg, ruleID)
	}

	var locations []SARIFLocation
	if loc, ok := cleanArtifactLocation(v.SourceFile); ok {
		locations = []SARIFLocation{
			{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: loc,
					},
				},
			},
		}
	}

	res := SARIFResult{
		RuleID:          ruleID,
		Level:           sarifLevel(v.Severity),
		CorrelationGUID: stableCorrelationGUID(ruleID, v.PURL),
		Message: SARIFMultiformatMessageString{
			Text: msgText,
		},
		Locations: locations,
	}

	props := make(map[string]interface{})
	if v.PURL != "" {
		props["purl"] = v.PURL
	}
	if v.DependencyDepth != nil {
		props["dependency_depth"] = *v.DependencyDepth
	}
	if v.DependencyScope != "" {
		props["dependency_scope"] = v.DependencyScope
	}
	if v.VEXStatus != "" {
		props["vex_status"] = v.VEXStatus
	}
	if len(v.Aliases) > 0 {
		props["aliases"] = v.Aliases
	}
	if len(locations) == 0 && v.SourceFile != "" {
		props["source_file"] = v.SourceFile
	}
	if len(props) > 0 {
		res.Properties = props
	}

	if isSuppressed(v) {
		justification := v.VEXStatus
		if v.VEXJustification != "" {
			justification += ": " + v.VEXJustification
		}
		res.Suppressions = []SARIFSuppression{
			{
				Kind:          "external",
				Justification: justification,
			},
		}
	}

	return res
}

func buildSARIF(items []dto.VulnerabilityListItem) SARIFLog {
	rules := aggregateRules(items)
	results := make([]SARIFResult, 0, len(items))
	for _, v := range items {
		results = append(results, buildSARIFResult(v))
	}

	return SARIFLog{
		Schema:  sarifSchemaURI,
		Version: sarifSchemaVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           sarifToolName,
						Version:        version,
						InformationURI: sarifInfoURI,
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}
}

// writeSARIFStream writes a SARIF 2.1.0 document to w without building a complete
// in-memory slice of SARIFResult objects, bounding gateway memory usage.
func writeSARIFStream(w io.Writer, items []dto.VulnerabilityListItem) error {
	rules := aggregateRules(items)
	rulesJSON, err := json.Marshal(rules)
	if err != nil {
		return err
	}

	if _, err := io.WriteString(w, `{"$schema":"`+sarifSchemaURI+`","version":"`+sarifSchemaVersion+`","runs":[{"tool":{"driver":{"name":"`+sarifToolName+`","version":"`+version+`","informationUri":"`+sarifInfoURI+`","rules":`); err != nil {
		return err
	}
	if _, err := w.Write(rulesJSON); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `}},"results":[`); err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	for i, v := range items {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		res := buildSARIFResult(v)
		if err := enc.Encode(res); err != nil {
			return err
		}
	}

	_, err = io.WriteString(w, "]}]}")
	return err
}

func writeEmptySARIF(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", sarifContentType)
	w.WriteHeader(status)
	logData := SARIFLog{
		Schema:  sarifSchemaURI,
		Version: sarifSchemaVersion,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           sarifToolName,
						Version:        version,
						InformationURI: sarifInfoURI,
						Rules:          []SARIFRule{},
					},
				},
				Results: []SARIFResult{},
			},
		},
	}
	_ = json.NewEncoder(w).Encode(logData)
}

func writeSARIF(w http.ResponseWriter, status int, items []dto.VulnerabilityListItem) {
	w.Header().Set("Content-Type", sarifContentType)
	w.WriteHeader(status)
	if err := writeSARIFStream(w, items); err != nil {
		log.Printf("ERROR: Failed to write SARIF stream: %v", err)
	}
}
