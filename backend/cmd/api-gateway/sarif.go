package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

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
	RuleID       string                        `json:"ruleId"`
	Level        string                        `json:"level,omitempty"`
	Message      SARIFMultiformatMessageString `json:"message"`
	Locations    []SARIFLocation               `json:"locations,omitempty"`
	Properties   map[string]interface{}        `json:"properties,omitempty"`
	Suppressions []SARIFSuppression            `json:"suppressions,omitempty"`
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

func sarifSecuritySeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "7.5"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "2.0"
	default:
		return ""
	}
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

func buildSARIF(items []dto.VulnerabilityListItem) SARIFLog {
	rulesMap := make(map[string]SARIFRule)
	results := make([]SARIFResult, 0, len(items))

	for _, v := range items {
		ruleID := v.VulnID
		if ruleID == "" {
			ruleID = "UNKNOWN"
		}

		summary := v.Summary
		if summary == "" {
			summary = ruleID
		}
		if existing, ok := rulesMap[ruleID]; !ok {
			r := SARIFRule{
				ID: ruleID,
				ShortDescription: &SARIFMultiformatMessageString{
					Text: summary,
				},
				HelpURI: "https://osv.dev/vulnerability/" + ruleID,
			}
			secSev := sarifSecuritySeverity(v.Severity)
			if secSev != "" {
				r.Properties = map[string]interface{}{
					"security-severity": secSev,
				}
			}
			rulesMap[ruleID] = r
		} else {
			if existing.ShortDescription != nil && existing.ShortDescription.Text == ruleID && summary != ruleID {
				existing.ShortDescription.Text = summary
			}
			if existing.Properties == nil {
				secSev := sarifSecuritySeverity(v.Severity)
				if secSev != "" {
					existing.Properties = map[string]interface{}{
						"security-severity": secSev,
					}
				}
			}
			rulesMap[ruleID] = existing
		}

		pkg := formatPackage(v.PURL)
		var msgText string
		if v.FixedVersion != "" {
			msgText = fmt.Sprintf("%s is affected by %s (fixed in: %s)", pkg, ruleID, v.FixedVersion)
		} else {
			msgText = fmt.Sprintf("%s is affected by %s (no fix available)", pkg, ruleID)
		}

		uri := v.SourceFile
		if uri == "" {
			uri = v.PURL
		}
		if uri == "" {
			uri = "unknown"
		}

		res := SARIFResult{
			RuleID: ruleID,
			Level:  sarifLevel(v.Severity),
			Message: SARIFMultiformatMessageString{
				Text: msgText,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: uri,
						},
					},
				},
			},
		}

		props := map[string]interface{}{}
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
		if len(props) > 0 {
			res.Properties = props
		}

		if isVEXSuppressed(v.VEXStatus) {
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

		results = append(results, res)
	}

	ruleKeys := make([]string, 0, len(rulesMap))
	for k := range rulesMap {
		ruleKeys = append(ruleKeys, k)
	}
	sort.Strings(ruleKeys)

	rules := make([]SARIFRule, 0, len(ruleKeys))
	for _, k := range ruleKeys {
		rules = append(rules, rulesMap[k])
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

func writeSARIF(w http.ResponseWriter, status int, items []dto.VulnerabilityListItem) {
	w.Header().Set("Content-Type", sarifContentType)
	w.WriteHeader(status)
	logData := buildSARIF(items)
	if err := json.NewEncoder(w).Encode(logData); err != nil {
		log.Printf("ERROR: Failed to encode SARIF response: %v", err)
	}
}
