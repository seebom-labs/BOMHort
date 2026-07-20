// Package osvutil provides shared utility functions for processing OSV vulnerability data.
package osvutil

import (
	"fmt"
	"math"
	"strings"

	"github.com/seebom-labs/bomhort/backend/internal/osv"
)

// ClassifySeverity maps OSV severity data to a simple category (CRITICAL/HIGH/MEDIUM/LOW).
// It tries multiple strategies in order:
//  1. CVSS_V3 score (numeric or vector string)
//  2. database_specific.severity (GHSA entries often have this)
//  3. Fallback: MEDIUM if any severity data exists, LOW otherwise
func ClassifySeverity(v osv.VulnEntry) string {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			score := ParseCVSSScore(s.Score)
			if score >= 0 {
				return scoreToSeverity(score)
			}
		}
	}

	// Check database_specific.severity (common in GHSA entries).
	if v.DatabaseSpecific != nil {
		if sev, ok := v.DatabaseSpecific["severity"]; ok {
			if sevStr, ok := sev.(string); ok {
				upper := strings.ToUpper(sevStr)
				switch upper {
				case "CRITICAL", "HIGH", "MEDIUM", "LOW":
					return upper
				}
			}
		}
	}

	if len(v.Severity) > 0 {
		return "MEDIUM"
	}
	return "LOW"
}

// scoreToSeverity maps a CVSS numeric base score to a severity label.
func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ParseCVSSScore extracts a numeric base score from a CVSS v3 vector string
// or a plain numeric string. Returns -1 if the input cannot be parsed.
func ParseCVSSScore(score string) float64 {
	// Try plain numeric first (e.g., "9.8").
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err == nil && !strings.Contains(score, "/") {
		return f
	}

	// Try CVSS v3 vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").
	if strings.HasPrefix(score, "CVSS:3") {
		if computed := computeCVSSv3BaseScore(score); computed >= 0 {
			return computed
		}
	}

	return -1
}

// computeCVSSv3BaseScore calculates the CVSS v3.x base score from a vector string.
// Returns -1 if the vector is malformed.
func computeCVSSv3BaseScore(vector string) float64 {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string, 8)
	for _, p := range parts[1:] { // Skip "CVSS:3.x"
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	av, ok := attackVectorScore[metrics["AV"]]
	if !ok {
		return -1
	}
	ac, ok := attackComplexityScore[metrics["AC"]]
	if !ok {
		return -1
	}
	ui, ok := userInteractionScore[metrics["UI"]]
	if !ok {
		return -1
	}
	scope := metrics["S"]
	if scope != "U" && scope != "C" {
		return -1
	}
	pr, ok := privilegesRequiredScore(metrics["PR"], scope)
	if !ok {
		return -1
	}
	c, ok := impactScore[metrics["C"]]
	if !ok {
		return -1
	}
	i, ok := impactScore[metrics["I"]]
	if !ok {
		return -1
	}
	a, ok := impactScore[metrics["A"]]
	if !ok {
		return -1
	}

	// Impact Sub Score
	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

	var impact float64
	if scope == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	if impact <= 0 {
		return 0.0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scope == "U" {
		base = impact + exploitability
		if base > 10.0 {
			base = 10.0
		}
	} else {
		base = 1.08 * (impact + exploitability)
		if base > 10.0 {
			base = 10.0
		}
	}

	// CVSS "Roundup": round up to 1 decimal place.
	return roundUp(base)
}

// roundUp rounds a float64 up to 1 decimal place (CVSS standard rounding).
func roundUp(v float64) float64 {
	x := math.Round(v*100000) / 100000 // eliminate floating point noise
	return math.Ceil(x*10) / 10
}

var attackVectorScore = map[string]float64{
	"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20,
}

var attackComplexityScore = map[string]float64{
	"L": 0.77, "H": 0.44,
}

var userInteractionScore = map[string]float64{
	"N": 0.85, "R": 0.62,
}

func privilegesRequiredScore(value, scope string) (float64, bool) {
	if scope == "C" {
		switch value {
		case "N":
			return 0.85, true
		case "L":
			return 0.68, true
		case "H":
			return 0.50, true
		}
	} else {
		switch value {
		case "N":
			return 0.85, true
		case "L":
			return 0.62, true
		case "H":
			return 0.27, true
		}
	}
	return 0, false
}

var impactScore = map[string]float64{
	"H": 0.56, "L": 0.22, "N": 0.00,
}

// ExtractFixedVersion finds the first "fixed" version from OSV affected data.
func ExtractFixedVersion(v osv.VulnEntry) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// ExtractAffectedVersions collects all explicitly listed affected versions.
func ExtractAffectedVersions(v osv.VulnEntry) []string {
	var versions []string
	for _, a := range v.Affected {
		versions = append(versions, a.Versions...)
	}
	if versions == nil {
		versions = []string{}
	}
	return versions
}
