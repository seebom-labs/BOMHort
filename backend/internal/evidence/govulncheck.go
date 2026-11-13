package evidence

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FindingEvidence represents an evaluated vulnerability finding from govulncheck (#535).
type FindingEvidence struct {
	OSV       string
	Aliases   []string
	Module    string
	Package   string
	Reachable bool
}

// GovulncheckReport represents the parsed findings and scanner tool information
// from a govulncheck JSON (-json) execution.
type GovulncheckReport struct {
	// Tool is the scanner name and version (e.g. "govulncheck v1.1.3").
	Tool string
	// ReachableIDs contains every OSV ID and CVE/GHSA alias for findings
	// whose call trace was present (called in the binary/codebase).
	ReachableIDs map[string]bool
	// Findings lists the evaluated vulnerability findings with module and reachability.
	Findings []FindingEvidence
	// TotalFindings is the number of finding entries decoded from the report.
	TotalFindings int
	// CalledCount is the number of findings with a non-empty call trace.
	CalledCount int
}

// govulncheckMessage represents the generic container for govulncheck JSON output.
// govulncheck streams JSON objects with a single top-level key (config, osv, finding, etc.).
type govulncheckMessage struct {
	Config  *govulncheckConfig  `json:"config,omitempty"`
	OSV     *govulncheckOSV     `json:"osv,omitempty"`
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

type govulncheckConfig struct {
	ProtocolVersion string `json:"protocol_version"`
	ScannerName     string `json:"scanner_name"`
	ScannerVersion  string `json:"scanner_version"`
}

type govulncheckOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type govulncheckFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
}

type govulncheckFinding struct {
	OSV          string             `json:"osv"`
	FixedVersion string             `json:"fixed_version"`
	Trace        []govulncheckFrame `json:"trace"`
}

// ParseGovulncheck parses govulncheck JSON output from an io.Reader.
// It accepts either a stream of newline-delimited JSON objects (standard govulncheck -json)
// or a JSON array of messages.
func ParseGovulncheck(r io.Reader) (*GovulncheckReport, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read evidence payload: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty evidence payload")
	}

	var rawMessages []json.RawMessage
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &rawMessages); err != nil {
			return nil, fmt.Errorf("malformed JSON array in evidence: %w", err)
		}
	} else {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, fmt.Errorf("malformed JSON object in evidence: %w", err)
			}
			rawMessages = append(rawMessages, raw)
		}
	}

	if len(rawMessages) == 0 {
		return nil, fmt.Errorf("no JSON messages found in evidence")
	}

	var scannerName, scannerVersion string
	osvAliases := make(map[string][]string)
	reachableIDs := make(map[string]bool)

	type rawFinding struct {
		OSV   string
		Trace []govulncheckFrame
	}
	var findings []rawFinding

	for _, raw := range rawMessages {
		var msg govulncheckMessage
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		if msg.Config != nil {
			name := strings.TrimSpace(msg.Config.ScannerName)
			if strings.EqualFold(name, "govulncheck") {
				scannerName = name
				scannerVersion = strings.TrimSpace(msg.Config.ScannerVersion)
			}
		}

		if msg.OSV != nil {
			if msg.OSV.ID != "" {
				osvAliases[msg.OSV.ID] = msg.OSV.Aliases
			}
		}

		if msg.Finding != nil {
			if msg.Finding.OSV != "" {
				findings = append(findings, rawFinding{
					OSV:   msg.Finding.OSV,
					Trace: msg.Finding.Trace,
				})
			}
		}
	}

	// Require recognized govulncheck scanner identity (#535).
	if scannerName == "" || !strings.EqualFold(scannerName, "govulncheck") {
		return nil, fmt.Errorf("unrecognized evidence format: expected scanner_name 'govulncheck'")
	}

	// Reject reports without meaningful scan findings (#535).
	if len(findings) == 0 {
		return nil, fmt.Errorf("unrecognized evidence format: report contains no scan findings")
	}

	tool := formatToolName(scannerName, scannerVersion)
	calledCount := 0

	type findingKey struct {
		osv    string
		module string
	}
	findingMap := make(map[findingKey]*FindingEvidence)

	for _, f := range findings {
		module := ""
		pkg := ""
		called := false
		if len(f.Trace) > 0 {
			module = strings.TrimSpace(f.Trace[0].Module)
			pkg = strings.TrimSpace(f.Trace[0].Package)
			for _, frame := range f.Trace {
				if frame.Function != "" {
					called = true
					break
				}
			}
		}

		if called {
			calledCount++
			reachableIDs[f.OSV] = true
			if aliases, ok := osvAliases[f.OSV]; ok {
				for _, alias := range aliases {
					reachableIDs[alias] = true
				}
			}
		}

		k := findingKey{osv: f.OSV, module: module}
		if existing, ok := findingMap[k]; ok {
			if called {
				existing.Reachable = true
			}
		} else {
			findingMap[k] = &FindingEvidence{
				OSV:       f.OSV,
				Aliases:   osvAliases[f.OSV],
				Module:    module,
				Package:   pkg,
				Reachable: called,
			}
		}
	}

	reportFindings := make([]FindingEvidence, 0, len(findingMap))
	for _, fe := range findingMap {
		reportFindings = append(reportFindings, *fe)
	}

	return &GovulncheckReport{
		Tool:          tool,
		ReachableIDs:  reachableIDs,
		Findings:      reportFindings,
		TotalFindings: len(findings),
		CalledCount:   calledCount,
	}, nil
}

func formatToolName(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" {
		name = "govulncheck"
	}
	if version == "" {
		return name
	}
	return name + " " + version
}
