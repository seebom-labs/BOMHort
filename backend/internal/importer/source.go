// Package importer moves an existing SBOM inventory into BOMHort through the
// public upload API (#536). It reads SBOMs and their triage decisions from a
// Source, turns the decisions into one OpenVEX document per SBOM and uploads
// both. It never talks to ClickHouse: everything goes through
// POST /api/v1/sboms/upload, so it runs against any instance it has an API
// key for.
package importer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Project is one SBOM in the source inventory.
type Project struct {
	// ID identifies the SBOM within its source (a relative path for a
	// directory source).
	ID string
	// Name is what mapping entries match on.
	Name string
	// FileName is the upload file name (X-Filename); it ends in .json.
	FileName string
}

// Analysis is one triage decision: the state of one vulnerability in the
// listed components of one SBOM. The vocabulary is CycloneDX's
// (impactAnalysisState, impactAnalysisJustification, impactAnalysisResponse),
// which inventory tools commonly use for their own analysis records too;
// values are matched case-insensitively.
type Analysis struct {
	VulnID        string
	Aliases       []string
	PURLs         []string
	State         string
	Justification string
	Responses     []string
	Detail        string
	// Updated is when the decision was last changed; zero if unknown.
	Updated time.Time
}

// Source is where the importer reads from. notes in ListAnalyses lists
// decisions that could not be read and why; they are reported, not fatal.
type Source interface {
	ListProjects(ctx context.Context) ([]Project, error)
	GetSBOM(ctx context.Context, p Project) ([]byte, error)
	ListAnalyses(ctx context.Context, p Project) (analyses []Analysis, notes []string, err error)
}

// DirSource reads CycloneDX JSON documents with embedded
// vulnerabilities[].analysis from a directory tree.
type DirSource struct {
	root string
	// Skipped lists files ListProjects ignored and why, for the plan.
	Skipped []string
}

// NewDirSource returns a source for the CycloneDX documents under root.
func NewDirSource(root string) (*DirSource, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	return &DirSource{root: root}, nil
}

// ListProjects returns every CycloneDX JSON document under the root, in
// lexical path order. SPDX and VEX files and JSON that is not CycloneDX are
// skipped and recorded in Skipped.
func (s *DirSource) ListProjects(_ context.Context) ([]Project, error) {
	s.Skipped = nil
	var out []Project
	err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(s.root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		lower := strings.ToLower(d.Name())
		switch {
		case !strings.HasSuffix(lower, ".json"):
			return nil
		case strings.HasSuffix(lower, ".openvex.json"), strings.HasSuffix(lower, ".vex.json"),
			strings.HasSuffix(lower, ".spdx.json"):
			s.Skipped = append(s.Skipped, rel+": not a CycloneDX SBOM")
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		doc, err := parseCycloneDX(data)
		if err != nil {
			s.Skipped = append(s.Skipped, rel+": "+err.Error())
			return nil
		}
		name := doc.name()
		if name == "" {
			name = strings.TrimSuffix(strings.TrimSuffix(d.Name(), ".json"), ".cdx")
		}
		out = append(out, Project{ID: rel, Name: name, FileName: d.Name()})
		return nil
	})
	return out, err
}

// GetSBOM returns the document's bytes unchanged.
func (s *DirSource) GetSBOM(_ context.Context, p Project) ([]byte, error) {
	return os.ReadFile(s.path(p))
}

// ListAnalyses returns the analyses embedded in the document.
func (s *DirSource) ListAnalyses(_ context.Context, p Project) ([]Analysis, []string, error) {
	data, err := os.ReadFile(s.path(p))
	if err != nil {
		return nil, nil, err
	}
	doc, err := parseCycloneDX(data)
	if err != nil {
		return nil, nil, err
	}
	analyses, notes := doc.analyses()
	return analyses, notes, nil
}

func (s *DirSource) path(p Project) string {
	return filepath.Join(s.root, filepath.FromSlash(p.ID))
}
