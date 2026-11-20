package importer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	json "github.com/goccy/go-json"

	tagpkg "github.com/seebom-labs/bomhort/backend/internal/tags"
)

// Mapping assigns BOMHort ownership to imported SBOMs. It is read from a JSON
// file like the instance's other mapping files (project-groups.json):
//
//	{
//	  "tags": ["imported"],
//	  "projects": {
//	    "payments-api": {"project": "payments", "tags": ["team-payments"]}
//	  }
//	}
//
// Keys under "projects" are source project names. "tags" at the top level go
// on every SBOM and are merged with the project's own, as upload tags are.
// An SBOM without a project entry keeps the project BOMHort derives from the
// document.
type Mapping struct {
	Tags     []string                  `json:"tags"`
	Projects map[string]ProjectMapping `json:"projects"`
}

// ProjectMapping is the ownership of one source project.
type ProjectMapping struct {
	Project string   `json:"project"`
	Tags    []string `json:"tags"`
}

// LoadMapping reads a mapping file. Unknown fields are an error, so a typo
// does not silently import everything unmapped.
func LoadMapping(path string) (*Mapping, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Mapping
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("mapping file %s: %w", path, err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return nil, fmt.Errorf("mapping file %s: unexpected data after the JSON object", path)
	}
	return &m, nil
}

// Resolve returns the BOMHort project ("" = derive from the document) and the
// normalised tags for a source project.
func (m *Mapping) Resolve(name string) (project string, tags []string) {
	if m == nil {
		return "", nil
	}
	pm := m.Projects[name]
	return strings.TrimSpace(pm.Project), tagpkg.Merge(m.Tags, pm.Tags)
}
