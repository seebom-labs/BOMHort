package importer

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadMapping(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mapping.json", `{
	  "tags": ["Imported"],
	  "projects": {"payments-api": {"project": " payments ", "tags": ["team-payments", "imported"]}}
	}`)
	m, err := LoadMapping(filepath.Join(dir, "mapping.json"))
	if err != nil {
		t.Fatal(err)
	}

	project, tags := m.Resolve("payments-api")
	if project != "payments" || !reflect.DeepEqual(tags, []string{"imported", "team-payments"}) {
		t.Errorf("Resolve(mapped) = %q, %v", project, tags)
	}
	// Unmapped: BOMHort derives the project, the global tags still apply.
	project, tags = m.Resolve("other")
	if project != "" || !reflect.DeepEqual(tags, []string{"imported"}) {
		t.Errorf("Resolve(unmapped) = %q, %v", project, tags)
	}

	var none *Mapping
	if project, tags := none.Resolve("x"); project != "" || tags != nil {
		t.Errorf("nil mapping resolved to %q, %v", project, tags)
	}
}

func TestLoadMapping_Rejects(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"typo.json":     `{"project": {"a": {"project": "b"}}}`,
		"inner.json":    `{"projects": {"a": {"name": "b"}}}`,
		"trailing.json": `{"tags": []} {}`,
		"broken.json":   `{`,
	}
	for name, content := range cases {
		writeFile(t, dir, name, content)
		if _, err := LoadMapping(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s: accepted %s", name, content)
		}
	}
}
