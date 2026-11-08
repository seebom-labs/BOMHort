package extrafields

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const ownerConfig = `{
  "fields": [
    {
      "name": "owner_contact",
      "from": [
        {"cyclonedx": "metadata.component.properties", "property": "bomhort:owner:contact"},
        {"cyclonedx": "metadata.properties", "property": "bomhort:owner:contact"}
      ]
    },
    {
      "name": "issue_tracker",
      "from": [{"cyclonedx": "metadata.component.externalReferences", "type": "issue-tracker"}]
    }
  ]
}`

func mustParse(t *testing.T, s string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestExtract_PropertiesAndExternalReferences(t *testing.T) {
	cfg := mustParse(t, ownerConfig)
	doc := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "metadata": {
	    "properties": [
	      {"name": "bomhort:owner:contact", "value": "platform@example.com"},
	      {"name": "bomhort:owner:contact", "value": "team-a@example.com"}
	    ],
	    "component": {
	      "name": "app",
	      "properties": [
	        {"name": "bomhort:owner:contact", "value": "team-a@example.com"},
	        {"name": "other", "value": "ignored"}
	      ],
	      "externalReferences": [
	        {"type": "vcs", "url": "https://github.com/acme/app"},
	        {"type": "issue-tracker", "url": "https://github.com/acme/app/issues"}
	      ]
	    }
	  }
	}`
	got := Extract([]byte(doc), cfg)
	want := map[string][]string{
		// Component properties come first (source order), duplicates collapse.
		"owner_contact": {"team-a@example.com", "platform@example.com"},
		"issue_tracker": {"https://github.com/acme/app/issues"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Extract = %#v, want %#v", got, want)
	}
}

func TestExtract_NoMatchReturnsNil(t *testing.T) {
	cfg := mustParse(t, ownerConfig)
	doc := `{"bomFormat":"CycloneDX","metadata":{"component":{"name":"x"}}}`
	if got := Extract([]byte(doc), cfg); got != nil {
		t.Fatalf("Extract = %#v, want nil", got)
	}
}

func TestExtract_NilConfig(t *testing.T) {
	doc := `{"bomFormat":"CycloneDX","metadata":{"properties":[{"name":"a","value":"b"}]}}`
	if got := Extract([]byte(doc), nil); got != nil {
		t.Fatalf("Extract(nil cfg) = %#v, want nil", got)
	}
}

func TestExtract_SPDXIsOutOfScope(t *testing.T) {
	cfg := mustParse(t, ownerConfig)
	doc := `{"spdxVersion":"SPDX-2.3","annotations":[{"comment":"bomhort:owner:contact=x"}]}`
	if got := Extract([]byte(doc), cfg); got != nil {
		t.Fatalf("Extract(SPDX) = %#v, want nil", got)
	}
}

func TestExtract_InTotoEnvelope(t *testing.T) {
	cfg := mustParse(t, ownerConfig)
	doc := `{
	  "_type": "https://in-toto.io/Statement/v0.1",
	  "predicateType": "https://cyclonedx.org/bom",
	  "predicate": {
	    "bomFormat": "CycloneDX",
	    "metadata": {"properties": [{"name": "bomhort:owner:contact", "value": "sec@example.com"}]}
	  }
	}`
	got := Extract([]byte(doc), cfg)
	if want := []string{"sec@example.com"}; !reflect.DeepEqual(got["owner_contact"], want) {
		t.Fatalf("owner_contact = %v, want %v", got["owner_contact"], want)
	}
}

// A producer writing odd shapes must not lose the well-formed entries, and
// must never make Extract panic or fail the ingest.
func TestExtract_LenientOnOddShapes(t *testing.T) {
	cfg := mustParse(t, ownerConfig)
	cases := map[string]string{
		"not json":           `{{{`,
		"metadata is string": `{"bomFormat":"CycloneDX","metadata":"x"}`,
		"component is array": `{"bomFormat":"CycloneDX","metadata":{"component":[1,2]}}`,
		"properties object":  `{"bomFormat":"CycloneDX","metadata":{"properties":{"a":1}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Extract([]byte(doc), cfg); got != nil {
				t.Fatalf("Extract = %#v, want nil", got)
			}
		})
	}

	doc := `{"bomFormat":"CycloneDX","metadata":{"properties":[
	  {"name":"bomhort:owner:contact","value":42},
	  "garbage",
	  {"name":"bomhort:owner:contact","value":"ok@example.com"}
	]}}`
	got := Extract([]byte(doc), cfg)
	if want := []string{"ok@example.com"}; !reflect.DeepEqual(got["owner_contact"], want) {
		t.Fatalf("owner_contact = %v, want %v", got["owner_contact"], want)
	}
}

func TestExtract_UntrustedValueLimits(t *testing.T) {
	cfg := mustParse(t, ownerConfig)
	var props []string
	props = append(props,
		`{"name":"bomhort:owner:contact","value":"  line1\nline2\u0007  "}`,
		`{"name":"bomhort:owner:contact","value":"`+strings.Repeat("a", MaxValueLen+1)+`"}`,
		`{"name":"bomhort:owner:contact","value":"   "}`,
	)
	for i := 0; i < MaxValuesPerField+5; i++ {
		props = append(props, `{"name":"bomhort:owner:contact","value":"v`+strings.Repeat("x", i)+`"}`)
	}
	doc := `{"bomFormat":"CycloneDX","metadata":{"properties":[` + strings.Join(props, ",") + `]}}`
	got := Extract([]byte(doc), cfg)["owner_contact"]

	if len(got) != MaxValuesPerField {
		t.Fatalf("got %d values, want cap %d", len(got), MaxValuesPerField)
	}
	if got[0] != "line1line2" {
		t.Errorf("control characters not stripped: %q", got[0])
	}
	for _, v := range got {
		if len(v) > MaxValueLen {
			t.Errorf("over-long value kept (%d bytes)", len(v))
		}
		if strings.TrimSpace(v) == "" {
			t.Errorf("blank value kept")
		}
	}
}

func TestExtract_DropsInvalidUTF8(t *testing.T) {
	if _, ok := clean("bad\xffbyte"); ok {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestParse_AllowsTrailingWhitespace(t *testing.T) {
	if _, err := Parse([]byte("{\"fields\":[]}\n\n  \t")); err != nil {
		t.Fatalf("trailing whitespace rejected: %v", err)
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":         `{"fields":[{"name":"a","from":[{"cyclonedx":"metadata.properties","propery":"x"}]}]}`,
		"spdx source":         `{"fields":[{"name":"a","from":[{"spdx":"annotations"}]}]}`,
		"unknown cdx source":  `{"fields":[{"name":"a","from":[{"cyclonedx":"components","property":"x"}]}]}`,
		"missing property":    `{"fields":[{"name":"a","from":[{"cyclonedx":"metadata.properties"}]}]}`,
		"missing type":        `{"fields":[{"name":"a","from":[{"cyclonedx":"metadata.component.externalReferences"}]}]}`,
		"type on properties":  `{"fields":[{"name":"a","from":[{"cyclonedx":"metadata.properties","property":"x","type":"vcs"}]}]}`,
		"property on extrefs": `{"fields":[{"name":"a","from":[{"cyclonedx":"metadata.component.externalReferences","type":"vcs","property":"x"}]}]}`,
		"no sources":          `{"fields":[{"name":"a","from":[]}]}`,
		"bad name":            `{"fields":[{"name":"Owner Contact","from":[{"cyclonedx":"metadata.properties","property":"x"}]}]}`,
		"duplicate name":      `{"fields":[{"name":"a","from":[{"cyclonedx":"metadata.properties","property":"x"}]},{"name":"a","from":[{"cyclonedx":"metadata.properties","property":"y"}]}]}`,
		"empty cyclonedx":     `{"fields":[{"name":"a","from":[{"property":"x"}]}]}`,
		"not json":            `nope`,
		"second value":        `{"fields":[]} {"fields":[]}`,
		"trailing garbage":    `{"fields":[]} nope`,
		"trailing bracket":    `{"fields":[]}]`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Fatal("Parse accepted invalid config")
			}
		})
	}
}

func TestParse_TooManyFields(t *testing.T) {
	var fields []string
	for i := 0; i <= MaxFields; i++ {
		fields = append(fields, `{"name":"f`+strings.Repeat("x", i)+`","from":[{"cyclonedx":"metadata.properties","property":"p"}]}`)
	}
	if _, err := Parse([]byte(`{"fields":[` + strings.Join(fields, ",") + `]}`)); err == nil {
		t.Fatal("Parse accepted more than MaxFields fields")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	if cfg, err := Load(filepath.Join(dir, "missing.json")); cfg != nil || err != nil {
		t.Fatalf("missing file: got (%v, %v), want (nil, nil)", cfg, err)
	}
	if cfg, err := Load(""); cfg != nil || err != nil {
		t.Fatalf("empty path: got (%v, %v), want (nil, nil)", cfg, err)
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"fields":[{"name":"X"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Fatal("invalid file loaded without error")
	}

	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(ownerConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(good)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []string{"owner_contact", "issue_tracker"}; !reflect.DeepEqual(cfg.Names(), want) {
		t.Fatalf("Names = %v, want %v", cfg.Names(), want)
	}
}

// The example shipped with the repository (and mounted by docker-compose)
// must always load.
func TestShippedExampleLoads(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "..", "sboms", "extra-fields.json"))
	if err != nil {
		t.Fatalf("shipped extra-fields.json: %v", err)
	}
	if cfg == nil {
		t.Fatal("shipped extra-fields.json not found")
	}
	found := false
	for _, f := range cfg.Fields {
		if f.Name == "owner_contact" {
			found = true
		}
	}
	if !found {
		t.Fatal("shipped config does not declare owner_contact")
	}
}
