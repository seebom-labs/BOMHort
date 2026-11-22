package sbom

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
)

func TestProbeRetainsCycloneDXMetadataAcrossBackends(t *testing.T) {
	defer SetUseProtobom(false)
	cfg, err := extrafields.Parse([]byte(`{"fields":[{"name":"owner","from":[
	  {"cyclonedx":"metadata.properties","property":"owner"}
	]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, predicate := range []string{"", `,"predicate":["unrelated"]`, `,"predicateType":42,"spdxVersion":42`} {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		  "metadata":{"component":{"type":"application","name":"app"},
		    "properties":[{"name":"owner","value":"team"}]}` + predicate + `}`
		for _, proto := range []bool{false, true} {
			// Protobom itself rejects a non-string spdxVersion, before extraction.
			if proto && strings.Contains(predicate, `"spdxVersion":42`) {
				continue
			}
			SetUseProtobom(proto)
			result, err := Parse(strings.NewReader(doc), "test.cdx.json", "hash", true)
			if err != nil {
				t.Fatalf("proto=%v, predicate=%q: %v", proto, predicate, err)
			}
			want := map[string][]string{"owner": {"team"}}
			if got := extrafields.Extract(result.CycloneDXMetadata, cfg); !reflect.DeepEqual(got, want) {
				t.Errorf("proto=%v, predicate=%q: fields = %v, want %v", proto, predicate, got, want)
			}
			withoutMetadata, err := Parse(strings.NewReader(doc), "test.cdx.json", "hash", false)
			if err != nil {
				t.Fatalf("proto=%v: parse without metadata: %v", proto, err)
			}
			if len(withoutMetadata.CycloneDXMetadata) != 0 {
				t.Errorf("proto=%v: metadata captured while disabled: %s", proto, withoutMetadata.CycloneDXMetadata)
			}
		}
	}
}

func TestProbeExcludesSPDXMetadata(t *testing.T) {
	defer SetUseProtobom(false)
	doc := `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"doc",
	  "dataLicense":"CC0-1.0","documentNamespace":"https://example.test/doc",
	  "creationInfo":{"created":"2024-01-01T00:00:00Z","creators":["Tool: test"]},
	  "metadata":{"properties":[{"name":"owner","value":"not-cyclonedx"}]}}`
	for _, proto := range []bool{false, true} {
		SetUseProtobom(proto)
		result, err := Parse(strings.NewReader(doc), "test.spdx.json", "hash", true)
		if err != nil {
			t.Fatalf("proto=%v: %v", proto, err)
		}
		if len(result.CycloneDXMetadata) != 0 {
			t.Errorf("proto=%v: SPDX metadata was treated as CycloneDX", proto)
		}
	}
}

func TestProbeCapturesCycloneDXInPredicate(t *testing.T) {
	doc := `{"predicateType":"https://cyclonedx.org/bom","predicate":{
	  "bomFormat":"CycloneDX","metadata":{"properties":[{"name":"owner","value":"team"}]}
	}}`
	SetUseProtobom(false)
	result, err := Parse(strings.NewReader(doc), "envelope.json", "hash", true)
	if err != nil {
		t.Fatal(err)
	}
	var md struct {
		Properties []struct{ Name, Value string } `json:"properties"`
	}
	if err := json.Unmarshal(result.CycloneDXMetadata, &md); err != nil {
		t.Fatal(err)
	}
	if len(md.Properties) != 1 || md.Properties[0].Value != "team" {
		t.Fatalf("predicate metadata = %s", result.CycloneDXMetadata)
	}
}

func TestProbeUsesProtobomFormatDetection(t *testing.T) {
	cases := []struct {
		doc  string
		want formats.Format
	}{
		{`{"bomFormat":"CycloneDX","specVersion":"1.3"}`, formats.CDX13JSON},
		{`{"bomFormat":"cyclonedx","specVersion":"1.7"}`, formats.CDX17JSON},
		{`{"bomFormat":"CycloneDX","specVersion":"1.2"}`, formats.EmptyFormat},
		{`{"spdxVersion":"SPDX-2.2"}`, formats.SPDX22JSON},
		{`{"spdxVersion":"SPDX-2.3"}`, formats.SPDX23JSON},
		{`{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}`, formats.SPDX3JSON},
		{`{"@context":[null,"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}`, formats.SPDX3JSON},
		{`{"bomFormat":"CycloneDX","specVersion":"1.6","specVersion":null}`, formats.CDX16JSON},
		{`{"spdxVersion":"SPDX-2.3","spdxVersion":null,"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}`, formats.SPDX23JSON},
		{`{"bomFormat":"CycloneDX","specVersion":"1.9"}`, formats.EmptyFormat},
	}
	for _, tc := range cases {
		var probe probeWithMetadata
		if err := json.Unmarshal([]byte(tc.doc), &probe); err != nil {
			t.Fatalf("%s: %v", tc.doc, err)
		}
		got, err := sniffProtobomFormat(probe.formatProbe)
		if err != nil {
			t.Fatalf("%s: %v", tc.doc, err)
		}
		if got != tc.want {
			t.Errorf("%s: probed %q, want %q", tc.doc, got, tc.want)
		}
		want, err := (&formats.Sniffer{}).SniffReader(bytes.NewReader([]byte(tc.doc)))
		if err != nil {
			want = formats.EmptyFormat
		}
		// Empty means the original document is handed back to protobom's
		// sniffer, including for future formats.
		if got != formats.EmptyFormat && got != want {
			t.Errorf("%s: probed %q, original detection %q", tc.doc, got, want)
		}
	}
	for _, doc := range []string{
		`{"bomFormat":"CycloneDX","specVersion":123,"specVersion":"1.6"}`,
		`{"spdxVersion":123,"spdxVersion":"SPDX-2.3"}`,
	} {
		var probe probeWithMetadata
		if err := json.Unmarshal([]byte(doc), &probe); err == nil {
			t.Errorf("%s: malformed format field did not fall back to protobom", doc)
		}
	}
}
