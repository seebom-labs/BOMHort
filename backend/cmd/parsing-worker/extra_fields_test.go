package main

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/seebom-labs/bomhort/backend/internal/extrafields"
	"github.com/seebom-labs/bomhort/backend/internal/sbom"
)

const extraFieldsTestConfig = `{"fields":[{"name":"owner_contact","from":[
  {"cyclonedx":"metadata.component.properties","property":"bomhort:owner:contact"},
  {"cyclonedx":"metadata.properties","property":"bomhort:owner:contact"}
]}]}`

const extraFieldsTestBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "metadata": {
    "component": {
      "type": "application", "bom-ref": "app", "name": "payments", "version": "1.0.0",
      "properties": [{"name": "bomhort:owner:contact", "value": "payments@example.com"}]
    }
  },
  "components": [{"bom-ref": "lib", "name": "lib", "version": "1.0.0", "purl": "pkg:golang/example.com/lib@1.0.0"}]
}`

// The parsed document and the extracted fields end up on the same SBOM row,
// for either parser backend.
func TestApplyExtraFields_BothParserBackends(t *testing.T) {
	cfg, err := extrafields.Parse([]byte(extraFieldsTestConfig))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"owner_contact": {"payments@example.com"}}

	for _, protobom := range []bool{false, true} {
		sbom.SetUseProtobom(protobom)
		res, err := sbom.Parse(bytes.NewReader([]byte(extraFieldsTestBOM)), "payments.cdx.json", "deadbeef")
		if err != nil {
			t.Fatalf("protobom=%v: parse: %v", protobom, err)
		}
		applyExtraFields(&res.SBOM, []byte(extraFieldsTestBOM), cfg)
		if !reflect.DeepEqual(res.SBOM.ExtraFields, want) {
			t.Errorf("protobom=%v: ExtraFields = %#v, want %#v", protobom, res.SBOM.ExtraFields, want)
		}
	}
	sbom.SetUseProtobom(false)
}

func TestApplyExtraFields_NoConfigLeavesRowUnchanged(t *testing.T) {
	res, err := sbom.Parse(bytes.NewReader([]byte(extraFieldsTestBOM)), "payments.cdx.json", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	applyExtraFields(&res.SBOM, []byte(extraFieldsTestBOM), nil)
	if res.SBOM.ExtraFields != nil {
		t.Fatalf("ExtraFields = %#v, want nil without config", res.SBOM.ExtraFields)
	}
}
