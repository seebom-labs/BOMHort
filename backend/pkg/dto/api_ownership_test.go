package dto

import (
	"encoding/json"
	"strings"
	"testing"
)

// #177: the list contract exposes the ownership dimensions, so a client can
// tell which cluster/namespace/project a listed SBOM belongs to without a
// second request per row. They stay omitted on single-instance deployments,
// where all three default to ''.

func TestSBOMListItem_OwnershipFieldsSerialized(t *testing.T) {
	item := SBOMListItem{
		SBOMID:       "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		DocumentName: "payment-service",
		Cluster:      "prod-eu",
		Namespace:    "payments",
		Project:      "payment-service",
	}

	b, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	out := string(b)

	for _, want := range []string{
		`"cluster":"prod-eu"`,
		`"namespace":"payments"`,
		`"project":"payment-service"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestSBOMListItem_OwnershipFieldsOmittedWhenUnset(t *testing.T) {
	item := SBOMListItem{
		SBOMID:       "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		DocumentName: "standalone",
	}

	b, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	out := string(b)

	for _, unwanted := range []string{"cluster", "namespace", "project", "source_repo", "source_ref"} {
		if strings.Contains(out, `"`+unwanted+`"`) {
			t.Errorf("unset %q must be omitted, got %s", unwanted, out)
		}
	}
	// The always-present fields must survive the omitempty additions.
	for _, want := range []string{`"sbom_id"`, `"document_name"`, `"package_count"`, `"vuln_count"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing required field %s in %s", want, out)
		}
	}
}
