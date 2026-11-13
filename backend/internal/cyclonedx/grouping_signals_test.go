package cyclonedx

import "testing"

func parseCDXSignals(t *testing.T, doc string) (purl, supplier string) {
	t.Helper()
	res, err := Parse([]byte(doc), "test.cdx.json", "hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return res.SBOM.RootPURL, res.SBOM.Supplier
}

func TestGroupingSignalsManufacturerWins(t *testing.T) {
	purl, supplier := parseCDXSignals(t, `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {
				"type": "application", "name": "ledger", "version": "2.0.1",
				"purl": "pkg:maven/com.acme.payments/ledger@2.0.1",
				"supplier": {"name": "ACME Distribution"}
			},
			"manufacturer": {"name": "ACME Corp"},
			"supplier": {"name": "Reseller GmbH"}
		},
		"components": [{"type": "library", "name": "jackson", "purl": "pkg:maven/com.fasterxml/jackson@2.17", "supplier": {"name": "FasterXML"}}]
	}`)
	if purl != "pkg:maven/com.acme.payments/ledger@2.0.1" {
		t.Errorf("root purl = %q", purl)
	}
	if supplier != "ACME Corp" {
		t.Errorf("supplier = %q, want the manufacturer ACME Corp", supplier)
	}
}

func TestImageIdentityFromRootPURL(t *testing.T) {
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res, err := Parse([]byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.6",
		"metadata":{"component":{"type":"container","name":"api","purl":"pkg:oci/acme/api@`+digest+`?repository_url=ghcr.io%2Facme%2Fapi"}}
	}`), "api.cdx.json", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if res.SBOM.ImageRef != "ghcr.io/acme/api" || res.SBOM.ImageDigest != digest {
		t.Errorf("image identity = (%q, %q)", res.SBOM.ImageRef, res.SBOM.ImageDigest)
	}
}

// CycloneDX 1.5 spelled it "manufacture".
func TestGroupingSignalsManufacture15(t *testing.T) {
	_, supplier := parseCDXSignals(t, `{
		"bomFormat": "CycloneDX", "specVersion": "1.5",
		"metadata": {"component": {"type": "application", "name": "x"}, "manufacture": {"name": "Initech"}}
	}`)
	if supplier != "Initech" {
		t.Errorf("supplier = %q, want Initech", supplier)
	}
}

func TestGroupingSignalsSupplierFallbacks(t *testing.T) {
	_, supplier := parseCDXSignals(t, `{
		"bomFormat": "CycloneDX", "specVersion": "1.6",
		"metadata": {"component": {"type": "application", "name": "x", "supplier": {"name": "Component Supplier"}}}
	}`)
	if supplier != "Component Supplier" {
		t.Errorf("supplier = %q, want the component's supplier as last fallback", supplier)
	}

	purl, supplier := parseCDXSignals(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}}`)
	if purl != "" || supplier != "" {
		t.Errorf("no metadata.component → (%q, %q), want empty", purl, supplier)
	}
}

// Documents that parsed before the grouping signals existed must keep
// parsing: a bare string is read leniently, anything else is ignored.
func TestGroupingSignalsNeverFailTheDocument(t *testing.T) {
	_, supplier := parseCDXSignals(t, `{
		"bomFormat": "CycloneDX", "specVersion": "1.6",
		"metadata": {"component": {"type": "application", "name": "x"}, "manufacturer": "ACME as a string"}
	}`)
	if supplier != "ACME as a string" {
		t.Errorf("string manufacturer = %q", supplier)
	}
	for _, odd := range []string{`42`, `["a"]`, `true`, `null`} {
		res, err := Parse([]byte(`{
			"bomFormat": "CycloneDX", "specVersion": "1.6",
			"metadata": {"component": {"type": "application", "name": "x", "supplier": `+odd+`}, "manufacturer": `+odd+`, "supplier": `+odd+`},
			"components": [{"type": "library", "name": "dep", "supplier": `+odd+`}]
		}`), "odd.cdx.json", "hash")
		if err != nil {
			t.Errorf("supplier/manufacturer %s failed the document: %v", odd, err)
			continue
		}
		if res.SBOM.Supplier != "" {
			t.Errorf("supplier/manufacturer %s → %q, want empty", odd, res.SBOM.Supplier)
		}
	}
}
