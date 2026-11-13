package spdx

import (
	"strings"
	"testing"
)

// Grouping signals (root purl, supplier) feed the parent grouping of
// projects. They come from the described root only.

func parseSignals(t *testing.T, doc string) (purl, supplier string) {
	t.Helper()
	res, err := Parse(strings.NewReader(doc), "test.spdx.json", "hash")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	return res.SBOM.RootPURL, res.SBOM.Supplier
}

func TestGroupingSignalsFromRoot(t *testing.T) {
	purl, supplier := parseSignals(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "ledger",
		"documentDescribes": ["SPDXRef-Package-ledger"],
		"packages": [
			{
				"SPDXID": "SPDXRef-Package-ledger",
				"name": "ledger",
				"supplier": "Organization: ACME Corp",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:maven/com.acme.payments/ledger@2.0.1"}]
			},
			{
				"SPDXID": "SPDXRef-Package-dep",
				"name": "jackson",
				"supplier": "Organization: FasterXML",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:maven/com.fasterxml/jackson@2.17"}]
			}
		]
	}`)
	if purl != "pkg:maven/com.acme.payments/ledger@2.0.1" {
		t.Errorf("root purl = %q", purl)
	}
	if supplier != "ACME Corp" {
		t.Errorf("supplier = %q, want ACME Corp (prefix stripped, dependency ignored)", supplier)
	}
}

func TestImageIdentityFromRootPURL(t *testing.T) {
	digest := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	res, err := Parse(strings.NewReader(`{
		"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"api",
		"documentDescribes":["SPDXRef-Package-api"],
		"packages":[{"SPDXID":"SPDXRef-Package-api","name":"api",
			"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:oci/acme/api@`+digest+`?repository_url=ghcr.io%2Facme%2Fapi"}]}]
	}`), "api.spdx.json", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if res.SBOM.ImageRef != "ghcr.io/acme/api" || res.SBOM.ImageDigest != digest {
		t.Errorf("image identity = (%q, %q)", res.SBOM.ImageRef, res.SBOM.ImageDigest)
	}
}

// Originator is the fallback, a Person's email is dropped, NOASSERTION is
// nothing.
func TestGroupingSignalsSupplierFallbacks(t *testing.T) {
	cases := []struct {
		supplier, originator, want string
	}{
		{"NOASSERTION", "Person: Jane Doe (jane@example.com)", "Jane Doe"},
		{"", "Organization: Initech", "Initech"},
		{"NOASSERTION", "NOASSERTION", ""},
		{"organization: lower case", "", "lower case"},
	}
	for _, tc := range cases {
		_, got := parseSignals(t, `{
			"spdxVersion": "SPDX-2.3",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "app",
			"documentDescribes": ["SPDXRef-Package-app"],
			"packages": [{"SPDXID": "SPDXRef-Package-app", "name": "app", "supplier": "`+tc.supplier+`", "originator": "`+tc.originator+`"}]
		}`)
		if got != tc.want {
			t.Errorf("supplier %q / originator %q → %q, want %q", tc.supplier, tc.originator, got, tc.want)
		}
	}
}

// Without a described root nothing is attributed: packages[0] may be a
// dependency, exactly as for source_repo.
func TestGroupingSignalsNeedARoot(t *testing.T) {
	purl, supplier := parseSignals(t, `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "app",
		"packages": [{
			"SPDXID": "SPDXRef-Package-dep",
			"name": "dep",
			"supplier": "Organization: Someone Else",
			"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/dep@1.0.0"}]
		}]
	}`)
	if purl != "" || supplier != "" {
		t.Errorf("signals guessed without a root: (%q, %q)", purl, supplier)
	}
}

// Documents that parsed before the grouping signals existed must keep
// parsing, whatever a generator put into these fields.
func TestGroupingSignalsNeverFailTheDocument(t *testing.T) {
	for _, field := range []string{`"supplier": {"name": "ACME"}`, `"supplier": 42`, `"originator": ["x"]`, `"supplier": null`} {
		purl, supplier := parseSignals(t, `{
			"spdxVersion": "SPDX-2.3",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "app",
			"documentDescribes": ["SPDXRef-Package-app"],
			"packages": [{"SPDXID": "SPDXRef-Package-app", "name": "app", `+field+`}]
		}`)
		if purl != "" || supplier != "" {
			t.Errorf("%s: unexpected signals (%q, %q)", field, purl, supplier)
		}
	}
}
