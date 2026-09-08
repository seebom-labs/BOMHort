package sbomname

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestNeedsFallback(t *testing.T) {
	for _, name := range []string{"", " \n\t", "tmp", "tmp.ABC123xyz", "/tmp/tmp.ABC123xyz", "/tmp/tmp.ABC123xyz/", `C:\Temp\tmp.ABC123xyz`} {
		if !NeedsFallback(name) {
			t.Errorf("expected fallback for %q", name)
		}
	}
	for _, name := range []string{"project", "tmp-utils", "tmp.txt", "tmp.tool", "org/tmp.ABC123xyz", "Production tmp.ABC123xyz", "  Release Name  "} {
		if NeedsFallback(name) {
			t.Errorf("must preserve meaningful name %q", name)
		}
	}
}

func TestResolvePreservesExistingNameWithoutReparsing(t *testing.T) {
	name := "  My Project 1.0  "
	got, err := Resolve([]byte("not needed for a valid name"), name, "source.json")
	if err != nil || got != name {
		t.Fatalf("got %q, %v; want original verbatim", got, err)
	}
}

func TestResolveSPDX(t *testing.T) {
	const packages = `"packages":[{"SPDXID":"dep","name":"wrong-dependency","versionInfo":"9"},{"SPDXID":"root","name":"example/widget","versionInfo":"v1.2.3"}]`
	for _, tt := range []struct {
		name, fields, want string
	}{
		{"documentDescribes", `"documentDescribes":["root"],` + packages, "example/widget v1.2.3"},
		{"DESCRIBES", `"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"root"}],` + packages, "example/widget v1.2.3"},
		{"DESCRIBED_BY", `"relationships":[{"spdxElementId":"root","relationshipType":"DESCRIBED_BY","relatedSpdxElement":"SPDXRef-DOCUMENT"}],` + packages, "example/widget v1.2.3"},
		{"duplicate references", `"documentDescribes":["root","root"],"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"root"}],` + packages, "example/widget v1.2.3"},
		{"custom document ID", `"SPDXID":"document","relationships":[{"spdxElementId":"document","relationshipType":"DESCRIBES","relatedSpdxElement":"root"}],` + packages, "example/widget v1.2.3"},
		{"missing roots", packages, "team/widget/v1/widget"},
		{"unrelated DESCRIBES", `"relationships":[{"spdxElementId":"dep","relationshipType":"DESCRIBES","relatedSpdxElement":"root"}],` + packages, "team/widget/v1/widget"},
		{"multiple roots", `"documentDescribes":["dep","root"],` + packages, "team/widget/v1/widget"},
		{"dangling root", `"documentDescribes":["missing"],` + packages, "team/widget/v1/widget"},
		{"partly dangling roots", `"documentDescribes":["missing","root"],` + packages, "team/widget/v1/widget"},
		{"empty root reference", `"documentDescribes":[""],` + packages, "team/widget/v1/widget"},
		{"temporary root", `"documentDescribes":["root"],"packages":[{"SPDXID":"root","name":"tmp.ABC123xyz","versionInfo":"1"}]`, "team/widget/v1/widget"},
		{"empty root name", `"documentDescribes":["root"],"packages":[{"SPDXID":"root","name":"","versionInfo":"1"}]`, "team/widget/v1/widget"},
		{"duplicate package IDs", `"documentDescribes":["root"],"packages":[{"SPDXID":"root","name":"a"},{"SPDXID":"root","name":"b"}]`, "team/widget/v1/widget"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(`{"spdxVersion":"SPDX-2.3","name":"tmp.ABC123xyz",` + tt.fields + `}`)
			original := append([]byte(nil), data...)
			got, err := Resolve(data, "tmp.ABC123xyz", "s3://bucket/team/widget/v1/widget.spdx.json")
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
			if !bytes.Equal(data, original) {
				t.Fatal("source bytes were mutated")
			}
		})
	}
}

func TestResolveEnvelopeAndCycloneDX(t *testing.T) {
	for _, tt := range []struct{ name, data, want string }{
		{"envelope", `{"predicateType":"https://spdx.dev/Document","predicate":{"spdxVersion":"SPDX-2.3","name":"tmp.ABC123xyz","documentDescribes":["root"],"packages":[{"SPDXID":"root","name":"widget","versionInfo":"1"}]}}`, "widget 1"},
		{"cdx root", `{"bomFormat":"CycloneDX","metadata":{"component":{"name":"widget","version":"1"}}}`, "widget 1"},
		{"cdx serial", `{"bomFormat":"CycloneDX","serialNumber":"urn:uuid:example","metadata":{"component":{"name":"tmp.ABC123xyz","version":"1"}}}`, "urn:uuid:example"},
		{"cdx no root", `{"bomFormat":"CycloneDX","components":[{"name":"dependency"}]}`, "source"},
		{"cdx blank root", `{"bomFormat":"CycloneDX","metadata":{"component":{"name":"","version":"1"}}}`, "source"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve([]byte(tt.data), "", "source.json")
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestVersionPlaceholders(t *testing.T) {
	for _, version := range []string{"", "NOASSERTION", "NONE", "unknown", " UNKNOWN "} {
		if got := withVersion("widget", version); got != "widget" {
			t.Errorf("placeholder %q appended: %q", version, got)
		}
	}
}

func TestSourceFallback(t *testing.T) {
	for _, tt := range []struct{ source, want string }{
		{"s3://bucket/org/project/v1/bom_spdx.json", "org/project/v1/bom"},
		{"s3://bucket/project/v1/file.json", "project/v1/file"},
		{"/tmp/downloads/widget.spdx.json", "widget"},
		{`C:\downloads\widget.cdx.json`, "widget"},
		{"https://user:password@example.org/path/widget.spdx.json?token=secret#fragment", "widget"},
		{"s3://bucket/project%20name/file.SPDX.JSON", "project name/file"},
		{"", "Unnamed SBOM"},
		{"/tmp/tmp.ABC123xyz.json", "Unnamed SBOM"},
		{"s3://bucket/", "Unnamed SBOM"},
		{"https://%invalid", "Unnamed SBOM"},
	} {
		t.Run(tt.source, func(t *testing.T) {
			got, err := Resolve([]byte(`{}`), "", tt.source)
			if err != nil || got != tt.want {
				t.Fatalf("got %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

func TestResolveInvalidJSON(t *testing.T) {
	for _, data := range []string{`{`, `{"predicateType":"spdx","predicate":[]}`} {
		if _, err := Resolve([]byte(data), "", "source.json"); err == nil {
			t.Errorf("expected error for %s", data)
		}
	}
}

func TestResolveXMLUsesSource(t *testing.T) {
	got, err := Resolve([]byte(`<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>`), "", "widget.xml")
	if err != nil || got != "widget.xml" {
		t.Fatalf("got %q, %v; want source fallback for XML", got, err)
	}
}

func TestResolutionLogPreservesOriginalWithoutSourceSecrets(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	_, err := Resolve([]byte(`{}`), "tmp.ABC123xyz", "https://user:password@example.org/widget.json?token=secret")
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, `original="tmp.ABC123xyz"`) || !strings.Contains(text, `resolved="widget"`) {
		t.Fatalf("missing name provenance: %s", text)
	}
	if strings.Contains(text, "password") || strings.Contains(text, "secret") {
		t.Fatalf("source credentials leaked: %s", text)
	}
}
