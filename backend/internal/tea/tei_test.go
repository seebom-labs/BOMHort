package tea

import (
	"testing"
)

func TestTEIEncodingAndParsing(t *testing.T) {
	origPURL := "pkg:golang/github.com/seebom-labs/bomhort@v0.8.0"

	// 1. Encode into tei:// and parse back
	teiURI := EncodePURLTEI("products.example.com", origPURL)
	if teiURI == "" {
		t.Fatal("expected non-empty teiURI")
	}

	parsed, err := ParseTEI(teiURI)
	if err != nil {
		t.Fatalf("ParseTEI(%q) failed: %v", teiURI, err)
	}
	if parsed.Domain != "products.example.com" {
		t.Errorf("Domain = %q, want 'products.example.com'", parsed.Domain)
	}
	if parsed.Type != "purl" {
		t.Errorf("Type = %q, want 'purl'", parsed.Type)
	}
	if parsed.PURL != origPURL {
		t.Errorf("PURL = %q, want %q", parsed.PURL, origPURL)
	}

	// 2. Encode into urn:tei: and parse back
	urnTEI := EncodeURNTEI(origPURL)
	parsedURN, err := ParseTEI(urnTEI)
	if err != nil {
		t.Fatalf("ParseTEI(%q) failed: %v", urnTEI, err)
	}
	if parsedURN.Type != "purl" {
		t.Errorf("Type = %q, want 'purl'", parsedURN.Type)
	}
	if parsedURN.PURL != origPURL {
		t.Errorf("PURL = %q, want %q", parsedURN.PURL, origPURL)
	}

	// 3. Official spec example from tei-types/purl.md:
	// tei://example.com/purl/cGtnOm1hdmVuL2NvbW1vbnMtaW8vY29tbW9ucy1pb0AyLjIyLjA
	specExample := "tei://example.com/purl/cGtnOm1hdmVuL2NvbW1vbnMtaW8vY29tbW9ucy1pb0AyLjIyLjA"
	parsedSpec, err := ParseTEI(specExample)
	if err != nil {
		t.Fatalf("ParseTEI(specExample) failed: %v", err)
	}
	wantSpecPURL := "pkg:maven/commons-io/commons-io@2.22.0"
	if parsedSpec.PURL != wantSpecPURL {
		t.Errorf("PURL = %q, want %q", parsedSpec.PURL, wantSpecPURL)
	}

	// 4. Raw PURL passed directly into URN: urn:tei:purl:pkg:maven/org.apache/log4j@2.24.3
	rawURN := "urn:tei:purl:pkg:maven/org.apache/log4j@2.24.3"
	parsedRaw, err := ParseTEI(rawURN)
	if err != nil {
		t.Fatalf("ParseTEI(%q) failed: %v", rawURN, err)
	}
	if parsedRaw.PURL != "pkg:maven/org.apache/log4j@2.24.3" {
		t.Errorf("PURL = %q, want 'pkg:maven/org.apache/log4j@2.24.3'", parsedRaw.PURL)
	}

	// 5. UUID type TEI: tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1
	uuidTEI := "tei://example.com/uuid/d4d9f54a-abcf-11ee-ac79-1a52914d44b1"
	parsedUUID, err := ParseTEI(uuidTEI)
	if err != nil {
		t.Fatalf("ParseTEI(uuidTEI) failed: %v", err)
	}
	if parsedUUID.UUID != "d4d9f54a-abcf-11ee-ac79-1a52914d44b1" {
		t.Errorf("UUID = %q, want 'd4d9f54a-abcf-11ee-ac79-1a52914d44b1'", parsedUUID.UUID)
	}
}

func TestParseTEI_Invalid(t *testing.T) {
	invalidCases := []string{
		"",
		"http://example.com",
		"tei://incomplete",
		"tei://domain/purl/",
		"urn:tei:",
		"urn:tei:unknown",
		"tei://example.com/uuid/not-a-valid-uuid",
	}

	for _, tc := range invalidCases {
		_, err := ParseTEI(tc)
		if err == nil {
			t.Errorf("expected error for ParseTEI(%q), got nil", tc)
		}
	}
}
