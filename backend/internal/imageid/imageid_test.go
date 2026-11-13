package imageid

import (
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	ref, got, err := ParseRef("ghcr.io/acme/api:1.2@" + digest)
	if err != nil || ref != "ghcr.io/acme/api:1.2" || got != digest {
		t.Fatalf("ParseRef() = (%q, %q, %v)", ref, got, err)
	}
	for _, invalid := range []string{"", "image:latest", "image@sha256:abcd", "image@sha256:" + strings.Repeat("A", 64), "image name@" + digest} {
		if _, _, err := ParseRef(invalid); err == nil {
			t.Errorf("ParseRef(%q) unexpectedly succeeded", invalid)
		}
	}
}

func TestFromPURL(t *testing.T) {
	digest := "sha256:" + strings.Repeat("b", 64)
	ref, got := FromPURL("pkg:oci/acme/api@" + digest + "?repository_url=ghcr.io%2Facme%2Fapi")
	if ref != "ghcr.io/acme/api" || got != digest {
		t.Fatalf("FromPURL() = (%q, %q)", ref, got)
	}
	if _, got := FromPURL("pkg:oci/acme/api@sha256%3A" + strings.Repeat("b", 64)); got != digest {
		t.Errorf("FromPURL() did not decode escaped digest: %q", got)
	}
	if ref, got := FromPURL("pkg:oci/acme/api@1.2.3"); ref != "" || got != "" {
		t.Fatalf("tag-only PURL returned (%q, %q)", ref, got)
	}
}
