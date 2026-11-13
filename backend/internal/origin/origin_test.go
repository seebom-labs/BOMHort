package origin

import "testing"

func TestNormalizeAndValidate(t *testing.T) {
	if got := Normalize(" CI "); got != "ci" {
		t.Fatalf("Normalize() = %q, want ci", got)
	}
	for _, value := range []string{"cluster-scan", "ci", "registry", "vendor", "manual"} {
		if !IsValid(value) {
			t.Errorf("IsValid(%q) = false", value)
		}
	}
	for _, value := range []string{"", "unknown", "CI"} {
		if IsValid(value) {
			t.Errorf("IsValid(%q) = true", value)
		}
	}
}
