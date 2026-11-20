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

func TestValidate(t *testing.T) {
	cases := []struct {
		input string
		valid bool
	}{
		{"", true},
		{"   ", true},
		{"cluster-scan", true},
		{"ci", true},
		{"CI", true},
		{" ci ", true},
		{"registry", true},
		{"vendor", true},
		{"manual", true},
		{"production", false},
		{"unknown", false},
	}
	for _, tc := range cases {
		err := Validate(tc.input)
		if tc.valid && err != nil {
			t.Errorf("Validate(%q) unexpected error: %v", tc.input, err)
		}
		if !tc.valid && err == nil {
			t.Errorf("Validate(%q) expected error, got nil", tc.input)
		}
	}
}
