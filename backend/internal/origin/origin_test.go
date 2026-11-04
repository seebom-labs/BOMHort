package origin

import (
	"testing"
)

func TestOriginValidation(t *testing.T) {
	valid := []string{
		"",
		" ",
		ClusterScan,
		CI,
		Registry,
		Vendor,
		Manual,
	}

	for _, v := range valid {
		if !IsValid(v) {
			t.Errorf("expected %q to be valid", v)
		}
		if err := Validate(v); err != nil {
			t.Errorf("expected %q to pass Validate(), got %v", v, err)
		}
	}

	invalid := []string{
		"unknown",
		"ci/cd",
		"k8s",
		"production",
		"CLUSTER-SCAN",
	}

	for _, inv := range invalid {
		if IsValid(inv) {
			t.Errorf("expected %q to be invalid", inv)
		}
		if err := Validate(inv); err == nil {
			t.Errorf("expected %q to fail Validate(), got nil", inv)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize("  ci  "); got != "ci" {
		t.Errorf("expected \"ci\", got %q", got)
	}
}
