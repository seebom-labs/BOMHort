package clearlydefined

import (
	"strings"
	"testing"
)

func TestGetLicenseText_CompleteCanonicalTexts(t *testing.T) {
	// Apache-2.0 must be the full unabbreviated text including section 9 and end of terms (#530).
	apache := GetLicenseText("Apache-2.0")
	if !strings.Contains(apache, "9. Accepting Warranty or Additional Liability.") {
		t.Errorf("Apache-2.0 text missing section 9: %s", apache[:min(300, len(apache))])
	}
	if !strings.Contains(apache, "END OF TERMS AND CONDITIONS") {
		t.Errorf("Apache-2.0 text missing end of terms and conditions")
	}

	// MPL-2.0 must be the full unabbreviated text including section 10.4, Exhibit A, and Exhibit B (#530).
	mpl := GetLicenseText("MPL-2.0")
	if !strings.Contains(mpl, "10.4. Distributing Source Code Form") {
		t.Errorf("MPL-2.0 text missing section 10.4: %s", mpl[:min(300, len(mpl))])
	}
	if !strings.Contains(mpl, "Exhibit A - Source Code Form License Notice") {
		t.Errorf("MPL-2.0 text missing Exhibit A")
	}
	if !strings.Contains(mpl, "Exhibit B") {
		t.Errorf("MPL-2.0 text missing Exhibit B")
	}

	// MIT full text
	mit := GetLicenseText("MIT")
	if !strings.Contains(mit, "Permission is hereby granted, free of charge") || !strings.Contains(mit, "THE SOFTWARE IS PROVIDED \"AS IS\"") {
		t.Errorf("MIT text incomplete: %s", mit)
	}

	// Aliases
	if GetLicenseText("Apache-2") != apache {
		t.Errorf("Apache-2 alias did not return Apache-2.0 text")
	}
	if GetLicenseText("GPL-2.0") != GetLicenseText("GPL-2.0-only") {
		t.Errorf("GPL-2.0 alias did not return GPL-2.0-only text")
	}

	// Unknown license fallback
	unknown := GetLicenseText("Unknown-Custom-1.0")
	if !strings.Contains(unknown, "Please refer to the upstream component repository") {
		t.Errorf("Unknown license did not return fallback text: %s", unknown)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
