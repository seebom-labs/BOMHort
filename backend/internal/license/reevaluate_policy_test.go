package license

import (
	"testing"
)

func TestReevaluate_PolicyModeChange(t *testing.T) {
	origMode := GetExpressionMode()
	defer SetExpressionMode(origMode)

	SetExpressionMode(ExpressionModeStrict)

	// In strict mode, "MIT AND GPL-3.0-only" evaluates to copyleft
	catStrict := Categorize("MIT AND GPL-3.0-only")
	if catStrict != CategoryCopyleft {
		t.Fatalf("expected strict mode to categorize as copyleft, got %s", catStrict)
	}

	initialResult := Result{
		LicenseID:            "MIT AND GPL-3.0-only",
		Category:             catStrict,
		PackageCount:         1,
		PackageNames:         []string{"pkg-dual"},
		NonCompliantPackages: []string{"pkg-dual"},
	}

	// Now switch policy expression mode to PermissiveWins
	SetExpressionMode(ExpressionModePermissiveWins)

	// Reevaluate with no exceptions
	rechecked := Reevaluate(initialResult, nil, "my-project")

	// Under permissive-wins, "MIT AND GPL-3.0-only" should now be permissive!
	if rechecked.Category != CategoryPermissive {
		t.Errorf("expected reevaluated Category to be permissive under permissive-wins, got %s", rechecked.Category)
	}
	if len(rechecked.NonCompliantPackages) != 0 {
		t.Errorf("expected no non-compliant packages once classified as permissive, got %v", rechecked.NonCompliantPackages)
	}

	// SameOutcome should return false because category and outcome changed
	if SameOutcome(initialResult, rechecked) {
		t.Error("expected SameOutcome to report false between strict and permissive-wins outcomes")
	}

	// The package identity must survive the permissive classification so a
	// later policy reversal can restore the violation.
	SetExpressionMode(ExpressionModeStrict)
	roundTrip := Reevaluate(rechecked, nil, "my-project")
	if roundTrip.Category != CategoryCopyleft || len(roundTrip.NonCompliantPackages) != 1 ||
		roundTrip.NonCompliantPackages[0] != "pkg-dual" {
		t.Fatalf("strict round trip lost package identity: %+v", roundTrip)
	}
}
