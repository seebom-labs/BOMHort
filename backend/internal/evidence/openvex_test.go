package evidence

import (
	"testing"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

func TestIsReachabilityVEX(t *testing.T) {
	tests := []struct {
		name       string
		stmt       models.VEXStatement
		wantStatus string
		wantOK     bool
	}{
		{
			name: "justification vulnerable_code_not_in_execute_path",
			stmt: models.VEXStatement{
				Justification: "vulnerable_code_not_in_execute_path",
			},
			wantStatus: models.ReachabilityNotReachable,
			wantOK:     true,
		},
		{
			name: "impact_statement reachability: reachable",
			stmt: models.VEXStatement{
				ImpactStatement: "reachability: reachable per symbol trace",
			},
			wantStatus: models.ReachabilityReachable,
			wantOK:     true,
		},
		{
			name: "impact_statement govulncheck: unreachable",
			stmt: models.VEXStatement{
				ImpactStatement: "govulncheck: unreachable function",
			},
			wantStatus: models.ReachabilityNotReachable,
			wantOK:     true,
		},
		{
			name: "unrelated justification and statement",
			stmt: models.VEXStatement{
				Justification:   "inline_mitigations_already_exist",
				ImpactStatement: "WAF blocks malicious payload",
			},
			wantStatus: "",
			wantOK:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, ok := IsReachabilityVEX(tc.stmt)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", status, tc.wantStatus)
			}
		})
	}
}

