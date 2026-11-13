package evidence

import (
	"strings"

	"github.com/seebom-labs/bomhort/backend/pkg/models"
)

// IsReachabilityVEX determines if an OpenVEX statement provides reachability evidence.
// It returns the reachability status ("reachable" or "not_reachable") and true if
// the statement qualifies as reachability evidence.
func IsReachabilityVEX(stmt models.VEXStatement) (status string, ok bool) {
	// 1. Explicit OpenVEX justification for unreachability
	if stmt.Justification == "vulnerable_code_not_in_execute_path" {
		return models.ReachabilityNotReachable, true
	}

	// 2. Recognised impact_statement prefix
	impact := strings.TrimSpace(strings.ToLower(stmt.ImpactStatement))
	switch {
	case strings.HasPrefix(impact, "reachability: reachable"),
		strings.HasPrefix(impact, "govulncheck: reachable"):
		return models.ReachabilityReachable, true
	case strings.HasPrefix(impact, "reachability: not_reachable"),
		strings.HasPrefix(impact, "reachability: unreachable"),
		strings.HasPrefix(impact, "govulncheck: not_reachable"),
		strings.HasPrefix(impact, "govulncheck: unreachable"):
		return models.ReachabilityNotReachable, true
	}

	return "", false
}

