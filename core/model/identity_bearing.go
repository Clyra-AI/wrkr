package model

import "strings"

// IsIdentityBearingFinding returns whether a finding participates in lifecycle/regress identity state.
func IsIdentityBearingFinding(f Finding) bool {
	if strings.TrimSpace(f.ToolType) == "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(f.FindingType)) {
	case "policy_check", "policy_violation", "parse_error":
		return false
	default:
		return true
	}
}
