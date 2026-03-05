package model

import "strings"

// IsIdentityBearingFinding returns whether a finding participates in lifecycle/regress identity state.
func IsIdentityBearingFinding(f Finding) bool {
	return isBearingFinding(f, identityBearingExclusions)
}

// IsInventoryBearingFinding returns whether a finding should materialize inventory entities.
func IsInventoryBearingFinding(f Finding) bool {
	return isBearingFinding(f, inventoryBearingExclusions)
}

var identityBearingExclusions = map[string]struct{}{
	"policy_check":        {},
	"policy_violation":    {},
	"parse_error":         {},
	"ai_project_signal":   {},
	"skill_metrics":       {},
	"skill_contribution":  {},
	"mcp_gateway_posture": {},
}

var inventoryBearingExclusions = map[string]struct{}{
	"policy_check":        {},
	"policy_violation":    {},
	"parse_error":         {},
	"ai_project_signal":   {},
	"skill_metrics":       {},
	"skill_contribution":  {},
	"mcp_gateway_posture": {},
}

func isBearingFinding(f Finding, exclusions map[string]struct{}) bool {
	if strings.TrimSpace(f.ToolType) == "" {
		return false
	}
	_, excluded := exclusions[strings.ToLower(strings.TrimSpace(f.FindingType))]
	return !excluded
}
