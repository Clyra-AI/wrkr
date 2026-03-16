package report

import (
	"fmt"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	activationTargetModeMySetup     = "my_setup"
	activationDefaultLimit          = 5
	activationReasonNoConcreteItems = "no_concrete_activation_items"
)

// BuildActivation projects a first-value view for local-machine scans without mutating raw risk ranking.
func BuildActivation(targetMode string, ranked []risk.ScoredFinding, limit int) *ActivationSummary {
	if strings.TrimSpace(targetMode) != activationTargetModeMySetup {
		return nil
	}
	if limit <= 0 {
		limit = activationDefaultLimit
	}

	items := make([]ActivationItem, 0, limit)
	eligibleCount := 0
	suppressedPolicyItems := false

	for _, item := range ranked {
		if isPolicyOnlyActivationFinding(item.Finding) {
			suppressedPolicyItems = true
			continue
		}
		if !isConcreteActivationFinding(item.Finding) {
			continue
		}
		eligibleCount++
		if len(items) >= limit {
			continue
		}
		items = append(items, ActivationItem{
			Rank:        len(items) + 1,
			RiskScore:   item.Score,
			FindingType: strings.TrimSpace(item.Finding.FindingType),
			ToolType:    strings.TrimSpace(item.Finding.ToolType),
			Severity:    strings.TrimSpace(item.Finding.Severity),
			Location:    strings.TrimSpace(item.Finding.Location),
			Repo:        strings.TrimSpace(item.Finding.Repo),
			NextStep:    activationNextStep(item.Finding),
		})
	}

	if eligibleCount == 0 {
		return &ActivationSummary{
			TargetMode:    activationTargetModeMySetup,
			Message:       "No concrete local tool, MCP, or secret signals were ranked for activation.",
			EligibleCount: 0,
			Reason:        activationReasonNoConcreteItems,
			Items:         []ActivationItem{},
		}
	}

	message := fmt.Sprintf("Review %d concrete local AI tool, MCP, or secret signal(s) first.", eligibleCount)
	if suppressedPolicyItems {
		message += " Policy-only items remain in the raw ranking but are suppressed from this activation view."
	}

	return &ActivationSummary{
		TargetMode:            activationTargetModeMySetup,
		Message:               message,
		EligibleCount:         eligibleCount,
		SuppressedPolicyItems: suppressedPolicyItems,
		Items:                 items,
	}
}

func isPolicyOnlyActivationFinding(finding model.Finding) bool {
	if strings.TrimSpace(finding.ToolType) == "policy" {
		return true
	}
	return strings.HasPrefix(strings.TrimSpace(finding.FindingType), "policy_")
}

func isConcreteActivationFinding(finding model.Finding) bool {
	if isPolicyOnlyActivationFinding(finding) {
		return false
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "source_discovery":
		return false
	default:
		return true
	}
}

func activationNextStep(finding model.Finding) string {
	if remediation := strings.TrimSpace(finding.Remediation); remediation != "" {
		return remediation
	}

	switch {
	case finding.FindingType == "mcp_server":
		return "Review this MCP surface for requested permissions, transport, and trust status."
	case finding.FindingType == "secret_presence" || finding.ToolType == "secret":
		return "Review local credential usage without exposing raw values."
	case finding.FindingType == "parse_error":
		return "Fix this local config parse issue so Wrkr can see the full posture."
	case finding.ToolType == "agent_project" || finding.FindingType == "tool_config":
		return "Inspect this local tool or project config to confirm intended behavior."
	default:
		return "Inspect this local AI tooling signal and decide whether it matches your intended setup."
	}
}
