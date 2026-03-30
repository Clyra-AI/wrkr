package report

import (
	"fmt"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	activationTargetModeMySetup     = "my_setup"
	activationTargetModeOrg         = "org"
	activationTargetModePath        = "path"
	activationDefaultLimit          = 5
	activationReasonNoConcreteItems = "no_concrete_activation_items"
	activationReasonNoGovernFirst   = "no_govern_first_activation_items"

	activationClassProductionBacked = "production_target_backed"
	activationClassUnknownWrite     = "unknown_to_security_write_path"
	activationClassApprovalGap      = "approval_gap_path"
	activationClassGovernFirst      = "govern_first_candidate"
)

// BuildActivation projects a first-value view for local-machine scans without mutating raw risk ranking.
func BuildActivation(targetMode string, ranked []risk.ScoredFinding, inventory *agginventory.Inventory, actionPaths []risk.ActionPath, limit int) *ActivationSummary {
	if limit == 0 {
		return nil
	}
	if limit < 0 {
		limit = activationDefaultLimit
	}
	switch strings.TrimSpace(targetMode) {
	case activationTargetModeMySetup:
		return buildMySetupActivation(ranked, limit)
	case activationTargetModeOrg, activationTargetModePath:
		if len(actionPaths) > 0 {
			return buildGovernFirstActivationFromPaths(strings.TrimSpace(targetMode), actionPaths, limit)
		}
		return buildGovernFirstActivation(strings.TrimSpace(targetMode), inventory, limit)
	default:
		return nil
	}
}

func buildGovernFirstActivationFromPaths(targetMode string, paths []risk.ActionPath, limit int) *ActivationSummary {
	items := make([]ActivationItem, 0, min(limit, len(paths)))
	for idx, path := range paths {
		if idx >= limit {
			break
		}
		items = append(items, ActivationItem{
			Rank:                     idx + 1,
			RiskScore:                path.RiskScore,
			FindingType:              "activation_path",
			ToolType:                 path.ToolType,
			Severity:                 governFirstPathSeverity(path),
			Location:                 strings.TrimSpace(path.Location),
			Repo:                     strings.TrimSpace(path.Repo),
			NextStep:                 governFirstPathNextStep(path),
			ItemClass:                classifyGovernFirstActionPath(path),
			WriteCapable:             path.WriteCapable,
			ProductionWrite:          path.ProductionWrite,
			ApprovalClassification:   path.RecommendedAction,
			SecurityVisibilityStatus: strings.TrimSpace(path.SecurityVisibilityStatus),
		})
	}
	if len(items) == 0 {
		return &ActivationSummary{
			TargetMode:    targetMode,
			Message:       "No govern-first candidate paths were ranked for activation.",
			EligibleCount: 0,
			Reason:        activationReasonNoGovernFirst,
			Items:         []ActivationItem{},
		}
	}
	return &ActivationSummary{
		TargetMode:    targetMode,
		Message:       fmt.Sprintf("Review %d govern-first candidate path(s) first.", len(paths)),
		EligibleCount: len(paths),
		Items:         items,
	}
}

func buildMySetupActivation(ranked []risk.ScoredFinding, limit int) *ActivationSummary {
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

func buildGovernFirstActivation(targetMode string, inventory *agginventory.Inventory, limit int) *ActivationSummary {
	if inventory == nil {
		return &ActivationSummary{
			TargetMode:    targetMode,
			Message:       "No govern-first candidate paths were ranked for activation.",
			EligibleCount: 0,
			Reason:        activationReasonNoGovernFirst,
			Items:         []ActivationItem{},
		}
	}

	entries := append([]agginventory.AgentPrivilegeMapEntry(nil), inventory.AgentPrivilegeMap...)
	sort.Slice(entries, func(i, j int) bool {
		ai, bi := activationClassPriority(classifyGovernFirstClass(entries[i])), activationClassPriority(classifyGovernFirstClass(entries[j]))
		if ai != bi {
			return ai < bi
		}
		if entries[i].RiskScore != entries[j].RiskScore {
			return entries[i].RiskScore > entries[j].RiskScore
		}
		if entries[i].Org != entries[j].Org {
			return entries[i].Org < entries[j].Org
		}
		if firstRepo(entries[i]) != firstRepo(entries[j]) {
			return firstRepo(entries[i]) < firstRepo(entries[j])
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		return entries[i].AgentID < entries[j].AgentID
	})

	items := make([]ActivationItem, 0, limit)
	eligibleCount := 0
	for _, entry := range entries {
		class := classifyGovernFirstClass(entry)
		if class == "" {
			continue
		}
		eligibleCount++
		if len(items) >= limit {
			continue
		}
		items = append(items, ActivationItem{
			Rank:                     len(items) + 1,
			RiskScore:                entry.RiskScore,
			FindingType:              "activation_path",
			ToolType:                 activationToolType(entry),
			Severity:                 governFirstSeverity(entry, class),
			Location:                 strings.TrimSpace(entry.Location),
			Repo:                     firstRepo(entry),
			NextStep:                 governFirstNextStep(class),
			ItemClass:                class,
			WriteCapable:             entry.WriteCapable,
			ProductionWrite:          entry.ProductionWrite,
			ApprovalClassification:   strings.TrimSpace(entry.ApprovalClassification),
			SecurityVisibilityStatus: strings.TrimSpace(entry.SecurityVisibilityStatus),
		})
	}

	if eligibleCount == 0 {
		return &ActivationSummary{
			TargetMode:    targetMode,
			Message:       "No govern-first candidate paths were ranked for activation.",
			EligibleCount: 0,
			Reason:        activationReasonNoGovernFirst,
			Items:         []ActivationItem{},
		}
	}

	return &ActivationSummary{
		TargetMode:    targetMode,
		Message:       fmt.Sprintf("Review %d govern-first candidate path(s) first.", eligibleCount),
		EligibleCount: eligibleCount,
		Items:         items,
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

func classifyGovernFirstClass(entry agginventory.AgentPrivilegeMapEntry) string {
	switch {
	case entry.ProductionWrite:
		return activationClassProductionBacked
	case entry.WriteCapable && strings.TrimSpace(entry.SecurityVisibilityStatus) == agginventory.SecurityVisibilityUnknownToSecurity:
		return activationClassUnknownWrite
	case entry.WriteCapable && isApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons):
		return activationClassApprovalGap
	case entry.WriteCapable:
		return activationClassGovernFirst
	default:
		return ""
	}
}

func activationClassPriority(class string) int {
	switch class {
	case activationClassProductionBacked:
		return 0
	case activationClassUnknownWrite:
		return 1
	case activationClassApprovalGap:
		return 2
	case activationClassGovernFirst:
		return 3
	default:
		return 99
	}
}

func governFirstSeverity(entry agginventory.AgentPrivilegeMapEntry, class string) string {
	switch class {
	case activationClassProductionBacked, activationClassUnknownWrite:
		return model.SeverityHigh
	case activationClassApprovalGap:
		return model.SeverityMedium
	default:
		if entry.RiskScore >= 7 {
			return model.SeverityMedium
		}
		return model.SeverityLow
	}
}

func governFirstNextStep(class string) string {
	switch class {
	case activationClassProductionBacked:
		return "Review this production-target-backed write path and decide whether proof or control should land first."
	case activationClassUnknownWrite:
		return "Inventory this unknown-to-security write-capable path and assign an explicit review owner."
	case activationClassApprovalGap:
		return "Close the approval gap on this write-capable path before wider rollout."
	default:
		return "Start governance review on this write-capable path and confirm the intended ownership."
	}
}

func classifyGovernFirstActionPath(path risk.ActionPath) string {
	switch {
	case path.ProductionWrite:
		return activationClassProductionBacked
	case path.WriteCapable && strings.TrimSpace(path.SecurityVisibilityStatus) == agginventory.SecurityVisibilityUnknownToSecurity:
		return activationClassUnknownWrite
	case path.WriteCapable && strings.TrimSpace(path.RecommendedAction) == "approval":
		return activationClassApprovalGap
	default:
		return activationClassGovernFirst
	}
}

func governFirstPathSeverity(path risk.ActionPath) string {
	return governFirstSeverity(agginventory.AgentPrivilegeMapEntry{
		RiskScore:                path.RiskScore,
		WriteCapable:             path.WriteCapable,
		ProductionWrite:          path.ProductionWrite,
		ApprovalGapReasons:       append([]string(nil), path.ApprovalGapReasons...),
		SecurityVisibilityStatus: path.SecurityVisibilityStatus,
	}, classifyGovernFirstActionPath(path))
}

func governFirstPathNextStep(path risk.ActionPath) string {
	switch strings.TrimSpace(path.RecommendedAction) {
	case "control":
		return "apply the highest-priority control on this write-capable path and rescan to confirm reduced exposure"
	case "approval":
		return "add or tighten deterministic human approval gates on this path before allowing further automation"
	case "proof":
		return "collect stronger identity, ownership, or deployment proof for this path before approving it"
	default:
		return "inventory and review this path before expanding its privileges"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isApprovalGap(status string, reasons []string) bool {
	if len(reasons) > 0 {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "unknown", "unapproved":
		return true
	default:
		return false
	}
}

func firstRepo(entry agginventory.AgentPrivilegeMapEntry) string {
	if len(entry.Repos) == 0 {
		return ""
	}
	repos := append([]string(nil), entry.Repos...)
	sort.Strings(repos)
	return repos[0]
}

func activationToolType(entry agginventory.AgentPrivilegeMapEntry) string {
	if strings.TrimSpace(entry.Framework) != "" {
		return strings.TrimSpace(entry.Framework)
	}
	return strings.TrimSpace(entry.ToolType)
}
