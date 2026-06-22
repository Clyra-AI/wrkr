package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func bomItemEligible(item AgentActionBOMItem) bool {
	if item.ActionPathEligible {
		return true
	}
	if strings.TrimSpace(item.ActionBindingState) != "" {
		return item.ActionPathEligible
	}
	if strings.TrimSpace(item.ExclusionReason) != "" {
		return false
	}
	return strings.TrimSpace(item.ConfidenceLane) != risk.ConfidenceLaneContextOnly
}

func bomItemBindingState(item AgentActionBOMItem) string {
	if strings.TrimSpace(item.ActionBindingState) != "" {
		return strings.TrimSpace(item.ActionBindingState)
	}
	if bomItemEligible(item) {
		if strings.TrimSpace(item.ConfidenceLane) == risk.ConfidenceLaneSemanticReviewCandidate {
			return risk.ActionBindingStatePartiallyBound
		}
		return risk.ActionBindingStateBound
	}
	return risk.ActionBindingStateUnboundContext
}

func bomItemPromotableActionPath(item AgentActionBOMItem) bool {
	if !bomItemEligible(item) {
		return false
	}
	if strings.TrimSpace(item.ConfidenceLane) == risk.ConfidenceLaneContextOnly {
		return false
	}
	switch strings.TrimSpace(item.ActionPathType) {
	case "":
		return !bomItemStaticContextSurface(item)
	case risk.ActionPathTypePlainSourceCode:
		return !bomItemStaticContextSurface(item)
	case risk.ActionPathTypeDependencyOnlySignal:
		return false
	case risk.ActionPathTypeCICDWorkflow,
		risk.ActionPathTypeAIAssistedWorkflow,
		risk.ActionPathTypeAgentFramework,
		risk.ActionPathTypeAgentInstruction,
		risk.ActionPathTypeAutomationBot,
		risk.ActionPathTypeLegacyScript:
		return true
	case risk.ActionPathTypeUnknownExecutablePath:
		return item.CredentialAccess ||
			item.StandingPrivilege ||
			len(item.WorkflowChainRefs) > 0 ||
			len(item.AuthorityBindingRefs) > 0 ||
			strings.TrimSpace(item.CredentialAuthorityRef) != ""
	default:
		return item.CredentialAccess ||
			item.StandingPrivilege ||
			len(item.WorkflowChainRefs) > 0 ||
			len(item.AuthorityBindingRefs) > 0 ||
			strings.TrimSpace(item.CredentialAuthorityRef) != ""
	}
}

func bomItemStaticContextSurface(item AgentActionBOMItem) bool {
	toolType := strings.TrimSpace(strings.ToLower(item.ToolType))
	switch toolType {
	case "openapi", "route", "dependency":
		return true
	}
	location := strings.TrimSpace(strings.ToLower(strings.ReplaceAll(item.Location, "\\", "/")))
	if strings.Contains(location, "openapi") ||
		strings.Contains(location, "swagger") ||
		strings.Contains(location, "/routes/") ||
		strings.Contains(location, "/route/") ||
		strings.Contains(location, "/schema/") ||
		strings.Contains(location, "/schemas/") ||
		strings.Contains(location, "/spec/") ||
		strings.Contains(location, "/specs/") {
		return len(item.WorkflowChainRefs) == 0 && len(item.RuntimeSessionRefs) == 0 && len(item.ObservedSessionActions) == 0
	}
	return false
}
