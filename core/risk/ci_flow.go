package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

const (
	CIFlowClassStandardGovernedCI           = "standard_governed_ci"
	CIFlowClassBroadStandingAuthority       = "ci_with_broad_standing_authority"
	CIFlowClassReachableFromUntrustedPR     = "ci_reachable_from_untrusted_pr"
	CIFlowClassEditingReleaseOrWorkflowPath = "ci_editing_release_or_workflow_path"
	CIFlowClassAgenticCIFlow                = "agentic_ci_flow"
	CIFlowClassProductionOrReleaseAction    = "production_or_release_action_path"
)

func deriveCIFlowClassification(path ActionPath) (string, []string) {
	if !pathLooksLikeCIWorkflow(path) {
		return "", nil
	}

	reasons := []string{"ci_flow:workflow_surface"}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}

	switch {
	case ciPathHasAgenticInfluence(path):
		add("ci_flow:agentic")
		return CIFlowClassAgenticCIFlow, dedupeSortedStrings(reasons)
	case standingCredentialWithBroadAuthority(path):
		add("ci_flow:broad_standing_authority")
		return CIFlowClassBroadStandingAuthority, dedupeSortedStrings(reasons)
	case ciPathReachableFromUntrustedPR(path):
		add("ci_flow:pull_request_reachable")
		return CIFlowClassReachableFromUntrustedPR, dedupeSortedStrings(reasons)
	case pathHasHighImpactDeliveryEvidence(path):
		add("ci_flow:production_or_release_reach")
		return CIFlowClassProductionOrReleaseAction, dedupeSortedStrings(reasons)
	case ciPathEditsReleaseOrWorkflow(path):
		add("ci_flow:workflow_or_release_mutation")
		return CIFlowClassEditingReleaseOrWorkflowPath, dedupeSortedStrings(reasons)
	case legacyStandardCIControlContext(path) || ciPathHasImportedOrDeclaredControls(path):
		add("ci_flow:standard_governed")
		if ciPathHasImportedOrDeclaredControls(path) {
			add("ci_flow:imported_or_declared_controls")
		}
		return CIFlowClassStandardGovernedCI, dedupeSortedStrings(reasons)
	default:
		return "", nil
	}
}

func ciPathHasImportedOrDeclaredControls(path ActionPath) bool {
	switch strings.TrimSpace(path.ControlResolutionState) {
	case ControlResolutionStateExternalControlReference, ControlResolutionStateDeclaredControl, ControlResolutionStateDetectedControl:
		return true
	}
	if len(path.ConstraintEvidenceClasses) > 0 {
		return true
	}
	switch normalizeEvidenceState(path.ApprovalEvidenceState) {
	case EvidenceStateVerified, EvidenceStateDeclared:
		return true
	}
	return false
}

func ciPathReachableFromUntrustedPR(path ActionPath) bool {
	if !path.PullRequestWrite {
		return false
	}
	if pathHasHighImpactDeliveryEvidence(path) || standingCredentialWithBroadAuthority(path) {
		return false
	}
	return !ciPathHasImportedOrDeclaredControls(path)
}

func ciPathEditsReleaseOrWorkflow(path ActionPath) bool {
	location := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path.Location), "\\", "/"))
	if strings.Contains(location, ".github/workflows/") && containsAnyPathClass(path.WritePathClasses,
		agginventory.WritePathWrite,
		agginventory.WritePathRepoWrite,
		agginventory.WritePathReleaseWrite,
		agginventory.WritePathPackagePublish,
	) {
		return true
	}
	return containsAnyPathClass(path.WritePathClasses, agginventory.WritePathReleaseWrite, agginventory.WritePathPackagePublish)
}

func ciPathHasAgenticInfluence(path ActionPath) bool {
	switch strings.TrimSpace(path.ActionPathType) {
	case ActionPathTypeAIAssistedWorkflow, ActionPathTypeAgentFramework, ActionPathTypeAgentInstruction, ActionPathTypeAutomationBot:
		return true
	}
	switch strings.ToLower(strings.TrimSpace(path.ToolType)) {
	case "claude", "codex", "cursor", "copilot", "openai_agents", "langchain", "langgraph", "crewai", "autogen", "llamaindex", "semantic_kernel", "custom_agent":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(path.AutonomyLevel)) {
	case "headless_auto", "headless_gated", "copilot":
		return true
	}
	return len(path.DeliveryHarnesses) > 0 ||
		len(path.ResolverRefs) > 0 ||
		len(path.EvalConfigRefs) > 0 ||
		len(path.WorkflowChainRefs) > 0 ||
		strings.TrimSpace(path.RuntimeProvider) != "" ||
		strings.TrimSpace(path.RuntimeKind) != ""
}
