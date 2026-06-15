package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

const (
	ActionBindingStateBound          = "bound"
	ActionBindingStatePartiallyBound = "partially_bound"
	ActionBindingStateUnboundContext = "unbound_context"
	ActionBindingStateContradictory  = "contradictory"
)

func ValidActionBindingState(value string) bool {
	switch strings.TrimSpace(value) {
	case ActionBindingStateBound,
		ActionBindingStatePartiallyBound,
		ActionBindingStateUnboundContext,
		ActionBindingStateContradictory:
		return true
	default:
		return false
	}
}

func IsActionPathEligible(path ActionPath) bool {
	if ValidActionBindingState(path.ActionBindingState) {
		return path.ActionPathEligible
	}
	eligible, _ := deriveActionBindingProjection(path)
	return eligible
}

func IsTargetSurfaceContext(path ActionPath) bool {
	return pathTargetsCorrelationContext(path) && !IsActionPathEligible(path)
}

func IsInstructionControlSurface(path ActionPath) bool {
	return pathIsAgentInstructionControlSurface(path) && !IsActionPathEligible(path)
}

func actionBindingStateForPath(path ActionPath) string {
	if ValidActionBindingState(path.ActionBindingState) {
		return strings.TrimSpace(path.ActionBindingState)
	}
	_, state := deriveActionBindingProjection(path)
	return state
}

func deriveActionBindingProjection(path ActionPath) (bool, string) {
	switch {
	case len(path.Contradictions) > 0,
		actionPathHasContradictoryControlEvidence(path),
		normalizeEvidenceState(path.TargetEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.OwnerEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.ApprovalEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.ProofEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.RuntimeEvidenceState) == EvidenceStateContradictory:
		return false, ActionBindingStateContradictory
	}

	if pathHasExecutableBinding(path) && pathHasGovernableBinding(path) {
		return true, ActionBindingStateBound
	}
	if pathHasContextSurfaceCorrelation(path) {
		return true, ActionBindingStatePartiallyBound
	}
	if pathHasGovernableBinding(path) || pathIsPromptOrInstructionSurface(path) || pathTargetsCorrelationContext(path) {
		return false, ActionBindingStateUnboundContext
	}
	return false, ActionBindingStateUnboundContext
}

func pathHasGovernableBinding(path ActionPath) bool {
	return pathHasPermissionOrTargetSignal(path) ||
		path.CredentialAccess ||
		path.StandingPrivilege ||
		actionPathHasStrongIdentity(path)
}

func pathHasContextSurfaceCorrelation(path ActionPath) bool {
	if pathHasExecutableBinding(path) {
		return true
	}
	if isAgentFrameworkToolType(strings.TrimSpace(strings.ToLower(path.ToolType))) || actionPathHasBotIdentity(path) {
		return true
	}
	if pathIsAgentInstructionControlSurface(path) {
		switch strings.TrimSpace(strings.ToLower(path.ToolType)) {
		case "codex", "claude", "cursor", "skill", "prompt_channel":
			return true
		}
	}
	if path.DeployWrite || strings.EqualFold(strings.TrimSpace(path.DeploymentStatus), "deployed") || hasOperationalTargetCorrelation(path.MatchedProductionTargets) {
		return true
	}
	if actionPathHasStrongIdentity(path) {
		return true
	}
	if hasRuntimeCorrelationEvidence(path) {
		return true
	}
	if path.IntroducedBy != nil && (strings.TrimSpace(path.IntroducedBy.Reference) != "" || strings.TrimSpace(path.IntroducedBy.Timestamp) != "") {
		return true
	}
	for _, binding := range agginventory.NormalizeAuthorityBindings(path.AuthorityBindings) {
		if binding == nil {
			continue
		}
		if strings.TrimSpace(binding.Kind) != "" || strings.TrimSpace(binding.TargetSystem) != "" || strings.TrimSpace(binding.Resource) != "" {
			return true
		}
	}
	if authority := agginventory.NormalizeCredentialAuthority(path.CredentialAuthority); authority != nil {
		if authority.CredentialUsableByPath || authority.CredentialPresent {
			return true
		}
	}
	return false
}

func hasOperationalTargetCorrelation(targets []string) bool {
	for _, target := range targets {
		switch strings.TrimSpace(target) {
		case "built_in:deploy_workflow",
			"built_in:kubernetes",
			"built_in:release_automation",
			"built_in:package_publishing":
			return true
		}
	}
	return false
}

func hasRuntimeCorrelationEvidence(path ActionPath) bool {
	for _, state := range []string{
		normalizeEvidenceState(path.RuntimeEvidenceState),
		normalizeEvidenceState(path.RuntimeContextEvidenceState),
	} {
		switch state {
		case EvidenceStateVerified, EvidenceStateDeclared, EvidenceStateInferred:
			return true
		}
	}
	return strings.TrimSpace(path.RuntimeProvider) != "" ||
		strings.TrimSpace(path.RuntimeHost) != "" ||
		strings.TrimSpace(path.RuntimeKind) != "" ||
		strings.TrimSpace(path.ExecutionEnvironment) != ""
}

func stripUncorrelatedContextAuthority(path ActionPath) ActionPath {
	if !pathTargetsCorrelationContext(path) || pathHasContextSurfaceCorrelation(path) {
		return path
	}
	out := path
	out.CredentialAccess = false
	out.Credentials = nil
	out.CredentialProvenance = nil
	out.CredentialAuthorityRef = ""
	out.CredentialAuthority = nil
	out.AuthorityBindingRefs = nil
	out.AuthorityBindings = nil
	out.StandingPrivilege = false
	out.StandingPrivilegeReasons = nil
	return out
}

func pathIsAgentInstructionControlSurface(path ActionPath) bool {
	location := strings.ToLower(strings.TrimSpace(path.Location))
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))

	switch {
	case toolType == "skill":
		return true
	case strings.HasSuffix(location, "agents.md"),
		strings.HasSuffix(location, "agents.override.md"),
		strings.HasSuffix(location, "claude.md"),
		strings.HasSuffix(location, ".cursorrules"),
		strings.Contains(location, ".cursor/rules/"),
		strings.HasSuffix(location, ".codex/config.toml"),
		strings.HasSuffix(location, ".codex/config.yaml"),
		strings.HasSuffix(location, ".codex/config.yml"),
		strings.HasSuffix(location, ".cursor/mcp.json"),
		strings.HasSuffix(location, ".claude/settings.json"),
		strings.HasSuffix(location, ".claude/settings.local.json"),
		strings.HasSuffix(location, ".mcp.json"),
		strings.HasSuffix(location, "/skill.md"):
		return true
	default:
		return false
	}
}

func pathTargetsCorrelationContext(path ActionPath) bool {
	if pathIsAgentInstructionControlSurface(path) {
		return false
	}
	if actionPathDependencyOnly(path) {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(path.ToolType)) {
	case "openapi", "route", "dependency":
		return true
	}

	if path.PathContext != nil {
		switch strings.TrimSpace(path.PathContext.Kind) {
		case agginventory.PathContextDocs,
			agginventory.PathContextExample,
			agginventory.PathContextGeneratedCode,
			agginventory.PathContextPackageCache:
			return true
		}
	}

	location := strings.ToLower(strings.TrimSpace(path.Location))
	switch {
	case strings.Contains(location, "openapi"),
		strings.Contains(location, "swagger"),
		strings.Contains(location, "/routes"),
		strings.Contains(location, "/route"),
		strings.Contains(location, "generated"),
		strings.Contains(location, "client"),
		strings.Contains(location, "schema"),
		strings.Contains(location, "spec"):
		return true
	default:
		return false
	}
}
