package risk

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

const (
	ControlStateSafeByDefault  = "safe_by_default"
	ControlStateApprovalNeeded = "approval_required"
	ControlStateBlockRecommend = "block_recommended"
	ControlStateEvidenceNeeded = "evidence_required"
	ControlStateInventoryOnly  = "inventory_only"

	RiskZoneCodingHelp     = "coding_help"
	RiskZoneRepoWrite      = "repo_write"
	RiskZoneCredential     = "credential_bearing" // #nosec G101 -- Deterministic risk-zone label, not credential material.
	RiskZoneCICD           = "ci_cd"
	RiskZoneIAC            = "iac"
	RiskZoneRelease        = "release"
	RiskZoneProductionData = "production_data"
	RiskZoneExternalEgress = "external_egress"

	ReviewBurdenLow      = "low"
	ReviewBurdenMedium   = "medium"
	ReviewBurdenHigh     = "high"
	ReviewBurdenCritical = "critical"

	ConfidenceLaneConfirmedActionPath     = "confirmed_action_path"
	ConfidenceLaneLikelyActionPath        = "likely_action_path"
	ConfidenceLaneSemanticReviewCandidate = "semantic_review_candidate"
	ConfidenceLaneContextOnly             = "context_only"

	EmptyStateEligible        = "eligible"
	EmptyStateNotEligible     = "not_eligible"
	EmptyStateCoverageReduced = "coverage_reduced"
)

type ActionPathSummaryOptions struct {
	ScanCoverageReduced bool
}

func ProjectActionPath(path ActionPath) ActionPath {
	out := path
	out.ConfidenceLane, out.ConfidenceLaneReasons = deriveConfidenceLane(out)
	out = projectEvidenceStates(out)
	out.TargetClass, out.TargetClassReasons, out.TargetClassEvidenceRefs = deriveTargetClass(out)
	out.ActionPathType, out.ActionPathTypeReasons, out.ActionPathTypeEvidenceRefs = deriveActionPathType(out)

	model := deriveGovernFirstModel(out)
	out.InventoryRisk = model.inventoryRisk
	out.ControlPriority = model.controlPriority
	out.RiskTier = model.riskTier
	out.RecommendedAction = model.recommendedAction

	out.ControlState, out.ControlStateReasons = deriveControlState(out)
	out.RiskZone, out.RiskZoneReasons = deriveRiskZone(out)
	out.ReviewBurden, out.ReviewBurdenReasons = deriveReviewBurden(out)
	out = normalizeProjectedControlState(out)
	return out
}

func ProjectActionPaths(paths []ActionPath) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		out = append(out, ProjectActionPath(path))
	}
	sort.Slice(out, func(i, j int) bool {
		return compareActionPaths(out[i], out[j])
	})
	return out
}

func ProjectBuyerFacingActionPath(path ActionPath) ActionPath {
	return ProjectActionPath(path)
}

func SummarizeActionPaths(paths []ActionPath, opts ActionPathSummaryOptions) ActionPathSummary {
	summary := ActionPathSummary{TotalPaths: len(paths)}
	for _, rawPath := range paths {
		path := ProjectActionPath(rawPath)

		if path.WriteCapable {
			summary.WriteCapablePaths++
		}
		if path.CredentialAccess {
			summary.CredentialAccessPaths++
		}
		if path.StandingPrivilege {
			summary.StandingPrivilegePaths++
		}
		if path.ProductionWrite || len(path.MatchedProductionTargets) > 0 {
			summary.ProductionTargetBackedPaths++
		}
		if strings.TrimSpace(path.ControlPriority) != ControlPriorityInventoryHygiene {
			summary.GovernFirstPaths++
		}
		if strings.TrimSpace(path.ControlPriority) == ControlPriorityControlFirst {
			summary.ControlFirstPaths++
		}
		switch strings.TrimSpace(path.ControlResolutionState) {
		case ControlResolutionStateDetectedControl:
			summary.DetectedControlPaths++
		case ControlResolutionStateDeclaredControl:
			summary.DeclaredControlPaths++
		case ControlResolutionStateExternalControlReference:
			summary.ExternalControlPaths++
		case ControlResolutionStateContradictoryControl:
			summary.ContradictoryControlPaths++
		case ControlResolutionStateNoVisibleControl:
			summary.ControlEvidenceUnknownPaths++
			summary.MissingPolicyPaths++
		}
		if strings.TrimSpace(path.ApprovalEvidenceState) == EvidenceStateUnknown {
			summary.ApprovalEvidenceUnknownPaths++
			summary.MissingApprovalPaths++
		}
		if strings.TrimSpace(path.ProofEvidenceState) == EvidenceStateUnknown {
			summary.ProofEvidenceUnknownPaths++
			summary.MissingProofPaths++
		}
		if strings.TrimSpace(path.OwnerEvidenceState) == EvidenceStateUnknown ||
			strings.TrimSpace(path.OwnerEvidenceState) == EvidenceStateContradictory {
			summary.OwnerEvidenceUnknownPaths++
			summary.UnresolvedOwnerPaths++
		}
		switch strings.TrimSpace(path.ReviewBurden) {
		case ReviewBurdenHigh, ReviewBurdenCritical:
			summary.HighReviewBurdenPaths++
		}
		switch confidenceLaneForPath(path) {
		case ConfidenceLaneConfirmedActionPath:
			summary.ConfirmedActionPaths++
		case ConfidenceLaneLikelyActionPath:
			summary.LikelyActionPaths++
		case ConfidenceLaneSemanticReviewCandidate:
			summary.SemanticReviewCandidatePaths++
		default:
			summary.ContextOnlyPaths++
		}
	}

	summary.EmptyStateStatus, summary.EmptyStateReasons = evaluateEmptyState(summary, opts)
	return summary
}

func evaluateEmptyState(summary ActionPathSummary, opts ActionPathSummaryOptions) (string, []string) {
	reasons := []string{}
	if summary.TotalPaths == 0 {
		reasons = append(reasons, "action_paths:none")
	} else if summary.ContextOnlyPaths == summary.TotalPaths {
		reasons = append(reasons, "action_paths:context_only_only")
	}

	hasBlocker := false
	for _, blocker := range []struct {
		count  int
		reason string
	}{
		{summary.ControlFirstPaths, "control_first_paths_present"},
		{summary.WriteCapablePaths, "write_capable_paths_present"},
		{summary.CredentialAccessPaths, "credential_access_paths_present"},
		{summary.StandingPrivilegePaths, "standing_privilege_paths_present"},
		{summary.ProductionTargetBackedPaths, "production_target_backed_paths_present"},
		{summary.ApprovalEvidenceUnknownPaths, "approval_evidence_unknown_paths_present"},
		{summary.ControlEvidenceUnknownPaths, "control_evidence_unknown_paths_present"},
		{summary.ProofEvidenceUnknownPaths, "proof_evidence_unknown_paths_present"},
		{summary.OwnerEvidenceUnknownPaths, "owner_evidence_unknown_paths_present"},
		{summary.HighReviewBurdenPaths, "high_review_burden_paths_present"},
		{summary.ConfirmedActionPaths, "confirmed_action_paths_present"},
		{summary.LikelyActionPaths, "likely_action_paths_present"},
		{summary.SemanticReviewCandidatePaths, "semantic_review_candidates_present"},
	} {
		if blocker.count > 0 {
			hasBlocker = true
			reasons = append(reasons, blocker.reason)
		}
	}
	if opts.ScanCoverageReduced {
		reasons = append(reasons, "scan_quality:reduced")
	}

	switch {
	case hasBlocker:
		return EmptyStateNotEligible, dedupeSortedStrings(reasons)
	case opts.ScanCoverageReduced:
		return EmptyStateCoverageReduced, dedupeSortedStrings(reasons)
	default:
		return EmptyStateEligible, dedupeSortedStrings(reasons)
	}
}

func deriveControlState(path ActionPath) (string, []string) {
	reasons := []string{}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}

	lane := confidenceLaneForPath(path)
	add("confidence_lane:" + lane)

	highBlastRadius := path.ProductionWrite ||
		path.DeployWrite ||
		path.MergeExecute ||
		pathHasHighImpactMutableEndpoint(path) ||
		containsPathValue(path.ActionClasses, "deploy") ||
		containsPathValue(path.ActionClasses, "delete") ||
		containsPathValue(path.ActionClasses, "execute")
	controlledPath := highBlastRadius ||
		path.WriteCapable ||
		path.PullRequestWrite ||
		path.CredentialAccess ||
		len(path.MatchedProductionTargets) > 0 ||
		pathHasAnyMutableEndpoint(path)
	missingPolicyOrProof := strings.TrimSpace(path.PolicyCoverageStatus) == "" ||
		strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone ||
		strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusStale ||
		strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusConflict ||
		len(path.PolicyMissingReasons) > 0 ||
		actionPathMissingProof(path)

	switch lane {
	case ConfidenceLaneContextOnly:
		add("control_priority:inventory_hygiene")
		return ControlStateInventoryOnly, dedupeSortedStrings(reasons)
	case ConfidenceLaneSemanticReviewCandidate:
		if path.ApprovalGap {
			add("approval_gap:true")
			reasons = append(reasons, path.ApprovalGapReasons...)
			return ControlStateApprovalNeeded, dedupeSortedStrings(reasons)
		}
		if controlledPath {
			add("controlled_path:true")
		} else {
			add("semantic_review:true")
		}
		if missingPolicyOrProof {
			add("coverage_gap:true")
		}
		return ControlStateEvidenceNeeded, dedupeSortedStrings(reasons)
	}

	switch {
	case strings.TrimSpace(path.ControlPriority) == ControlPriorityInventoryHygiene &&
		!controlledPath &&
		!path.ApprovalGap &&
		!path.StandingPrivilege:
		add("control_priority:inventory_hygiene")
		return ControlStateInventoryOnly, dedupeSortedStrings(reasons)
	case highBlastRadius &&
		path.StandingPrivilege &&
		(path.ApprovalGap || missingPolicyOrProof):
		add("blast_radius:high")
		add("standing_privilege:true")
		if path.ApprovalGap {
			add("approval_gap:true")
		}
		if missingPolicyOrProof {
			add("coverage_gap:true")
		}
		return ControlStateBlockRecommend, dedupeSortedStrings(reasons)
	case controlledPath && path.ApprovalGap:
		add("controlled_path:true")
		add("approval_gap:true")
		reasons = append(reasons, path.ApprovalGapReasons...)
		return ControlStateApprovalNeeded, dedupeSortedStrings(reasons)
	case controlledPath && missingPolicyOrProof:
		add("controlled_path:true")
		if strings.TrimSpace(path.PolicyCoverageStatus) == "" || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone {
			add("policy_coverage:none")
		}
		if strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusStale {
			add("policy_coverage:stale")
		}
		if strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusConflict {
			add("policy_coverage:conflict")
		}
		if actionPathMissingProof(path) {
			add("proof_coverage:missing")
		}
		return ControlStateEvidenceNeeded, dedupeSortedStrings(reasons)
	default:
		if controlledPath {
			add("controlled_path:true")
		} else {
			add("visibility_only:true")
		}
		return ControlStateSafeByDefault, dedupeSortedStrings(reasons)
	}
}

func deriveRiskZone(path ActionPath) (string, []string) {
	reasons := []string{}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}

	location := strings.ToLower(strings.TrimSpace(path.Location))
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))

	switch {
	case pathHasSensitiveDataEndpoint(path):
		for _, item := range pathMutableEndpointSemantics(path) {
			add("mutable_endpoint_semantic:" + strings.TrimSpace(item.Semantic))
		}
		return RiskZoneProductionData, dedupeSortedStrings(reasons)
	case path.ProductionWrite || strings.Contains(location, "prod") || strings.Contains(location, "database") || strings.Contains(location, "migration"):
		if path.ProductionWrite {
			add("production_write:true")
		}
		if strings.Contains(location, "database") || strings.Contains(location, "migration") {
			add("location:production_data")
		}
		return RiskZoneProductionData, dedupeSortedStrings(reasons)
	case containsPathValue(path.ActionClasses, "egress") || strings.Contains(toolType, "mcp") || strings.Contains(toolType, "a2a"):
		add("action_class:egress")
		if strings.Contains(toolType, "mcp") || strings.Contains(toolType, "a2a") {
			add("tool_type:" + strings.TrimSpace(path.ToolType))
		}
		return RiskZoneExternalEgress, dedupeSortedStrings(reasons)
	case containsAnyPathClass(path.ActionClasses, "deploy") || strings.Contains(location, "release"):
		if strings.Contains(location, "release") || containsAnyPathClass(path.WritePathClasses, "release_write", "package_publish") {
			add("release_surface:true")
			return RiskZoneRelease, dedupeSortedStrings(reasons)
		}
		if containsAnyPathClass(path.WritePathClasses, "infra_write") || strings.Contains(location, "terraform") || strings.Contains(location, "helm") || strings.Contains(location, "k8s") || strings.Contains(location, "iac") {
			add("infrastructure_surface:true")
			return RiskZoneIAC, dedupeSortedStrings(reasons)
		}
		add("delivery_surface:true")
		return RiskZoneCICD, dedupeSortedStrings(reasons)
	case path.CredentialAccess || path.StandingPrivilege:
		if path.CredentialAccess {
			add("credential_access:true")
		}
		if path.StandingPrivilege {
			add("standing_privilege:true")
		}
		return RiskZoneCredential, dedupeSortedStrings(reasons)
	case path.WriteCapable || path.PullRequestWrite || path.MergeExecute:
		if path.PullRequestWrite {
			add("pull_request_write:true")
		}
		if path.MergeExecute {
			add("merge_execute:true")
		}
		if path.WriteCapable {
			add("write_capable:true")
		}
		return RiskZoneRepoWrite, dedupeSortedStrings(reasons)
	default:
		add("read_or_guidance_only:true")
		return RiskZoneCodingHelp, dedupeSortedStrings(reasons)
	}
}

func deriveReviewBurden(path ActionPath) (string, []string) {
	score := 0
	reasons := []string{}
	add := func(reason string, delta int) {
		if strings.TrimSpace(reason) == "" {
			return
		}
		reasons = append(reasons, strings.TrimSpace(reason))
		score += delta
	}

	switch strings.TrimSpace(path.ControlState) {
	case ControlStateBlockRecommend:
		add("control_state:block_recommended", 4)
	case ControlStateApprovalNeeded:
		add("control_state:approval_required", 3)
	case ControlStateEvidenceNeeded:
		add("control_state:evidence_required", 2)
	case ControlStateInventoryOnly:
		add("control_state:inventory_only", 0)
	default:
		add("control_state:safe_by_default", 1)
	}

	switch confidenceLaneForPath(path) {
	case ConfidenceLaneConfirmedActionPath:
		add("confidence_lane:confirmed_action_path", 2)
	case ConfidenceLaneLikelyActionPath:
		add("confidence_lane:likely_action_path", 1)
	case ConfidenceLaneSemanticReviewCandidate:
		add("confidence_lane:semantic_review_candidate", 1)
	default:
		add("confidence_lane:context_only", 0)
	}

	switch strings.TrimSpace(path.RiskZone) {
	case RiskZoneProductionData, RiskZoneRelease:
		add("risk_zone:"+strings.TrimSpace(path.RiskZone), 3)
	case RiskZoneIAC, RiskZoneCICD, RiskZoneCredential:
		add("risk_zone:"+strings.TrimSpace(path.RiskZone), 2)
	case RiskZoneRepoWrite:
		add("risk_zone:"+strings.TrimSpace(path.RiskZone), 1)
	}
	if path.StandingPrivilege {
		add("standing_privilege:true", 2)
	}
	if pathHasHighImpactMutableEndpoint(path) {
		add("mutable_endpoint_semantic:high_impact", 3)
	} else if pathHasAnyMutableEndpoint(path) {
		add("mutable_endpoint_semantic:present", 1)
	}
	if path.ApprovalGap {
		add("approval_gap:true", 2)
	}
	if actionPathHasWeakOwnership(path) {
		add("ownership_gap:true", 2)
	}
	if len(path.PolicyMissingReasons) > 0 || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusStale || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusConflict {
		add("policy_gap:true", 2)
	}
	if actionPathMissingProof(path) {
		add("proof_gap:true", 2)
	}

	switch {
	case score >= 8:
		return ReviewBurdenCritical, dedupeSortedStrings(reasons)
	case score >= 6:
		return ReviewBurdenHigh, dedupeSortedStrings(reasons)
	case score >= 3:
		return ReviewBurdenMedium, dedupeSortedStrings(reasons)
	default:
		return ReviewBurdenLow, dedupeSortedStrings(reasons)
	}
}

func normalizeProjectedControlState(path ActionPath) ActionPath {
	out := path
	addControlReason := func(reason string) {
		if strings.TrimSpace(reason) == "" {
			return
		}
		out.ControlStateReasons = dedupeSortedStrings(append(out.ControlStateReasons, strings.TrimSpace(reason)))
	}
	addReviewReason := func(reason string) {
		if strings.TrimSpace(reason) == "" {
			return
		}
		out.ReviewBurdenReasons = dedupeSortedStrings(append(out.ReviewBurdenReasons, strings.TrimSpace(reason)))
	}

	highImpact := out.ProductionWrite ||
		out.DeployWrite ||
		out.MergeExecute ||
		out.StandingPrivilege ||
		pathHasHighImpactMutableEndpoint(out) ||
		pathHasSensitiveDataEndpoint(out)
	contradictory := actionPathHasContradictoryControlEvidence(out)
	criticalReview := strings.TrimSpace(out.ReviewBurden) == ReviewBurdenCritical

	if contradictory {
		if strings.TrimSpace(out.ControlPriority) != ControlPriorityControlFirst {
			out.ControlPriority = ControlPriorityControlFirst
			addControlReason("consistency:contradictory_control_routes_to_control_first")
		}
		if strings.TrimSpace(out.ControlState) != ControlStateBlockRecommend {
			out.ControlState = ControlStateBlockRecommend
			addControlReason("consistency:contradictory_control_blocks_clean_state")
		}
		if reviewBurdenRank(out.ReviewBurden) > reviewBurdenRank(ReviewBurdenCritical) {
			out.ReviewBurden = ReviewBurdenCritical
			addReviewReason("consistency:contradictory_control_requires_critical_review")
		}
		out.RiskTier = promoteRiskTier(out.RiskTier, minimumConsistencyRiskTier(highImpact))
		return out
	}

	if strings.TrimSpace(out.ControlPriority) == ControlPriorityControlFirst && strings.TrimSpace(out.ControlState) == ControlStateSafeByDefault {
		out.ControlState = ControlStateEvidenceNeeded
		addControlReason("consistency:control_first_cannot_be_safe_by_default")
	}

	if criticalReview {
		if strings.TrimSpace(out.ControlPriority) == ControlPriorityInventoryHygiene {
			out.ControlPriority = ControlPriorityReviewQueue
			addReviewReason("consistency:critical_review_cannot_stay_inventory_hygiene")
		}
		switch strings.TrimSpace(out.ControlState) {
		case ControlStateSafeByDefault, ControlStateInventoryOnly:
			switch {
			case out.ApprovalGap:
				out.ControlState = ControlStateApprovalNeeded
				addControlReason("consistency:critical_review_requires_approval_or_evidence")
			case highImpact:
				out.ControlState = ControlStateBlockRecommend
				addControlReason("consistency:critical_review_requires_fail_closed_state")
			default:
				out.ControlState = ControlStateEvidenceNeeded
				addControlReason("consistency:critical_review_requires_approval_or_evidence")
			}
		}
		out.RiskTier = promoteRiskTier(out.RiskTier, minimumConsistencyRiskTier(highImpact))
	}

	if strings.TrimSpace(out.ControlPriority) == ControlPriorityControlFirst {
		out.RiskTier = promoteRiskTier(out.RiskTier, minimumConsistencyRiskTier(highImpact))
	}

	return out
}

func actionPathHasContradictoryControlEvidence(path ActionPath) bool {
	if strings.TrimSpace(path.ControlResolutionState) == ControlResolutionStateContradictoryControl {
		return true
	}
	for _, state := range []string{
		path.ApprovalEvidenceState,
		path.OwnerEvidenceState,
		path.ProofEvidenceState,
		path.RuntimeEvidenceState,
		path.TargetEvidenceState,
		path.CredentialEvidenceState,
	} {
		if normalizeEvidenceState(state) == EvidenceStateContradictory {
			return true
		}
	}
	return false
}

func minimumConsistencyRiskTier(highImpact bool) string {
	if highImpact {
		return RiskTierCritical
	}
	return RiskTierHigh
}

func promoteRiskTier(current, minimum string) string {
	if riskTierRank(minimum) < riskTierRank(current) {
		return minimum
	}
	if strings.TrimSpace(current) == "" {
		return minimum
	}
	return strings.TrimSpace(current)
}

func riskTierRank(value string) int {
	switch strings.TrimSpace(value) {
	case RiskTierCritical:
		return 0
	case RiskTierHigh:
		return 1
	case RiskTierMedium:
		return 2
	default:
		return 3
	}
}

func deriveConfidenceLane(path ActionPath) (string, []string) {
	reasons := []string{}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}

	executableBinding := pathHasExecutableBinding(path)
	permissionOrTargetSignal := pathHasPermissionOrTargetSignal(path)
	authorityLinkage := path.CredentialAccess || path.StandingPrivilege || actionPathHasStrongIdentity(path)
	promptSurface := pathIsPromptOrInstructionSurface(path)
	contextOnlySurface := pathIsContextOnlySurface(path)

	switch {
	case promptSurface && !executableBinding:
		add("surface:prompt_or_instruction")
		add("execution_linkage:missing")
		return ConfidenceLaneSemanticReviewCandidate, dedupeSortedStrings(reasons)
	case executableBinding && permissionOrTargetSignal && authorityLinkage:
		add("execution_linkage:direct")
		add("permission_or_target_signal:present")
		add("authority_linkage:present")
		return ConfidenceLaneConfirmedActionPath, dedupeSortedStrings(reasons)
	case executableBinding && (permissionOrTargetSignal || authorityLinkage):
		add("execution_linkage:direct")
		if permissionOrTargetSignal {
			add("permission_or_target_signal:present")
		} else {
			add("permission_or_target_signal:missing")
		}
		if authorityLinkage {
			add("authority_linkage:present")
		} else {
			add("authority_linkage:missing")
		}
		return ConfidenceLaneLikelyActionPath, dedupeSortedStrings(reasons)
	case contextOnlySurface:
		add("surface:context_only")
		return ConfidenceLaneContextOnly, dedupeSortedStrings(reasons)
	case permissionOrTargetSignal || authorityLinkage:
		add("execution_linkage:missing")
		if promptSurface {
			add("surface:prompt_or_instruction")
			return ConfidenceLaneSemanticReviewCandidate, dedupeSortedStrings(reasons)
		}
		return ConfidenceLaneLikelyActionPath, dedupeSortedStrings(reasons)
	default:
		add("supporting_metadata_only")
		return ConfidenceLaneContextOnly, dedupeSortedStrings(reasons)
	}
}

func pathHasExecutableBinding(path ActionPath) bool {
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	location := strings.ToLower(strings.TrimSpace(path.Location))

	switch {
	case strings.Contains(location, ".github/workflows"),
		strings.Contains(location, "jenkinsfile"),
		strings.Contains(toolType, "compiled_action"),
		strings.Contains(toolType, "ci_agent"),
		strings.Contains(toolType, "mcp"),
		strings.Contains(toolType, "a2a"):
		return true
	case path.PathContext != nil &&
		(path.PathContext.Kind == agginventory.PathContextDeployableSource || path.PathContext.Kind == agginventory.PathContextRuntimeSource) &&
		(path.WriteCapable || path.CredentialAccess || len(path.ActionClasses) > 0):
		return true
	default:
		return false
	}
}

func pathHasPermissionOrTargetSignal(path ActionPath) bool {
	return path.WriteCapable ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		path.DeployWrite ||
		path.ProductionWrite ||
		len(path.MatchedProductionTargets) > 0 ||
		pathHasAnyMutableEndpoint(path) ||
		len(path.ActionClasses) > 0
}

func pathIsPromptOrInstructionSurface(path ActionPath) bool {
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	location := strings.ToLower(strings.TrimSpace(path.Location))
	switch {
	case toolType == "prompt_channel":
		return true
	case strings.Contains(location, "agents.md"),
		strings.Contains(location, "claude.md"),
		strings.Contains(location, ".cursorrules"),
		strings.Contains(location, ".cursor/rules"),
		strings.Contains(location, "prompt"),
		strings.Contains(location, "instruction"):
		return true
	default:
		return false
	}
}

func pathIsContextOnlySurface(path ActionPath) bool {
	if actionPathDependencyOnly(path) {
		return true
	}
	if path.PathContext == nil {
		return false
	}
	switch strings.TrimSpace(path.PathContext.Kind) {
	case agginventory.PathContextDocs,
		agginventory.PathContextExample,
		agginventory.PathContextUnitTest,
		agginventory.PathContextFunctionalTest,
		agginventory.PathContextGeneratedCode,
		agginventory.PathContextPackageCache:
		return true
	default:
		return false
	}
}

func actionPathMissingProof(path ActionPath) bool {
	if state := normalizeEvidenceState(path.ProofEvidenceState); state != "" {
		return state == EvidenceStateUnknown || state == EvidenceStateContradictory
	}
	if path.GaitCoverage == nil {
		return true
	}
	switch strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) {
	case "", GaitStatusMissing, GaitStatusConflict, GaitStatusStale:
		return true
	default:
		return false
	}
}

func confidenceLaneForPath(path ActionPath) string {
	switch strings.TrimSpace(path.ConfidenceLane) {
	case ConfidenceLaneConfirmedActionPath,
		ConfidenceLaneLikelyActionPath,
		ConfidenceLaneSemanticReviewCandidate,
		ConfidenceLaneContextOnly:
		return strings.TrimSpace(path.ConfidenceLane)
	default:
		lane, _ := deriveConfidenceLane(path)
		return lane
	}
}

func confidenceLaneRank(value string) int {
	switch strings.TrimSpace(value) {
	case ConfidenceLaneConfirmedActionPath:
		return 0
	case ConfidenceLaneLikelyActionPath:
		return 1
	case ConfidenceLaneSemanticReviewCandidate:
		return 2
	default:
		return 3
	}
}

func reviewBurdenRank(value string) int {
	switch strings.TrimSpace(value) {
	case ReviewBurdenCritical:
		return 0
	case ReviewBurdenHigh:
		return 1
	case ReviewBurdenMedium:
		return 2
	default:
		return 3
	}
}

func containsAnyPathClass(values []string, candidates ...string) bool {
	for _, candidate := range candidates {
		if containsPathValue(values, candidate) {
			return true
		}
	}
	return false
}

func containsPathValue(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
