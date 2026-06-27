package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/risk"
)

type FocusPreset string

const (
	FocusPresetBOM                     FocusPreset = "bom"
	FocusPresetRelease                 FocusPreset = "release"
	FocusPresetWriteDeploy             FocusPreset = "write-deploy"
	FocusPresetApprovalEvidenceUnknown FocusPreset = "approval-evidence-unknown"
	FocusPresetOwnerEvidenceUnknown    FocusPreset = "owner-evidence-unknown"
	FocusPresetEvidenceGaps            FocusPreset = "evidence-gaps"
	FocusPresetContradictions          FocusPreset = "contradictions"
	FocusPresetDriftReview             FocusPreset = "drift-review"
	FocusPresetRecommendations         FocusPreset = "recommendations"
)

const workflowHighlightLimit = 5

func ParseFocusPreset(raw string) (FocusPreset, bool) {
	switch FocusPreset(strings.TrimSpace(raw)) {
	case FocusPresetBOM,
		FocusPresetRelease,
		FocusPresetWriteDeploy,
		FocusPresetApprovalEvidenceUnknown,
		FocusPresetOwnerEvidenceUnknown,
		FocusPresetEvidenceGaps,
		FocusPresetContradictions,
		FocusPresetDriftReview,
		FocusPresetRecommendations:
		return FocusPreset(strings.TrimSpace(raw)), true
	default:
		return "", false
	}
}

func FocusPresetUsage() string {
	return "bom|release|write-deploy|approval-evidence-unknown|owner-evidence-unknown|evidence-gaps|contradictions|drift-review|recommendations"
}

func ApplyFocusPreset(summary *Summary, raw string) error {
	if summary == nil {
		return nil
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		summary.FocusView = nil
		return nil
	}

	preset, ok := ParseFocusPreset(trimmed)
	if !ok {
		return fmt.Errorf("--focus must be one of %s", FocusPresetUsage())
	}

	summary.FocusView = buildFocusView(*summary, preset)
	return nil
}

func BuildWorkflowHighlights(summary Summary) *WorkflowHighlights {
	items := eligibleWorkflowHighlightItems(summary.AgentActionBOM)
	if len(items) == 0 {
		return nil
	}

	limit := len(items)
	if limit > workflowHighlightLimit {
		limit = workflowHighlightLimit
	}

	out := &WorkflowHighlights{
		TotalItems: len(items),
		Highlights: make([]WorkflowHighlight, 0, limit),
	}
	for idx := 0; idx < limit; idx++ {
		out.Highlights = append(out.Highlights, workflowHighlightFromItem(items[idx]))
	}
	return out
}

func buildFocusView(summary Summary, preset FocusPreset) *FocusView {
	items := eligibleWorkflowHighlightItems(summary.AgentActionBOM)
	matches := filterFocusPresetItems(items, preset, summary)
	pathIDs := orderedFocusPathIDs(matches)
	workflowChainRefs := orderedFocusWorkflowChainRefs(matches)
	backlogIDs := orderedFocusBacklogIDs(summary.ControlBacklog, pathIDs)

	view := &FocusView{
		Preset:                 string(preset),
		Title:                  focusPresetTitle(preset),
		MatchingPaths:          len(pathIDs),
		MatchingWorkflowChains: len(workflowChainRefs),
		MatchingBacklogItems:   len(backlogIDs),
		RecommendedNextActions: focusPresetActions(preset),
		PathIDs:                pathIDs,
		WorkflowChainRefs:      workflowChainRefs,
		ControlBacklogIDs:      backlogIDs,
	}

	if len(matches) == 0 {
		view.EmptyStateStatus = focusPresetEmptyStateStatus(preset, summary)
		view.EmptyStateMessage = focusPresetEmptyStateMessage(preset, summary)
		return view
	}

	limit := len(matches)
	if limit > workflowHighlightLimit {
		limit = workflowHighlightLimit
	}
	view.Highlights = make([]WorkflowHighlight, 0, limit)
	for idx := 0; idx < limit; idx++ {
		view.Highlights = append(view.Highlights, workflowHighlightFromItem(matches[idx]))
	}
	return view
}

func eligibleWorkflowHighlightItems(bom *AgentActionBOM) []AgentActionBOMItem {
	if bom == nil || len(bom.Items) == 0 {
		return nil
	}

	filtered := make([]AgentActionBOMItem, 0, len(bom.Items))
	for _, item := range bom.Items {
		if !bomItemPromotableActionPath(item) {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) > 0 {
		return filtered
	}
	return nil
}

func filterFocusPresetItems(items []AgentActionBOMItem, preset FocusPreset, summary Summary) []AgentActionBOMItem {
	if len(items) == 0 {
		return nil
	}
	matches := make([]AgentActionBOMItem, 0, len(items))
	for _, item := range items {
		if matchesFocusPreset(item, preset, summary) {
			matches = append(matches, item)
		}
	}
	return matches
}

func matchesFocusPreset(item AgentActionBOMItem, preset FocusPreset, summary Summary) bool {
	switch preset {
	case FocusPresetBOM:
		return true
	case FocusPresetRelease:
		return item.TargetClass == risk.TargetClassReleaseAdjacent ||
			item.ProductionWrite ||
			hasHighStakesPreset(item.HighStakesPresets, "release_automation", "package_publishing")
	case FocusPresetWriteDeploy:
		return item.ProductionWrite ||
			len(item.MatchedProductionTargets) > 0 ||
			hasActionClass(item.ActionClasses, "deploy", "write", "merge") ||
			item.CredentialAccess
	case FocusPresetApprovalEvidenceUnknown:
		return normalizeEvidenceState(item.ApprovalEvidenceState) == risk.EvidenceStateUnknown || item.ApprovalGap
	case FocusPresetOwnerEvidenceUnknown:
		state := normalizeEvidenceState(item.OwnerEvidenceState)
		return state == risk.EvidenceStateUnknown || state == risk.EvidenceStateInferred
	case FocusPresetEvidenceGaps:
		return item.EvidenceCompleteness == nil ||
			strings.TrimSpace(item.EvidenceCompleteness.Label) != risk.EvidenceCompletenessStrong ||
			hasUnknownEvidenceState(item) ||
			strings.TrimSpace(item.EvidencePacketMissingEvidenceState) == "missing" ||
			strings.TrimSpace(item.RuntimeEvidenceAbsenceStatus) == risk.RuntimeEvidenceAbsenceMissingRequired ||
			strings.TrimSpace(item.RuntimeEvidenceAbsenceStatus) == risk.RuntimeEvidenceAbsenceMissingForClaim
	case FocusPresetContradictions:
		return len(item.Contradictions) > 0 ||
			strings.TrimSpace(item.ControlResolutionState) == risk.ControlResolutionStateContradictoryControl ||
			hasContradictoryEvidenceState(item)
	case FocusPresetDriftReview:
		if summary.RegressDrift == nil || !summary.RegressDrift.DriftDetected {
			return false
		}
		if strings.TrimSpace(summary.RegressDrift.ComparisonStatus) != "" &&
			strings.TrimSpace(summary.RegressDrift.ComparisonStatus) != regress.DriftComparisonStatusOK {
			return false
		}
		pathIDs := driftReviewPathIDs(summary)
		if len(pathIDs) == 0 {
			return true
		}
		_, ok := pathIDs[strings.TrimSpace(item.PathID)]
		return ok
	case FocusPresetRecommendations:
		return strings.TrimSpace(item.ControlPriority) == risk.ControlPriorityControlFirst ||
			strings.TrimSpace(item.Queue) == controlbacklog.QueueControlFirst ||
			strings.TrimSpace(item.RecommendedControl) != risk.RecommendedControlAllow ||
			strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessReviewRequired ||
			strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessApprovalRequired ||
			strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessProofRequired ||
			strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessBlocked ||
			strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessBlockedByContradiction
	default:
		return false
	}
}

func workflowHighlightFromItem(item AgentActionBOMItem) WorkflowHighlight {
	return WorkflowHighlight{
		PathID:               strings.TrimSpace(item.PathID),
		WorkflowChainRefs:    dedupeSortedStrings(item.WorkflowChainRefs),
		Repo:                 strings.TrimSpace(item.Repo),
		Workflow:             strings.TrimSpace(item.Location),
		PathType:             strings.TrimSpace(item.ActionPathType),
		TargetClass:          strings.TrimSpace(item.TargetClass),
		AutonomyTier:         strings.TrimSpace(item.AutonomyTier),
		DelegationReadiness:  strings.TrimSpace(item.DelegationReadinessState),
		Authority:            workflowAuthoritySummary(item),
		BlastRadius:          workflowBlastRadiusSummary(item),
		EvidenceSummary:      workflowEvidenceSummary(item),
		ApprovalPath:         risk.BuyerEvidenceStateLabel("approval", item.ApprovalEvidenceState),
		ProofStatus:          risk.BuyerEvidenceStateLabel("proof", item.ProofEvidenceState),
		RuntimeStatus:        risk.BuyerRuntimeEvidenceLabel(item.RuntimeEvidenceState, item.RuntimeEvidenceAbsenceStatus, item.GaitCoverage),
		RuntimeSessionStatus: firstNonEmptyValue(strings.TrimSpace(item.RuntimeSessionStatus), "not_collected"),
		Recommendation:       workflowRecommendation(item),
		BoundaryLabel:        firstNonEmptyValue(strings.TrimSpace(item.BoundaryLabel), BoundaryLabelReportOnly),
		Explanation:          workflowExplanation(item),
	}
}

func workflowAuthoritySummary(item AgentActionBOMItem) string {
	if len(item.AuthorityBindings) > 0 {
		parts := make([]string, 0, len(item.AuthorityBindings))
		for _, binding := range item.AuthorityBindings {
			if binding == nil {
				continue
			}
			parts = append(parts, strings.Trim(strings.Join([]string{
				strings.TrimSpace(binding.Kind),
				strings.TrimSpace(binding.Provider),
				firstNonEmptyValue(strings.TrimSpace(binding.TargetSystem), strings.TrimSpace(binding.Subject), strings.TrimSpace(binding.Resource)),
			}, ":"), ":"))
		}
		if len(parts) > 0 {
			sort.Strings(parts)
			if len(parts) > 2 {
				parts = parts[:2]
			}
			parts = appendStandingCredentialMetadata(parts, item)
			return strings.Join(parts, " | ")
		}
	}
	if item.CredentialAuthority != nil {
		parts := []string{}
		if kind := strings.TrimSpace(item.CredentialAuthority.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if access := strings.TrimSpace(item.CredentialAuthority.AccessType); access != "" {
			parts = append(parts, access)
		}
		if source := strings.TrimSpace(item.CredentialAuthority.CredentialSource); source != "" {
			parts = append(parts, source)
		}
		if len(parts) > 0 {
			parts = appendStandingCredentialMetadata(parts, item)
			return strings.Join(parts, " | ")
		}
	}
	if item.CredentialProvenance != nil {
		parts := []string{}
		if kind := strings.TrimSpace(item.CredentialProvenance.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if scope := strings.TrimSpace(item.CredentialProvenance.Scope); scope != "" {
			parts = append(parts, scope)
		}
		if item.CredentialProvenance.StandingAccess {
			parts = append(parts, "standing")
		}
		if len(parts) > 0 {
			parts = appendStandingCredentialMetadata(parts, item)
			return strings.Join(parts, " | ")
		}
	}
	if bomItemStandingCredentialMetadata(item) {
		return "standing credential authority"
	}
	if item.StandingPrivilege {
		return "standing credential authority"
	}
	if item.CredentialAccess {
		return "credential access declared"
	}
	return "no credential authority linked"
}

func appendStandingCredentialMetadata(parts []string, item AgentActionBOMItem) []string {
	if !bomItemStandingCredentialMetadata(item) {
		return parts
	}
	for _, part := range parts {
		if strings.Contains(strings.ToLower(strings.TrimSpace(part)), "standing") {
			return parts
		}
	}
	return append(parts, "standing credential")
}

func workflowBlastRadiusSummary(item AgentActionBOMItem) string {
	switch {
	case item.ProductionWrite || strings.TrimSpace(item.TargetClass) == risk.TargetClassProductionImpacting:
		return "production-impacting authority"
	case strings.TrimSpace(item.TargetClass) == risk.TargetClassCustomerDataAdjacent:
		return "customer-data-adjacent reach"
	case strings.TrimSpace(item.TargetClass) == risk.TargetClassReleaseAdjacent || hasHighStakesPreset(item.HighStakesPresets, "release_automation", "package_publishing"):
		return "release or deploy reach"
	case itemHasMutableEndpointProjection(item):
		return "mutable endpoint reach"
	case item.CredentialAccess || item.StandingPrivilege:
		return "credential-backed write reach"
	case strings.TrimSpace(item.TargetClass) != "":
		return strings.ReplaceAll(strings.TrimSpace(item.TargetClass), "_", " ")
	default:
		return "bounded workflow reach"
	}
}

func workflowEvidenceSummary(item AgentActionBOMItem) string {
	parts := []string{
		"control=" + risk.BuyerControlResolutionLabel(item.ControlResolutionState),
		"owner=" + risk.BuyerEvidenceStateLabel("owner", item.OwnerEvidenceState),
	}
	if item.EvidenceCompleteness != nil {
		parts = append(parts, "coverage="+risk.BuyerEvidenceCompletenessLabel(item.EvidenceCompleteness))
	}
	if len(item.Contradictions) > 0 {
		parts = append(parts, "contradictions=present")
	}
	return strings.Join(parts, " | ")
}

func workflowRecommendation(item AgentActionBOMItem) string {
	subject := workflowRecommendationSubject(item)
	scope := workflowRecommendationScope(item)
	switch {
	case len(item.Contradictions) > 0 || hasContradictoryEvidenceState(item):
		return "resolve contradictory control evidence for " + subject + " before promoting it"
	case bomItemStaticContextSurface(item):
		return "correlate this caller-facing surface to the workflow, runtime caller, or tool binding that actually uses it before promoting it"
	case bomItemStandardCIControlContext(item):
		return "import PR review, branch protection, deployment environment, or owner-map evidence for this standard CI workflow, and include required-check evidence when it gates the path, before treating it as an approval or proof gap"
	case bomItemBlockedStandingCredential(item):
		return blockedStandingCredentialNextAction(item)
	case bomItemNeedsAuthorityCorrelation(item):
		return "classify or correlate the exact credential authority and scope for " + subject + scope
	case strings.TrimSpace(item.OwnerEvidenceState) == risk.EvidenceStateUnknown:
		return "attach explicit owner evidence for " + subject + " and rescan"
	case strings.TrimSpace(item.ApprovalEvidenceState) == risk.EvidenceStateUnknown || item.ApprovalGap:
		return "attach scoped approval evidence for " + subject + scope
	case strings.TrimSpace(item.ProofEvidenceState) == risk.EvidenceStateUnknown:
		return "attach path-specific proof for " + subject + scope
	case item.StandingPrivilege || strings.TrimSpace(item.RecommendedControl) == risk.RecommendedControlBlockStandingCredential:
		return "replace standing credential authority on " + subject + " with tighter or JIT access"
	case strings.TrimSpace(item.RuntimeEvidenceState) == risk.EvidenceStateVerified:
		return "join runtime evidence to " + subject + " and keep proof current"
	case strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessReadyForControl:
		return "move " + subject + " into a control review with linked proof"
	default:
		return firstNonEmptyValue(strings.TrimSpace(item.Remediation), "review this path and tighten ownership, approval, or proof evidence")
	}
}

func bomItemBlockedStandingCredential(item AgentActionBOMItem) bool {
	if !bomItemStandingCredential(item) {
		return false
	}
	switch strings.TrimSpace(item.DelegationReadinessState) {
	case risk.DelegationReadinessBlocked, risk.DelegationReadinessBlockedByContradiction:
		return true
	}
	if strings.TrimSpace(item.RecommendedControl) == risk.RecommendedControlBlockStandingCredential {
		return true
	}
	return strings.TrimSpace(item.ControlState) == "block_recommended"
}

func bomItemStandingCredential(item AgentActionBOMItem) bool {
	if item.StandingPrivilege {
		return true
	}
	if strings.TrimSpace(item.RecommendedControl) == risk.RecommendedControlBlockStandingCredential {
		return true
	}
	if bomItemStandingCredentialMetadata(item) {
		return true
	}
	authority := strings.ToLower(workflowAuthoritySummary(item))
	return strings.Contains(authority, "standing")
}

func bomItemStandingCredentialMetadata(item AgentActionBOMItem) bool {
	if item.StandingPrivilege {
		return true
	}
	if authority := agginventory.NormalizeCredentialAuthority(item.CredentialAuthority); authority != nil && authority.StandingAccess {
		return true
	}
	return item.CredentialProvenance != nil && item.CredentialProvenance.StandingAccess
}

func blockedStandingCredentialNextAction(item AgentActionBOMItem) string {
	if !bomItemBlockedStandingCredential(item) {
		return ""
	}
	subject := workflowRecommendationSubject(item)
	return "replace standing credential authority on " + subject + " with brokered or repo-scoped JIT access"
}

func workflowRecommendationSubject(item AgentActionBOMItem) string {
	if bomItemStaticContextSurface(item) {
		switch strings.ToLower(strings.TrimSpace(item.ToolType)) {
		case "openapi":
			return "this API specification surface"
		case "route":
			return "this route surface"
		}
	}
	switch strings.TrimSpace(item.ActionPathType) {
	case risk.ActionPathTypeCICDWorkflow:
		return "this CI/CD workflow path"
	case risk.ActionPathTypeAIAssistedWorkflow:
		return "this AI-assisted workflow path"
	case risk.ActionPathTypeAgentFramework:
		return "this agent framework path"
	case risk.ActionPathTypeAgentInstruction:
		return "this agent instruction surface"
	case risk.ActionPathTypeAutomationBot:
		return "this automation bot path"
	case risk.ActionPathTypeLegacyScript:
		return "this legacy script path"
	case risk.ActionPathTypeUnknownExecutablePath:
		return "this executable path"
	case risk.ActionPathTypeDependencyOnlySignal:
		return "this dependency signal"
	case risk.ActionPathTypePlainSourceCode:
		return "this source surface"
	default:
		return "this action path"
	}
}

func workflowRecommendationScope(item AgentActionBOMItem) string {
	action := workflowActionSummary(item)
	target := workflowTargetSummary(item)
	if action == "" && target == "" {
		return ""
	}
	if action == "" {
		return " for " + target
	}
	if target == "" {
		return " before allowing " + action
	}
	return " before allowing " + action + " against " + target
}

func workflowActionSummary(item AgentActionBOMItem) string {
	actions := uniqueSortedStrings(item.ActionClasses)
	if len(actions) == 0 {
		return ""
	}
	if len(actions) > 3 {
		actions = actions[:3]
	}
	return strings.Join(actions, "/")
}

func workflowTargetSummary(item AgentActionBOMItem) string {
	switch strings.TrimSpace(item.TargetClass) {
	case risk.TargetClassProductionImpacting:
		return "production-impacting targets"
	case risk.TargetClassReleaseAdjacent:
		return "release-adjacent targets"
	case risk.TargetClassCustomerDataAdjacent:
		return "customer-data-adjacent targets"
	case risk.TargetClassInternalTooling:
		return "internal tooling"
	case risk.TargetClassDeveloperProductivity:
		return "developer-productivity systems"
	case risk.TargetClassTestDemoSandbox:
		return "test/demo/sandbox targets"
	case risk.TargetClassUnknown, "":
		return ""
	default:
		return strings.ReplaceAll(strings.TrimSpace(item.TargetClass), "_", "-") + " targets"
	}
}

func workflowExplanation(item AgentActionBOMItem) string {
	switch {
	case len(item.Contradictions) > 0 || hasContradictoryEvidenceState(item):
		return "Wrkr found conflicting control evidence, so this workflow should stay in review until the contradiction is resolved."
	case bomItemStaticContextSurface(item):
		return "This is static target context, so Wrkr keeps it in caller-correlation guidance until a real workflow, runtime caller, or tool binding is proven."
	case bomItemStandardCIControlContext(item):
		return "This looks like standard CI authority. Wrkr found the workflow and credential reference, but it has not imported the PR review, branch protection, deployment environment, owner-map, and any gating required-check evidence that may already cover it."
	case bomItemBlockedStandingCredential(item):
		return "This path is already blocked with standing credential metadata, so replacement or JIT reduction should lead before correlation work."
	case bomItemNeedsAuthorityCorrelation(item):
		return "Wrkr can see credential-bearing workflow reach, but the exact authority and scope are still incomplete, so the next step is to correlate or classify that authority rather than jump straight to standing-credential remediation."
	case strings.TrimSpace(item.OwnerEvidenceState) == risk.EvidenceStateUnknown:
		return "Wrkr can see what this workflow can do, but it still lacks ownership evidence strong enough for buyer-facing confidence."
	case strings.TrimSpace(item.ApprovalEvidenceState) == risk.EvidenceStateUnknown || item.ApprovalGap:
		return "The authority is visible, but approval evidence for this exact workflow path is still missing or weak."
	case strings.TrimSpace(item.ProofEvidenceState) == risk.EvidenceStateUnknown:
		return "The workflow path is real, yet the supporting proof chain is still incomplete for a confident control claim."
	case strings.TrimSpace(item.RuntimeEvidenceState) == risk.EvidenceStateVerified:
		return "Runtime evidence shows this path has been observed, which strengthens the static workflow claim without implying enforcement."
	case strings.TrimSpace(item.DelegationReadinessState) == risk.DelegationReadinessReadyForControl:
		return "The evidence is strong enough to move this workflow from report-only visibility toward explicit control review."
	case item.StandingPrivilege:
		return "A standing credential increases the blast radius, so the next step is usually to narrow access or replace it with JIT proof."
	default:
		return "This workflow remains one of the highest-signal paths to review because it combines meaningful authority with incomplete buyer-safe evidence."
	}
}

func bomItemStandardCIControlContext(item AgentActionBOMItem) bool {
	if strings.TrimSpace(item.CIFlowClass) != "" {
		return strings.TrimSpace(item.CIFlowClass) == risk.CIFlowClassStandardGovernedCI
	}
	if strings.TrimSpace(item.ActionPathType) != risk.ActionPathTypeCICDWorkflow {
		return false
	}
	if strings.TrimSpace(item.ControlPriority) != risk.ControlPriorityInventoryHygiene {
		return false
	}
	if len(item.Contradictions) > 0 || hasContradictoryEvidenceState(item) {
		return false
	}
	if bomItemHighImpactDeliveryEvidence(item) {
		return false
	}
	return item.CredentialAccess ||
		item.ApprovalGap ||
		item.StandingPrivilege ||
		strings.TrimSpace(item.ApprovalEvidenceState) == risk.EvidenceStateUnknown ||
		strings.TrimSpace(item.ProofEvidenceState) == risk.EvidenceStateUnknown
}

func bomItemNeedsAuthorityCorrelation(item AgentActionBOMItem) bool {
	if !item.CredentialAccess || item.StandingPrivilege {
		return false
	}
	authority := agginventory.NormalizeCredentialAuthority(item.CredentialAuthority)
	provenance := agginventory.NormalizeCredentialProvenance(item.CredentialProvenance)
	switch {
	case authority == nil && provenance == nil:
		return true
	case authority != nil && (!authority.CredentialUsableByPath || strings.TrimSpace(authority.AccessType) == "" || strings.TrimSpace(authority.AccessType) == agginventory.CredentialAccessTypeUnknown):
		return true
	case provenance != nil && (strings.TrimSpace(provenance.Scope) == "" || strings.TrimSpace(provenance.Scope) == agginventory.CredentialScopeUnknown):
		return true
	default:
		return false
	}
}

func bomItemHighImpactDeliveryEvidence(item AgentActionBOMItem) bool {
	if item.ProductionWrite || len(item.MatchedProductionTargets) > 0 {
		return true
	}
	switch strings.TrimSpace(item.TargetClass) {
	case risk.TargetClassProductionImpacting, risk.TargetClassReleaseAdjacent, risk.TargetClassCustomerDataAdjacent:
		return true
	}
	for _, preset := range item.HighStakesPresets {
		switch strings.TrimSpace(preset.Preset) {
		case risk.HighStakesPresetProductionPath,
			risk.HighStakesPresetReleaseAutomation,
			risk.HighStakesPresetPackagePublishing,
			risk.HighStakesPresetInfrastructureAsCode,
			risk.HighStakesPresetIdentityAuthCode,
			risk.HighStakesPresetPaymentFlow,
			risk.HighStakesPresetRegulatedCustomerFlow,
			risk.HighStakesPresetExternalEgress,
			risk.HighStakesPresetMutableEndpoint:
			return true
		}
	}
	return false
}

func focusPresetTitle(preset FocusPreset) string {
	switch preset {
	case FocusPresetBOM:
		return "Workflow BOM Review"
	case FocusPresetRelease:
		return "Release-Adjacent AI Paths"
	case FocusPresetWriteDeploy:
		return "Write and Deploy Reach"
	case FocusPresetApprovalEvidenceUnknown:
		return "Approval Evidence Gaps"
	case FocusPresetOwnerEvidenceUnknown:
		return "Owner Evidence Gaps"
	case FocusPresetEvidenceGaps:
		return "Evidence Gaps"
	case FocusPresetContradictions:
		return "Contradictions to Resolve"
	case FocusPresetDriftReview:
		return "Drift Review"
	case FocusPresetRecommendations:
		return "Recommended Next Controls"
	default:
		return "Focused Review"
	}
}

func focusPresetActions(preset FocusPreset) []string {
	switch preset {
	case FocusPresetBOM:
		return []string{
			"Review the top workflow paths first, then use the appendix sections for raw detector and proof detail.",
			"Pair any external sharing flow with a redacted report variant instead of sending the internal artifact set.",
		}
	case FocusPresetRelease:
		return []string{
			"Confirm release-path approval and proof coverage before widening delegation.",
			"Reduce standing credential and deploy authority where the release path does not need it.",
		}
	case FocusPresetWriteDeploy:
		return []string{
			"Review write or deploy reach first because these paths can change repo or environment state quickly.",
			"Prefer JIT or brokered credentials when the path does not need standing write access.",
		}
	case FocusPresetApprovalEvidenceUnknown:
		return []string{
			"Attach explicit approval evidence for the exact workflow, environment, or target.",
			"Keep the path in review until approval evidence is linked in a buyer-safe way.",
		}
	case FocusPresetOwnerEvidenceUnknown:
		return []string{
			"Attach owner evidence that names who governs the workflow path.",
			"Use the control backlog rows to assign follow-up before broader rollout or sharing.",
		}
	case FocusPresetEvidenceGaps:
		return []string{
			"Fill owner, approval, runtime, or proof gaps before making stronger control claims.",
			"Use runtime evidence only as corroboration; static discovery still needs path-specific proof.",
		}
	case FocusPresetContradictions:
		return []string{
			"Resolve contradictory evidence before approval or automation expansion.",
			"Treat contradictions as review blockers until one source of truth is established.",
		}
	case FocusPresetDriftReview:
		return []string{
			"Review the regress summary alongside the top workflow paths to understand what changed.",
			"Capture any newly widened authority or new proof gaps before the next assessment cycle.",
		}
	case FocusPresetRecommendations:
		return []string{
			"Start with control-first items, then work down to review-queue and evidence-only follow-up.",
			"Use the backlog and report artifacts together so recommendations keep full appendix traceability.",
		}
	default:
		return nil
	}
}

func focusPresetEmptyStateStatus(preset FocusPreset, summary Summary) string {
	if preset == FocusPresetDriftReview {
		if summary.RegressDrift == nil {
			return "baseline_not_supplied"
		}
		if strings.TrimSpace(summary.RegressDrift.ComparisonStatus) != "" && strings.TrimSpace(summary.RegressDrift.ComparisonStatus) != regress.DriftComparisonStatusOK {
			return "drift_comparison_unavailable"
		}
		if !summary.RegressDrift.DriftDetected {
			return "no_drift_detected"
		}
	}
	return "no_matching_paths"
}

func focusPresetEmptyStateMessage(preset FocusPreset, summary Summary) string {
	switch preset {
	case FocusPresetDriftReview:
		if summary.RegressDrift == nil {
			return "No drift baseline was provided, so Wrkr cannot build a drift-review preset from this report alone."
		}
		if strings.TrimSpace(summary.RegressDrift.ComparisonStatus) != "" && strings.TrimSpace(summary.RegressDrift.ComparisonStatus) != regress.DriftComparisonStatusOK {
			return "Wrkr could not complete action-path drift comparison for the supplied baseline. Regenerate the baseline from a current scan snapshot before relying on drift-review output."
		}
		if !summary.RegressDrift.DriftDetected {
			return "Wrkr did not detect regress drift for the supplied baseline, so there are no drift-review items to highlight."
		}
		return "Wrkr detected drift, but none of the current buyer-facing workflow paths matched the preset filter."
	case FocusPresetContradictions:
		return "No contradictory workflow evidence was projected for the current report scope."
	case FocusPresetEvidenceGaps:
		return "The current workflow paths did not match the selected evidence-gap filter."
	default:
		return "The current workflow paths did not match the selected preset."
	}
}

func orderedFocusPathIDs(items []AgentActionBOMItem) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		pathID := strings.TrimSpace(item.PathID)
		if pathID == "" {
			continue
		}
		if _, ok := seen[pathID]; ok {
			continue
		}
		seen[pathID] = struct{}{}
		out = append(out, pathID)
	}
	return out
}

func orderedFocusWorkflowChainRefs(items []AgentActionBOMItem) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, item := range items {
		for _, ref := range item.WorkflowChainRefs {
			trimmed := strings.TrimSpace(ref)
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	return out
}

func driftReviewPathIDs(summary Summary) map[string]struct{} {
	if summary.RegressDrift == nil {
		return nil
	}
	out := map[string]struct{}{}
	for _, category := range summary.RegressDrift.DriftCategories {
		for _, ref := range category.AffectedPathRefs {
			trimmed := strings.TrimSpace(ref)
			if !strings.HasPrefix(trimmed, "current:") {
				continue
			}
			pathID := strings.TrimPrefix(trimmed, "current:")
			if pathID == "" || strings.Contains(pathID, "|") {
				continue
			}
			out[pathID] = struct{}{}
		}
		for _, example := range category.Examples {
			if pathID := strings.TrimSpace(example.PathID); pathID != "" {
				out[pathID] = struct{}{}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func orderedFocusBacklogIDs(backlog *controlbacklog.Backlog, pathIDs []string) []string {
	if backlog == nil || len(backlog.Items) == 0 || len(pathIDs) == 0 {
		return nil
	}
	pathSet := map[string]struct{}{}
	for _, pathID := range pathIDs {
		if strings.TrimSpace(pathID) == "" {
			continue
		}
		pathSet[strings.TrimSpace(pathID)] = struct{}{}
	}
	out := []string{}
	seen := map[string]struct{}{}
	for _, item := range backlog.Items {
		if _, ok := pathSet[strings.TrimSpace(item.LinkedActionPathID)]; !ok {
			continue
		}
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func hasActionClass(values []string, classes ...string) bool {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		for _, class := range classes {
			if trimmed == class {
				return true
			}
		}
	}
	return false
}

func hasHighStakesPreset(values []risk.HighStakesPreset, presets ...string) bool {
	for _, value := range values {
		preset := strings.TrimSpace(value.Preset)
		for _, candidate := range presets {
			if preset == candidate {
				return true
			}
		}
	}
	return false
}

func hasUnknownEvidenceState(item AgentActionBOMItem) bool {
	return normalizeEvidenceState(item.OwnerEvidenceState) == risk.EvidenceStateUnknown ||
		normalizeEvidenceState(item.ApprovalEvidenceState) == risk.EvidenceStateUnknown ||
		normalizeEvidenceState(item.ProofEvidenceState) == risk.EvidenceStateUnknown ||
		normalizeEvidenceState(item.RuntimeEvidenceState) == risk.EvidenceStateUnknown ||
		normalizeEvidenceState(item.TargetEvidenceState) == risk.EvidenceStateUnknown ||
		normalizeEvidenceState(item.CredentialEvidenceState) == risk.EvidenceStateUnknown
}

func hasContradictoryEvidenceState(item AgentActionBOMItem) bool {
	return normalizeEvidenceState(item.OwnerEvidenceState) == risk.EvidenceStateContradictory ||
		normalizeEvidenceState(item.ApprovalEvidenceState) == risk.EvidenceStateContradictory ||
		normalizeEvidenceState(item.ProofEvidenceState) == risk.EvidenceStateContradictory ||
		normalizeEvidenceState(item.RuntimeEvidenceState) == risk.EvidenceStateContradictory ||
		normalizeEvidenceState(item.TargetEvidenceState) == risk.EvidenceStateContradictory ||
		normalizeEvidenceState(item.CredentialEvidenceState) == risk.EvidenceStateContradictory
}

func normalizeEvidenceState(value string) string {
	switch strings.TrimSpace(value) {
	case risk.EvidenceStateVerified:
		return risk.EvidenceStateVerified
	case risk.EvidenceStateDeclared:
		return risk.EvidenceStateDeclared
	case risk.EvidenceStateInferred:
		return risk.EvidenceStateInferred
	case risk.EvidenceStateContradictory:
		return risk.EvidenceStateContradictory
	default:
		return risk.EvidenceStateUnknown
	}
}

func dedupeSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
