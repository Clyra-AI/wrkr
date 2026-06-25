package risk

import (
	"sort"
	"strings"
)

func ProjectReviewLifecycleTransitions(current []ActionPath, previous []ActionPath) []ActionPath {
	if len(current) == 0 {
		return nil
	}

	previousByPathID := map[string]ActionPath{}
	previousByResolutionKey := map[string]ActionPath{}
	previousByRepoLocation := map[string]ActionPath{}
	for _, raw := range previous {
		path := ProjectActionPath(raw)
		if pathID := strings.TrimSpace(path.PathID); pathID != "" {
			previousByPathID[pathID] = path
		}
		if resolutionKey := strings.TrimSpace(path.ResolutionKey); resolutionKey != "" {
			previousByResolutionKey[resolutionKey] = path
		}
		if key := reviewLifecycleRepoLocationKey(path); key != "" {
			previousByRepoLocation[key] = path
		}
	}

	out := make([]ActionPath, 0, len(current))
	for _, raw := range current {
		path := ProjectActionPath(raw)
		if previousPath, ok := matchPreviousReviewLifecyclePath(path, previousByPathID, previousByResolutionKey, previousByRepoLocation); ok {
			path = applyReviewLifecycleTransition(path, previousPath)
		}
		path.ReviewAuditContext = buildReviewAuditContext(path)
		path = ProjectActionPath(path)
		out = append(out, path)
	}

	sort.Slice(out, func(i, j int) bool {
		return compareActionPaths(out[i], out[j])
	})
	return out
}

func applyCurrentReviewLifecycleProjection(path ActionPath) ActionPath {
	out := path

	state := strings.TrimSpace(out.ReviewLifecycleState)
	switch {
	case state == "" && containsReasonCode(out.ReviewLifecycleReasons, "review_declaration:expired"):
		state = ReviewLifecycleStateExpired
	case state == "" && pathHasImportedControl(out):
		state = ReviewLifecycleStateCoveredByImportedControl
	case state == "":
		state = ReviewLifecycleStateOpen
	}
	if !ValidReviewLifecycleState(state) {
		state = ReviewLifecycleStateOpen
	}
	out.ReviewLifecycleState = state

	if reviewLifecycleResolvedAppendixState(state) {
		out.ResolvedVisibility = ReviewResolvedVisibilityAppendix
		out.ResolvedAppendixRefs = reviewLifecycleAppendixRefs(out)
	} else {
		out.ResolvedVisibility = ReviewResolvedVisibilityPrimary
		out.ResolvedAppendixRefs = nil
	}

	out.ReviewLifecycleReasons = dedupeSortedStrings(append(append([]string(nil), out.ReviewLifecycleReasons...), reviewLifecycleReasonForState(state)))
	out.ReviewAuditContext = buildReviewAuditContext(out)
	return out
}

func applyReviewLifecycleTransition(current ActionPath, previous ActionPath) ActionPath {
	if !reviewLifecycleResolvedAppendixState(previous.ReviewLifecycleState) || reviewLifecycleResolvedAppendixState(current.ReviewLifecycleState) {
		return current
	}

	reopenReasons := reviewReopenReasons(previous, current)
	if len(reopenReasons) == 0 {
		return current
	}

	out := current
	out.PreviousReviewLifecycleState = strings.TrimSpace(previous.ReviewLifecycleState)
	out.ReopenState = ReviewReopenStateReopened
	out.ReopenReasons = dedupeSortedStrings(reopenReasons)
	out.ReopenEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), previous.ControlEvidenceRefs...), current.ControlEvidenceRefs...))
	out.ReviewLifecycleState = ReviewLifecycleStateReopenedByDrift
	out.ReviewLifecycleReasons = dedupeSortedStrings(append(out.ReviewLifecycleReasons, "review_lifecycle:reopened_by_drift"))
	out.ResolvedVisibility = ReviewResolvedVisibilityPrimary
	out.ResolvedAppendixRefs = nil
	return out
}

func applyResolvedReviewLifecycleOutputOverrides(path ActionPath) ActionPath {
	if !reviewLifecycleResolvedAppendixState(path.ReviewLifecycleState) {
		return path
	}
	out := path
	out.ControlPriority = ControlPriorityInventoryHygiene
	out.RiskTier = RiskTierLow
	out.RecommendedAction = "inventory"
	out.ControlState = ControlStateInventoryOnly
	out.ControlStateReasons = dedupeSortedStrings(append(out.ControlStateReasons, "review_lifecycle:resolved_appendix"))
	return out
}

func matchPreviousReviewLifecyclePath(path ActionPath, byPathID map[string]ActionPath, byResolutionKey map[string]ActionPath, byRepoLocation map[string]ActionPath) (ActionPath, bool) {
	if pathID := strings.TrimSpace(path.PathID); pathID != "" {
		if matched, ok := byPathID[pathID]; ok {
			return matched, true
		}
	}
	if resolutionKey := strings.TrimSpace(path.ResolutionKey); resolutionKey != "" {
		if matched, ok := byResolutionKey[resolutionKey]; ok {
			return matched, true
		}
	}
	if key := reviewLifecycleRepoLocationKey(path); key != "" {
		if matched, ok := byRepoLocation[key]; ok {
			return matched, true
		}
	}
	return ActionPath{}, false
}

func reviewLifecycleRepoLocationKey(path ActionPath) string {
	repo := strings.TrimSpace(path.Repo)
	location := strings.TrimSpace(path.Location)
	if repo == "" && location == "" {
		return ""
	}
	return repo + "|" + location
}

func reviewReopenReasons(previous ActionPath, current ActionPath) []string {
	reasons := []string{}
	if strings.TrimSpace(current.ReviewLifecycleState) == ReviewLifecycleStateExpired ||
		containsReasonCode(current.ReviewLifecycleReasons, "review_declaration:expired") {
		reasons = append(reasons, "declaration_expired")
	}
	if reviewLifecycleScopeContradicted(firstNonEmptyString(strings.TrimSpace(current.ReviewScope), strings.TrimSpace(previous.ReviewScope)), current) {
		reasons = append(reasons, "scope_contradicted_by_production_evidence")
	}
	if pathHasImportedControl(previous) && !pathHasImportedControl(current) {
		reasons = append(reasons, "imported_control_disappeared")
	}
	if previousFamily, currentFamily := reviewLifecycleCredentialFamily(previous), reviewLifecycleCredentialFamily(current); previousFamily != "" && currentFamily != "" && previousFamily != currentFamily {
		reasons = append(reasons, "credential_family_changed")
	}
	if reviewLifecycleTargetEscalated(previous, current) {
		reasons = append(reasons, "target_class_escalated")
	}
	if len(reasons) == 0 && strings.TrimSpace(previous.ReviewLifecycleState) != "" && strings.TrimSpace(current.ReviewLifecycleState) == ReviewLifecycleStateOpen {
		reasons = append(reasons, "review_context_removed")
	}
	return dedupeSortedStrings(reasons)
}

func pathHasImportedControl(path ActionPath) bool {
	if strings.TrimSpace(path.ReviewLifecycleState) == ReviewLifecycleStateCoveredByImportedControl {
		return true
	}
	if strings.TrimSpace(path.ControlResolutionState) != ControlResolutionStateExternalControlReference {
		return false
	}
	switch strings.TrimSpace(path.ApprovalEvidenceState) {
	case EvidenceStateContradictory, EvidenceStateUnknown:
		return false
	}
	return len(path.ControlEvidenceRefs) > 0
}

func reviewLifecycleResolvedAppendixState(state string) bool {
	switch strings.TrimSpace(state) {
	case ReviewLifecycleStateDeclaredControlled,
		ReviewLifecycleStateCoveredByImportedControl,
		ReviewLifecycleStateAcceptedRisk,
		ReviewLifecycleStateNotApplicable,
		ReviewLifecycleStateFalsePositive:
		return true
	default:
		return false
	}
}

func reviewLifecycleReasonForState(state string) string {
	switch strings.TrimSpace(state) {
	case ReviewLifecycleStateDeclaredControlled:
		return "review_lifecycle:declared_controlled"
	case ReviewLifecycleStateCoveredByImportedControl:
		return "review_lifecycle:covered_by_imported_control"
	case ReviewLifecycleStateAcceptedRisk:
		return "review_lifecycle:accepted_risk"
	case ReviewLifecycleStateNotApplicable:
		return "review_lifecycle:not_applicable"
	case ReviewLifecycleStateFalsePositive:
		return "review_lifecycle:false_positive"
	case ReviewLifecycleStateNeedsRuntimeEvidence:
		return "review_lifecycle:needs_runtime_evidence"
	case ReviewLifecycleStateExpired:
		return "review_lifecycle:expired"
	case ReviewLifecycleStateReopenedByDrift:
		return "review_lifecycle:reopened_by_drift"
	case ReviewLifecycleStateConfirmed:
		return "review_lifecycle:confirmed"
	default:
		return "review_lifecycle:open"
	}
}

func reviewLifecycleAppendixRefs(path ActionPath) []string {
	refs := []string{"risk_report:action_paths", "report_summary:resolved_appendix"}
	if pathID := strings.TrimSpace(path.PathID); pathID != "" {
		refs = append(refs, "path:"+pathID)
	}
	if resolutionKey := strings.TrimSpace(path.ResolutionKey); resolutionKey != "" {
		refs = append(refs, "resolution_key:"+resolutionKey)
	}
	return dedupeSortedStrings(refs)
}

func buildReviewAuditContext(path ActionPath) *ReviewAuditContext {
	state := strings.TrimSpace(path.ReviewLifecycleState)
	owner := strings.TrimSpace(path.ReviewOwner)
	source := strings.TrimSpace(path.ReviewSource)
	rationale := strings.TrimSpace(path.ReviewRationale)
	observedAt := strings.TrimSpace(path.ReviewObservedAt)
	validUntil := strings.TrimSpace(path.ReviewValidUntil)
	scope := strings.TrimSpace(path.ReviewScope)
	evidenceRefs := dedupeSortedStrings(path.ControlEvidenceRefs)
	reasonCodes := dedupeSortedStrings(append(append([]string(nil), path.ReviewLifecycleReasons...), path.ReopenReasons...))
	if state == "" && owner == "" && source == "" && rationale == "" && observedAt == "" && validUntil == "" && scope == "" && len(evidenceRefs) == 0 && len(reasonCodes) == 0 {
		return nil
	}
	return &ReviewAuditContext{
		LifecycleState: state,
		Owner:          owner,
		Source:         source,
		Rationale:      rationale,
		ObservedAt:     observedAt,
		ValidUntil:     validUntil,
		Scope:          scope,
		EvidenceRefs:   evidenceRefs,
		ReasonCodes:    reasonCodes,
	}
}

func reviewLifecycleScopeContradicted(scope string, path ActionPath) bool {
	switch strings.TrimSpace(scope) {
	case "non_production":
		return path.ProductionWrite ||
			len(path.MatchedProductionTargets) > 0 ||
			strings.TrimSpace(path.TargetClass) == TargetClassProductionImpacting ||
			strings.TrimSpace(path.TargetClass) == TargetClassReleaseAdjacent
	case "production":
		return !path.ProductionWrite &&
			len(path.MatchedProductionTargets) == 0 &&
			strings.TrimSpace(path.TargetClass) != TargetClassProductionImpacting &&
			strings.TrimSpace(path.TargetClass) != TargetClassReleaseAdjacent
	default:
		return false
	}
}

func reviewLifecycleCredentialFamily(path ActionPath) string {
	if path.CredentialAuthority != nil && strings.TrimSpace(path.CredentialAuthority.CredentialKind) != "" {
		return strings.TrimSpace(path.CredentialAuthority.CredentialKind)
	}
	if path.CredentialProvenance != nil && strings.TrimSpace(path.CredentialProvenance.CredentialKind) != "" {
		return strings.TrimSpace(path.CredentialProvenance.CredentialKind)
	}
	for _, item := range path.Credentials {
		if item == nil {
			continue
		}
		if value := strings.TrimSpace(item.CredentialKind); value != "" {
			return value
		}
	}
	return ""
}

func reviewLifecycleTargetEscalated(previous ActionPath, current ActionPath) bool {
	previousRank := targetClassRank(previous.TargetClass)
	currentRank := targetClassRank(current.TargetClass)
	return currentRank < previousRank
}

func CloneReviewAuditContext(in *ReviewAuditContext) *ReviewAuditContext {
	if in == nil {
		return nil
	}
	out := *in
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	return &out
}
