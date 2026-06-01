package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/owners"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func resolveExecutiveRollup(summary Summary) *controlbacklog.ExecutiveRollup {
	if summary.ExecutiveRollup != nil {
		return summary.ExecutiveRollup
	}
	return buildExecutiveRollup(summary)
}

func resolveGovernedUsageMetrics(summary Summary) *controlbacklog.GovernedUsageMetrics {
	if summary.GovernedUsageMetrics != nil {
		return summary.GovernedUsageMetrics
	}
	return buildGovernedUsageMetrics(summary)
}

func buildExecutiveRollup(summary Summary) *controlbacklog.ExecutiveRollup {
	rollup := &controlbacklog.ExecutiveRollup{}
	if len(summary.ActionPaths) == 0 {
		return rollup
	}

	backlogByPath := backlogItemsByPath(summary.ControlBacklog)
	repoClusterByPath := repoClusterLabels(summary)

	type accumulator struct {
		group controlbacklog.ExecutiveRollupGroup
		paths []string
	}

	groups := map[string]*accumulator{}
	for _, path := range summary.ActionPaths {
		dimensions := controlbacklog.ExecutiveRollupDimensions{
			ActionClass:         executiveActionClass(path),
			TargetClass:         executiveTargetClass(path),
			RiskZone:            executiveRiskZone(path),
			CredentialAuthority: executiveCredentialAuthority(path),
			ProductionTarget:    executiveProductionTarget(path),
			EvidenceState:       executiveEvidenceState(path),
			OwnerState:          executiveOwnerState(path),
			RepoCluster:         repoClusterByPath[strings.TrimSpace(path.PathID)],
			DetectorConfidence:  executiveDetectorConfidence(path),
			ContradictionState:  executiveContradictionState(path),
			ClosureAction:       executiveClosureAction(path, backlogByPath[strings.TrimSpace(path.PathID)]),
		}
		key := executiveRollupKey(dimensions)
		current := groups[key]
		if current == nil {
			current = &accumulator{
				group: controlbacklog.ExecutiveRollupGroup{
					GroupID:              executiveRollupID(key),
					HighestSeverity:      executiveSeverity(path),
					HighestPriority:      executivePriority(path),
					EvidenceStateSummary: controlbacklog.ExecutiveRollupEvidenceStateCounts{},
					Dimensions:           dimensions,
				},
			}
			groups[key] = current
		}
		current.group.Count++
		current.group.HighestSeverity = strongerExecutiveSeverity(current.group.HighestSeverity, executiveSeverity(path))
		current.group.HighestPriority = strongerExecutivePriority(current.group.HighestPriority, executivePriority(path))
		incrementExecutiveEvidenceState(&current.group.EvidenceStateSummary, executiveEvidenceState(path))
		current.paths = append(current.paths, strings.TrimSpace(path.PathID))
	}

	ordered := make([]controlbacklog.ExecutiveRollupGroup, 0, len(groups))
	for _, item := range groups {
		sort.Strings(item.paths)
		item.group.TopExampleRefs = append([]string(nil), item.paths...)
		if len(item.group.TopExampleRefs) > 3 {
			item.group.TopExampleRefs = item.group.TopExampleRefs[:3]
		}
		item.group.ClosureRecommendation = executiveClosureRecommendation(item.group)
		item.group.Rationale = executiveRollupRationale(item.group)
		ordered = append(ordered, item.group)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return compareExecutiveRollupGroups(ordered[i], ordered[j])
	})

	rollup.TotalGroups = len(ordered)
	rollup.TotalPaths = len(summary.ActionPaths)
	rollup.Groups = ordered
	return rollup
}

func buildGovernedUsageMetrics(summary Summary) *controlbacklog.GovernedUsageMetrics {
	metrics := &controlbacklog.GovernedUsageMetrics{
		EvidencePacks:           executiveEvidencePackCount(summary),
		AuditExports:            executiveAuditExportCount(summary),
		GovernedAgentsWorkflows: executiveGovernedSurfaceCount(summary),
	}
	if len(summary.ActionPaths) == 0 {
		return metrics
	}

	runtimePathIDs := runtimeConnectedPathIDs(summary)
	for _, path := range summary.ActionPaths {
		if strings.TrimSpace(path.ConfidenceLane) != "context_only" {
			metrics.ActiveMonitoredActionPaths++
			if strings.TrimSpace(path.ControlPriority) != risk.ControlPriorityInventoryHygiene {
				metrics.GovernedPaths++
			}
		}
		switch executiveControlVerificationState(path) {
		case "verified":
			metrics.VerifiedControlPaths++
		case "unknown":
			metrics.UnknownControlPaths++
		case "contradictory":
			metrics.ContradictoryPaths++
		}
		if executiveApprovalDecisionPresent(path) {
			metrics.ApprovalDecisions++
		}
	}

	metrics.ConnectedRuntimes = len(runtimePathIDs)
	return metrics
}

func executiveActionClass(path risk.ActionPath) string {
	values := append([]string(nil), path.ActionClasses...)
	sort.Strings(values)
	for _, candidate := range []string{"deploy", "write", "repo_write", "admin", "delete", "credential_access"} {
		for _, value := range values {
			if strings.TrimSpace(value) == candidate {
				return candidate
			}
		}
	}
	switch {
	case path.ProductionWrite || path.DeployWrite:
		return "deploy"
	case path.WriteCapable:
		return "write"
	case path.CredentialAccess:
		return "credential_access"
	case len(values) > 0:
		return strings.TrimSpace(values[0])
	default:
		return "unknown"
	}
}

func executiveTargetClass(path risk.ActionPath) string {
	if value := strings.TrimSpace(path.TargetClass); value != "" {
		return value
	}
	return "unknown"
}

func executiveRiskZone(path risk.ActionPath) string {
	if value := strings.TrimSpace(path.RiskZone); value != "" {
		return value
	}
	return "unknown"
}

func executiveCredentialAuthority(path risk.ActionPath) string {
	authority := agginventory.NormalizeCredentialAuthority(path.CredentialAuthority)
	switch {
	case authority == nil && !path.CredentialAccess:
		return "none"
	case authority == nil:
		return "unknown"
	case authority.StandingAccess:
		return "standing"
	case authority.AccessType == agginventory.CredentialAccessTypeJIT || authority.LikelyJIT:
		return "jit"
	case authority.AccessType == agginventory.CredentialAccessTypeWorkload:
		return "workload"
	case authority.AccessType == agginventory.CredentialAccessTypeDelegated:
		return "delegated"
	case authority.AccessType == agginventory.CredentialAccessTypeInherited:
		return "inherited"
	case authority.CredentialReferencedByWorkflow && !authority.CredentialUsableByPath:
		return "referenced_only"
	case authority.CredentialPresent || authority.CredentialUsableByPath:
		return "present"
	default:
		return "unknown"
	}
}

func executiveProductionTarget(path risk.ActionPath) string {
	if path.ProductionWrite || len(path.MatchedProductionTargets) > 0 || strings.TrimSpace(path.TargetClass) == risk.TargetClassProductionImpacting {
		return "production_targeted"
	}
	return "non_production_or_unknown"
}

func executiveEvidenceState(path risk.ActionPath) string {
	state := strongestExecutiveEvidenceState(
		path.ApprovalEvidenceState,
		path.OwnerEvidenceState,
		path.ProofEvidenceState,
		path.RuntimeEvidenceState,
		path.TargetEvidenceState,
		path.CredentialEvidenceState,
	)
	if state == "" {
		return risk.EvidenceStateUnknown
	}
	return state
}

func strongestExecutiveEvidenceState(values ...string) string {
	best := ""
	bestRank := -1
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		rank := executiveEvidenceStateRank(normalized)
		if rank > bestRank {
			best = normalized
			bestRank = rank
		}
	}
	return best
}

func executiveEvidenceStateRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.EvidenceStateContradictory:
		return 4
	case risk.EvidenceStateUnknown:
		return 3
	case risk.EvidenceStateInferred:
		return 2
	case risk.EvidenceStateDeclared:
		return 1
	case risk.EvidenceStateVerified:
		return 0
	default:
		return -1
	}
}

func executiveOwnerState(path risk.ActionPath) string {
	switch {
	case strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceConflict,
		strings.TrimSpace(path.OwnerEvidenceState) == risk.EvidenceStateContradictory,
		strings.Contains(strings.ToLower(strings.TrimSpace(path.OwnershipState)), "conflict"):
		return "conflicting"
	case strings.TrimSpace(path.OwnerEvidenceState) == risk.EvidenceStateVerified,
		strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusExplicit,
		strings.TrimSpace(path.OwnershipState) == "verified":
		return "verified"
	case strings.TrimSpace(path.OwnerEvidenceState) == risk.EvidenceStateDeclared:
		return "declared"
	case strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusInferred,
		strings.TrimSpace(path.OwnerEvidenceState) == risk.EvidenceStateInferred,
		strings.TrimSpace(path.OwnershipState) == "inferred":
		return "inferred"
	default:
		return "unknown"
	}
}

func repoClusterLabels(summary Summary) map[string]string {
	byPath := map[string]string{}
	reposByIdentity := map[string]map[string]struct{}{}
	for _, path := range summary.ActionPaths {
		identity := strings.TrimSpace(path.ExecutionIdentity)
		repo := strings.TrimSpace(path.Repo)
		if identity == "" || repo == "" {
			continue
		}
		if reposByIdentity[identity] == nil {
			reposByIdentity[identity] = map[string]struct{}{}
		}
		reposByIdentity[identity][repo] = struct{}{}
	}
	groups := summary.ExposureGroups
	if len(groups) == 0 && len(summary.ActionPaths) > 0 {
		groups = risk.BuildExposureGroups(summary.ActionPaths)
	}
	for _, group := range groups {
		label := "single_repo"
		switch {
		case len(group.Repos) > 1 && group.SharedExecutionIdentity:
			label = "cross_repo_shared_identity"
		case len(group.Repos) > 1:
			label = "multi_repo_cluster"
		case group.SharedExecutionIdentity:
			label = "shared_identity_single_repo"
		}
		for _, pathID := range group.PathIDs {
			byPath[strings.TrimSpace(pathID)] = label
		}
	}
	for _, path := range summary.ActionPaths {
		key := strings.TrimSpace(path.PathID)
		if key == "" {
			continue
		}
		if repos := reposByIdentity[strings.TrimSpace(path.ExecutionIdentity)]; len(repos) > 1 {
			byPath[key] = "cross_repo_shared_identity"
			continue
		}
		if _, ok := byPath[key]; ok {
			continue
		}
		if path.SharedExecutionIdentity {
			byPath[key] = "shared_identity_single_repo"
			continue
		}
		byPath[key] = "single_repo"
	}
	return byPath
}

func executiveDetectorConfidence(path risk.ActionPath) string {
	if value := strings.TrimSpace(path.ConfidenceLane); value != "" {
		return value
	}
	return "unknown"
}

func executiveContradictionState(path risk.ActionPath) string {
	if strings.TrimSpace(path.ControlResolutionState) == risk.ControlResolutionStateContradictoryControl ||
		len(path.Contradictions) > 0 ||
		executiveEvidenceState(path) == risk.EvidenceStateContradictory {
		return "contradictory"
	}
	return "consistent"
}

func executiveClosureAction(path risk.ActionPath, backlog controlbacklog.Item) string {
	if value := strings.TrimSpace(backlog.RecommendedAction); value != "" {
		return value
	}
	switch strings.TrimSpace(path.RecommendedAction) {
	case "control":
		return controlbacklog.ActionRemediate
	case "approval", "proof":
		return controlbacklog.ActionAttachEvidence
	case "inventory":
		return controlbacklog.ActionInventoryReview
	default:
		return controlbacklog.ActionMonitor
	}
}

func executiveRollupKey(dimensions controlbacklog.ExecutiveRollupDimensions) string {
	return strings.Join([]string{
		dimensions.ActionClass,
		dimensions.TargetClass,
		dimensions.RiskZone,
		dimensions.CredentialAuthority,
		dimensions.ProductionTarget,
		dimensions.EvidenceState,
		dimensions.OwnerState,
		dimensions.RepoCluster,
		dimensions.DetectorConfidence,
		dimensions.ContradictionState,
		dimensions.ClosureAction,
	}, "|")
}

func executiveRollupID(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return "xrg-" + hex.EncodeToString(sum[:6])
}

func executiveSeverity(path risk.ActionPath) string {
	if value := strings.TrimSpace(path.RiskTier); value != "" {
		return value
	}
	return "unknown"
}

func executivePriority(path risk.ActionPath) string {
	if value := strings.TrimSpace(path.ControlPriority); value != "" {
		return value
	}
	return risk.ControlPriorityReviewQueue
}

func strongerExecutiveSeverity(current, incoming string) string {
	if executiveSeverityRank(incoming) > executiveSeverityRank(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func executiveSeverityRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.RiskTierCritical:
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func strongerExecutivePriority(current, incoming string) string {
	if executivePriorityRank(incoming) < executivePriorityRank(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func executivePriorityRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.ControlPriorityControlFirst:
		return 0
	case risk.ControlPriorityReviewQueue:
		return 1
	case risk.ControlPriorityInventoryHygiene:
		return 2
	default:
		return 3
	}
}

func incrementExecutiveEvidenceState(counts *controlbacklog.ExecutiveRollupEvidenceStateCounts, state string) {
	if counts == nil {
		return
	}
	switch strings.TrimSpace(state) {
	case risk.EvidenceStateVerified:
		counts.Verified++
	case risk.EvidenceStateDeclared:
		counts.Declared++
	case risk.EvidenceStateInferred:
		counts.Inferred++
	case risk.EvidenceStateContradictory:
		counts.Contradictory++
	default:
		counts.Unknown++
	}
}

func executiveClosureRecommendation(group controlbacklog.ExecutiveRollupGroup) string {
	switch strings.TrimSpace(group.Dimensions.ClosureAction) {
	case controlbacklog.ActionRemediate:
		return "remediate standing production deploy paths first"
	case controlbacklog.ActionAttachEvidence:
		return "attach missing approval, proof, or runtime evidence before promotion"
	case controlbacklog.ActionApprove:
		return "complete the explicit approval trail and rescan"
	case controlbacklog.ActionInventoryReview:
		return "review inventory-only paths before promoting governance claims"
	case controlbacklog.ActionMonitor:
		return "monitor this grouped path set for drift and evidence movement"
	default:
		return "review grouped paths and close the highest-priority evidence gap"
	}
}

func executiveRollupRationale(group controlbacklog.ExecutiveRollupGroup) []string {
	return []string{
		fmt.Sprintf("%d %s paths grouped by %s and %s evidence", group.Count, group.Dimensions.ActionClass, group.Dimensions.TargetClass, group.Dimensions.EvidenceState),
		fmt.Sprintf("closure=%s repo_cluster=%s credential_authority=%s", group.Dimensions.ClosureAction, group.Dimensions.RepoCluster, group.Dimensions.CredentialAuthority),
	}
}

func compareExecutiveRollupGroups(left, right controlbacklog.ExecutiveRollupGroup) bool {
	if executiveSeverityRank(left.HighestSeverity) != executiveSeverityRank(right.HighestSeverity) {
		return executiveSeverityRank(left.HighestSeverity) > executiveSeverityRank(right.HighestSeverity)
	}
	if executiveUnresolvedClosure(left) != executiveUnresolvedClosure(right) {
		return executiveUnresolvedClosure(left)
	}
	if executiveProductionRank(left.Dimensions.ProductionTarget) != executiveProductionRank(right.Dimensions.ProductionTarget) {
		return executiveProductionRank(left.Dimensions.ProductionTarget) > executiveProductionRank(right.Dimensions.ProductionTarget)
	}
	if executiveCredentialAuthorityRank(left.Dimensions.CredentialAuthority) != executiveCredentialAuthorityRank(right.Dimensions.CredentialAuthority) {
		return executiveCredentialAuthorityRank(left.Dimensions.CredentialAuthority) > executiveCredentialAuthorityRank(right.Dimensions.CredentialAuthority)
	}
	if executiveContradictionRank(left.Dimensions.ContradictionState) != executiveContradictionRank(right.Dimensions.ContradictionState) {
		return executiveContradictionRank(left.Dimensions.ContradictionState) > executiveContradictionRank(right.Dimensions.ContradictionState)
	}
	if left.Count != right.Count {
		return left.Count > right.Count
	}
	return left.GroupID < right.GroupID
}

func executiveUnresolvedClosure(group controlbacklog.ExecutiveRollupGroup) bool {
	switch strings.TrimSpace(group.Dimensions.ClosureAction) {
	case "", controlbacklog.ActionMonitor, controlbacklog.ActionDebugOnly, controlbacklog.ActionSuppress:
		return false
	default:
		return true
	}
}

func executiveProductionRank(value string) int {
	if strings.TrimSpace(value) == "production_targeted" {
		return 1
	}
	return 0
}

func executiveCredentialAuthorityRank(value string) int {
	switch strings.TrimSpace(value) {
	case "standing":
		return 4
	case "delegated":
		return 3
	case "workload":
		return 2
	case "jit":
		return 1
	default:
		return 0
	}
}

func executiveContradictionRank(value string) int {
	if strings.TrimSpace(value) == "contradictory" {
		return 1
	}
	return 0
}

func executiveControlVerificationState(path risk.ActionPath) string {
	switch strings.TrimSpace(path.ControlResolutionState) {
	case risk.ControlResolutionStateContradictoryControl:
		return "contradictory"
	case risk.ControlResolutionStateDetectedControl,
		risk.ControlResolutionStateDeclaredControl,
		risk.ControlResolutionStateExternalControlReference:
		return "verified"
	default:
		return "unknown"
	}
}

func executiveApprovalDecisionPresent(path risk.ActionPath) bool {
	switch strings.TrimSpace(path.ApprovalEvidenceState) {
	case risk.EvidenceStateVerified, risk.EvidenceStateDeclared, risk.EvidenceStateInferred:
		return true
	default:
		return false
	}
}

func runtimeConnectedPathIDs(summary Summary) map[string]struct{} {
	connected := map[string]struct{}{}
	if summary.RuntimeSessions != nil {
		for _, item := range summary.RuntimeSessions.Correlations {
			if strings.TrimSpace(item.Status) == ingest.CorrelationStatusMatched && strings.TrimSpace(item.PathID) != "" {
				connected[strings.TrimSpace(item.PathID)] = struct{}{}
			}
		}
	}
	if summary.RuntimeEvidence != nil {
		for _, item := range summary.RuntimeEvidence.Correlations {
			if strings.TrimSpace(item.Status) == ingest.CorrelationStatusMatched && strings.TrimSpace(item.PathID) != "" {
				connected[strings.TrimSpace(item.PathID)] = struct{}{}
			}
		}
	}
	if len(connected) > 0 {
		return connected
	}
	for _, path := range summary.ActionPaths {
		if strings.TrimSpace(path.RuntimeEvidenceState) == risk.EvidenceStateVerified && strings.TrimSpace(path.PathID) != "" {
			connected[strings.TrimSpace(path.PathID)] = struct{}{}
		}
	}
	return connected
}

func executiveEvidencePackCount(summary Summary) int {
	if summary.EvidencePackets != nil {
		return summary.EvidencePackets.TotalPackets
	}
	seen := map[string]struct{}{}
	for _, path := range summary.ActionPaths {
		if len(path.EvidencePacketRefs) == 0 && strings.TrimSpace(path.EvidencePacketStatus) == "" {
			continue
		}
		if strings.TrimSpace(path.PathID) != "" {
			seen[strings.TrimSpace(path.PathID)] = struct{}{}
		}
	}
	return len(seen)
}

func executiveAuditExportCount(summary Summary) int {
	count := 2 // report summary plus evidence bundle remain the deterministic baseline export families.
	if len(summary.ActionPaths) > 0 {
		count++
	}
	if summary.ControlBacklog != nil && len(summary.ControlBacklog.Items) > 0 {
		count++
	}
	return count
}

func executiveGovernedSurfaceCount(summary Summary) int {
	if len(summary.ActionSurfaceRegistry) > 0 {
		return len(summary.ActionSurfaceRegistry)
	}
	seen := map[string]struct{}{}
	for _, path := range summary.ActionPaths {
		if strings.TrimSpace(path.ConfidenceLane) == "context_only" {
			continue
		}
		key := strings.Join([]string{
			strings.TrimSpace(path.Org),
			strings.TrimSpace(path.Repo),
			strings.TrimSpace(path.ToolType),
			strings.TrimSpace(path.Location),
		}, "|")
		seen[key] = struct{}{}
	}
	return len(seen)
}
