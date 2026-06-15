package risk

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

const (
	InventoryRiskProductionBacked = "production_backed"
	InventoryRiskWriteCapable     = "write_capable"
	InventoryRiskCredentialAccess = "credential_access" // #nosec G101 -- deterministic enum label, not credential material.
	InventoryRiskVisibilityOnly   = "visibility_only"
	InventoryRiskDependencyOnly   = "dependency_only"

	ControlPriorityControlFirst     = "control_first"
	ControlPriorityReviewQueue      = "review_queue"
	ControlPriorityInventoryHygiene = "inventory_hygiene"

	RiskTierCritical = "critical"
	RiskTierHigh     = "high"
	RiskTierMedium   = "medium"
	RiskTierLow      = "low"
)

type governFirstModel struct {
	inventoryRisk       string
	inventoryRiskRank   int
	controlPriority     string
	controlPriorityRank int
	riskTier            string
	riskTierRank        int
	recommendedAction   string
	sourceSignalRank    int
	governableScore     float64
}

func deriveGovernFirstModel(path ActionPath) governFirstModel {
	model := governFirstModel{
		sourceSignalRank: sourceSignalRank(path),
	}
	lane := confidenceLaneForPath(path)

	dependencyOnly := actionPathDependencyOnly(path)
	strongerGovernableSignal := path.CredentialAccess ||
		path.WriteCapable ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		path.DeployWrite ||
		path.ProductionWrite ||
		pathHasHighStakesPreset(path) ||
		pathHasAnyMutableEndpoint(path) ||
		path.AttackPathScore >= 7.0 ||
		path.ApprovalGap ||
		actionPathHasCriticalTrustGap(path.TrustDepth) ||
		path.PolicyCoverageStatus == PolicyCoverageStatusNone ||
		len(path.PolicyMissingReasons) > 0

	switch {
	case path.ProductionWrite || len(path.MatchedProductionTargets) > 0 || strings.EqualFold(strings.TrimSpace(path.DeploymentStatus), "deployed"):
		model.inventoryRisk = InventoryRiskProductionBacked
		model.inventoryRiskRank = 0
	case path.WriteCapable || path.PullRequestWrite || path.MergeExecute || path.DeployWrite:
		model.inventoryRisk = InventoryRiskWriteCapable
		model.inventoryRiskRank = 1
	case path.CredentialAccess:
		model.inventoryRisk = InventoryRiskCredentialAccess
		model.inventoryRiskRank = 2
	case dependencyOnly:
		model.inventoryRisk = InventoryRiskDependencyOnly
		model.inventoryRiskRank = 4
	default:
		model.inventoryRisk = InventoryRiskVisibilityOnly
		model.inventoryRiskRank = 3
	}

	if lane == ConfidenceLaneContextOnly {
		model.controlPriority = ControlPriorityInventoryHygiene
		model.controlPriorityRank = 2
		model.riskTier = RiskTierLow
		model.riskTierRank = 3
		model.recommendedAction = "inventory"
		model.governableScore = 0
		return model
	}
	if lane == ConfidenceLaneSemanticReviewCandidate {
		model.controlPriority = ControlPriorityReviewQueue
		model.controlPriorityRank = 1
		if strongerGovernableSignal || path.AttackPathScore >= 7.0 {
			model.riskTier = RiskTierMedium
			model.riskTierRank = 2
		} else {
			model.riskTier = RiskTierLow
			model.riskTierRank = 3
		}
		model.recommendedAction = "proof"
		model.governableScore = float64(governFirstPriorityScore(path))
		return model
	}

	switch {
	case path.ProductionWrite ||
		pathHasHighImpactMutableEndpoint(path) ||
		(path.WriteCapable && (path.DeployWrite || path.MergeExecute)) ||
		(path.CredentialAccess && (path.DeployWrite || path.ProductionWrite)) ||
		(actionPathHasCriticalTrustGap(path.TrustDepth) && path.AttackPathScore >= 7.0) ||
		(path.AttackPathScore >= 8.5 && strongerGovernableSignal):
		model.controlPriority = ControlPriorityControlFirst
		model.controlPriorityRank = 0
	case dependencyOnly && !strongerGovernableSignal:
		model.controlPriority = ControlPriorityInventoryHygiene
		model.controlPriorityRank = 2
	case !path.CredentialAccess &&
		!path.PullRequestWrite &&
		!path.MergeExecute &&
		!path.DeployWrite &&
		!path.ProductionWrite &&
		!path.ApprovalGap &&
		path.AttackPathScore < 6.0:
		model.controlPriority = ControlPriorityInventoryHygiene
		model.controlPriorityRank = 2
	default:
		model.controlPriority = ControlPriorityReviewQueue
		model.controlPriorityRank = 1
	}
	if lane == ConfidenceLaneLikelyActionPath && model.controlPriority == ControlPriorityInventoryHygiene {
		model.controlPriority = ControlPriorityReviewQueue
		model.controlPriorityRank = 1
	}

	switch model.controlPriority {
	case ControlPriorityControlFirst:
		switch {
		case path.ProductionWrite ||
			pathHasHighImpactMutableEndpoint(path) ||
			(path.AttackPathScore >= 9.0 && (path.CredentialAccess || path.WriteCapable)):
			model.riskTier = RiskTierCritical
			model.riskTierRank = 0
		default:
			model.riskTier = RiskTierHigh
			model.riskTierRank = 1
		}
	case ControlPriorityReviewQueue:
		model.riskTier = RiskTierMedium
		model.riskTierRank = 2
	default:
		model.riskTier = RiskTierLow
		model.riskTierRank = 3
	}
	if lane == ConfidenceLaneLikelyActionPath && model.riskTier == RiskTierLow {
		model.riskTier = RiskTierMedium
		model.riskTierRank = 2
	}

	switch model.controlPriority {
	case ControlPriorityInventoryHygiene:
		model.recommendedAction = "inventory"
	case ControlPriorityControlFirst:
		model.recommendedAction = "control"
	default:
		if path.ApprovalGap && actionPathHasStrongIdentity(path) && actionPathHasStrongOwnership(path) && !actionPathUnknownToSecurity(path) {
			model.recommendedAction = "approval"
		} else {
			model.recommendedAction = "proof"
		}
	}

	model.governableScore = float64(governFirstPriorityScore(path))
	if model.inventoryRisk == InventoryRiskDependencyOnly && model.sourceSignalRank <= 1 && !strongerGovernableSignal {
		model.governableScore = 0
	}
	return model
}

func compareActionPaths(left, right ActionPath) bool {
	leftModel := deriveGovernFirstModel(left)
	rightModel := deriveGovernFirstModel(right)
	leftProjection := ProjectBuyerFacingActionPath(left)
	rightProjection := ProjectBuyerFacingActionPath(right)
	if leftModel.controlPriorityRank != rightModel.controlPriorityRank {
		return leftModel.controlPriorityRank < rightModel.controlPriorityRank
	}
	if IsActionPathEligible(leftProjection) != IsActionPathEligible(rightProjection) {
		return IsActionPathEligible(leftProjection)
	}
	if actionBindingRank(leftProjection.ActionBindingState) != actionBindingRank(rightProjection.ActionBindingState) {
		return actionBindingRank(leftProjection.ActionBindingState) < actionBindingRank(rightProjection.ActionBindingState)
	}
	if autonomyTierRank(leftProjection.AutonomyTier) != autonomyTierRank(rightProjection.AutonomyTier) {
		return autonomyTierRank(leftProjection.AutonomyTier) < autonomyTierRank(rightProjection.AutonomyTier)
	}
	if delegationReadinessRank(leftProjection.DelegationReadinessState) != delegationReadinessRank(rightProjection.DelegationReadinessState) {
		return delegationReadinessRank(leftProjection.DelegationReadinessState) < delegationReadinessRank(rightProjection.DelegationReadinessState)
	}
	if highStakesPresetScore(leftProjection) != highStakesPresetScore(rightProjection) {
		return highStakesPresetScore(leftProjection) > highStakesPresetScore(rightProjection)
	}
	if agenticDeliverySystemChangeRank(leftProjection.AgenticDeliverySystemChange) != agenticDeliverySystemChangeRank(rightProjection.AgenticDeliverySystemChange) {
		return agenticDeliverySystemChangeRank(leftProjection.AgenticDeliverySystemChange) > agenticDeliverySystemChangeRank(rightProjection.AgenticDeliverySystemChange)
	}
	if leftModel.riskTierRank != rightModel.riskTierRank {
		return leftModel.riskTierRank < rightModel.riskTierRank
	}
	if targetClassRank(leftProjection.TargetClass) != targetClassRank(rightProjection.TargetClass) {
		return targetClassRank(leftProjection.TargetClass) < targetClassRank(rightProjection.TargetClass)
	}
	if actionPathTypeRank(leftProjection.ActionPathType) != actionPathTypeRank(rightProjection.ActionPathType) {
		return actionPathTypeRank(leftProjection.ActionPathType) < actionPathTypeRank(rightProjection.ActionPathType)
	}
	if confidenceLaneRank(leftProjection.ConfidenceLane) != confidenceLaneRank(rightProjection.ConfidenceLane) {
		return confidenceLaneRank(leftProjection.ConfidenceLane) < confidenceLaneRank(rightProjection.ConfidenceLane)
	}
	if reviewBurdenRank(leftProjection.ReviewBurden) != reviewBurdenRank(rightProjection.ReviewBurden) {
		return reviewBurdenRank(leftProjection.ReviewBurden) < reviewBurdenRank(rightProjection.ReviewBurden)
	}
	if leftModel.sourceSignalRank != rightModel.sourceSignalRank {
		return leftModel.sourceSignalRank > rightModel.sourceSignalRank
	}
	if leftModel.governableScore != rightModel.governableScore {
		return leftModel.governableScore > rightModel.governableScore
	}
	if left.AttackPathScore != right.AttackPathScore {
		return left.AttackPathScore > right.AttackPathScore
	}
	if left.RiskScore != right.RiskScore {
		return left.RiskScore > right.RiskScore
	}
	if left.Repo != right.Repo {
		return left.Repo < right.Repo
	}
	if left.Location != right.Location {
		return left.Location < right.Location
	}
	if sourceFindingKeyOrder(left.SourceFindingKeys) != sourceFindingKeyOrder(right.SourceFindingKeys) {
		return sourceFindingKeyOrder(left.SourceFindingKeys) < sourceFindingKeyOrder(right.SourceFindingKeys)
	}
	return left.PathID < right.PathID
}

func LinkAttackPaths(paths []ActionPath, attackPaths []riskattack.ScoredPath) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]ActionPath(nil), paths...)
	matchesByIndex := map[int][]riskattack.ScoredPath{}
	for _, attackPath := range attackPaths {
		matchIndexes := matchActionPathIndexes(out, attackPath)
		for _, idx := range matchIndexes {
			matchesByIndex[idx] = append(matchesByIndex[idx], attackPath)
		}
	}
	for idx := range out {
		matches := matchesByIndex[idx]
		if len(matches) == 0 {
			continue
		}
		attackPathRefs := make([]string, 0, len(matches))
		sourceFindingKeys := append([]string(nil), out[idx].SourceFindingKeys...)
		for _, match := range matches {
			attackPathRefs = append(attackPathRefs, strings.TrimSpace(match.PathID))
			sourceFindingKeys = append(sourceFindingKeys, match.SourceFindings...)
		}
		out[idx].AttackPathRefs = dedupeSortedStrings(append(out[idx].AttackPathRefs, attackPathRefs...))
		out[idx].SourceFindingKeys = dedupeSortedStrings(sourceFindingKeys)
	}
	return out
}

func applyLinkedAttackPathScores(paths []ActionPath, attackPaths []riskattack.ScoredPath) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	scoreByRef := map[string]float64{}
	for _, attackPath := range attackPaths {
		ref := strings.TrimSpace(attackPath.PathID)
		if ref == "" {
			continue
		}
		if attackPath.PathScore > scoreByRef[ref] {
			scoreByRef[ref] = attackPath.PathScore
		}
	}
	out := append([]ActionPath(nil), paths...)
	for idx := range out {
		best := 0.0
		for _, ref := range out[idx].AttackPathRefs {
			if scoreByRef[strings.TrimSpace(ref)] > best {
				best = scoreByRef[strings.TrimSpace(ref)]
			}
		}
		out[idx].AttackPathScore = best
	}
	return out
}

func matchActionPathIndexes(paths []ActionPath, attackPath riskattack.ScoredPath) []int {
	indexes := map[int]struct{}{}
	for _, key := range attackPath.SourceFindings {
		org, repo, location := parseAttackPathFindingKey(key)
		if repo == "" || location == "" {
			continue
		}
		for idx := range paths {
			if strings.TrimSpace(paths[idx].Repo) != repo {
				continue
			}
			if strings.TrimSpace(paths[idx].Location) != location {
				continue
			}
			if org != "" && strings.TrimSpace(paths[idx].Org) != "" && strings.TrimSpace(paths[idx].Org) != org {
				continue
			}
			indexes[idx] = struct{}{}
		}
	}
	out := make([]int, 0, len(indexes))
	for idx := range indexes {
		out = append(out, idx)
	}
	sort.Ints(out)
	return out
}

func parseAttackPathFindingKey(key string) (string, string, string) {
	parts := strings.Split(strings.TrimSpace(key), "|")
	if len(parts) < 6 {
		return "", "", ""
	}
	location := strings.TrimSpace(parts[3])
	repo := strings.TrimSpace(parts[len(parts)-2])
	org := strings.TrimSpace(parts[len(parts)-1])
	return org, repo, location
}

func sourceSignalRank(path ActionPath) int {
	switch {
	case actionPathDependencyOnly(path):
		return 0
	case strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "mcp"):
		return 4
	case strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "langchain"),
		strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "langgraph"),
		strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "crewai"),
		strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "autogen"),
		strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "llamaindex"),
		strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "compiled_action"),
		strings.Contains(strings.ToLower(strings.TrimSpace(path.ToolType)), "ci_agent"):
		return 3
	case pathHasAnyMutableEndpoint(path):
		return 3
	case len(path.ActionClasses) > 0 || len(path.ActionReasons) > 0:
		return 2
	default:
		return 1
	}
}

func actionPathDependencyOnly(path ActionPath) bool {
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	location := strings.ToLower(strings.TrimSpace(path.Location))
	switch {
	case strings.Contains(toolType, "dependency"):
		return true
	case location == "package.json",
		location == "package-lock.json",
		location == "pnpm-lock.yaml",
		location == "yarn.lock",
		location == "requirements.txt",
		location == "poetry.lock",
		location == "pyproject.toml",
		location == "go.mod",
		location == "cargo.toml":
		return true
	default:
		return false
	}
}

func actionPathHasStrongIdentity(path ActionPath) bool {
	status := strings.TrimSpace(path.ExecutionIdentityStatus)
	return status != "" && status != "unknown" && status != "ambiguous"
}

func actionPathHasStrongOwnership(path ActionPath) bool {
	return !actionPathHasWeakOwnership(path)
}

func actionPathUnknownToSecurity(path ActionPath) bool {
	return strings.TrimSpace(path.SecurityVisibilityStatus) == "unknown_to_security"
}

func sourceFindingKeyOrder(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	copyKeys := append([]string(nil), keys...)
	sort.Strings(copyKeys)
	return strings.Join(copyKeys, ",")
}

func RemediationForActionPath(path ActionPath) string {
	path = ProjectActionPath(path)
	if pathLikelyNeedsCorrelation(path) {
		switch {
		case IsInstructionControlSurface(path):
			return "Correlate this instruction surface to the workflow, agent runtime, MCP/tool path, or recent change that actually consumes it, then attach owner and review evidence before treating it as governable."
		case actionPathDependencyOnly(path):
			return "Keep this dependency-only signal in context until executable, runtime, or control evidence proves it governs a real path."
		default:
			return "Correlate this target surface to a real workflow, credential use, MCP/tool binding, deploy path, runtime caller, or recent change before promoting it into a governable action path."
		}
	}
	if actionPathHasContradictoryControlEvidence(path) {
		return "Control evidence is contradictory for this path; resolve the conflicting control or evidence signals, keep it in fail-closed review, and rerun the scan before treating it as governed."
	}
	if actionPathHasWeakOwnership(path) {
		switch normalizeEvidenceState(path.OwnerEvidenceState) {
		case EvidenceStateContradictory:
			return "Owner evidence is contradictory for this path; resolve the conflict, record one explicit owner, and rerun the scan before approving or expanding it."
		default:
			return "Owner evidence is unknown for this path; assign an explicit owner, attach linked ownership evidence, and rerun the scan before approving or expanding it."
		}
	}
	if path.ControlPriority == ControlPriorityInventoryHygiene || deriveGovernFirstModel(path).controlPriority == ControlPriorityInventoryHygiene {
		if actionPathDependencyOnly(path) {
			return "Confirm whether this dependency-only AI package is active agent code; if not, suppress it as accepted inventory, otherwise add source-level binding evidence."
		}
		return "Review this low-governance path for production relevance and either suppress it as accepted inventory or add stronger binding evidence."
	}
	if path.CredentialAccess && path.CredentialAuthority != nil && path.CredentialAuthority.StandingAccess {
		switch strings.TrimSpace(path.CredentialAuthority.RotationEvidenceStatus) {
		case agginventory.CredentialRotationEvidenceStale:
			return "Rotate the stale standing credential, convert it to brokered or JIT access where possible, attach fresh rotation evidence, and rescan."
		case agginventory.CredentialRotationEvidenceMissing, agginventory.CredentialRotationEvidenceUnknown:
			return "Replace the standing credential with brokered or JIT access where possible, attach rotation evidence, and rescan to confirm the reduced blast radius."
		}
	}
	if path.CredentialAccess && path.CredentialProvenance != nil && path.CredentialProvenance.StandingAccess {
		return "Replace the standing credential with brokered or JIT access where possible, attach rotation evidence, and rescan to confirm the reduced blast radius."
	}
	if pathHasHighImpactMutableEndpoint(path) {
		return "Review the declared mutable endpoint scope, require owner approval and proof for the exact action path, tighten token scope where possible, and rescan before treating this mutation surface as governed."
	}
	if pathHasSensitiveDataEndpoint(path) {
		return "Confirm the owner and policy binding for this sensitive data or account-management surface, attach proof for the exact path, and rescan after the control is in place."
	}
	if path.ProductionWrite || path.DeployWrite || strings.TrimSpace(path.WorkflowTriggerClass) == "deploy_pipeline" {
		return "Add or verify deployment gates, tighten write scope, attach path-specific proof, and rescan until this deploy-capable path drops out of the control-first queue."
	}
	if path.PullRequestWrite || path.MergeExecute {
		return "Require CODEOWNERS or equivalent merge approval on this write path, attach the approval and proof reference, and rescan."
	}
	if path.ApprovalGap && actionPathHasStrongIdentity(path) && actionPathHasStrongOwnership(path) && !actionPathUnknownToSecurity(path) {
		return "Record a time-bounded owner approval with scope and expiry, link the proof to this path, and rescan."
	}
	if strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone || len(path.PolicyMissingReasons) > 0 {
		return "Attach the missing policy or proof reference for this exact path and rescan so governance coverage is no longer inferred from the global chain."
	}
	if path.CredentialAccess {
		return "Classify the credential authority on this path, attach proof for scope and ownership, and confirm whether standing access can be reduced."
	}
	return "Add the missing identity, ownership, or control proof for this path and rescan before treating it as approved inventory."
}
