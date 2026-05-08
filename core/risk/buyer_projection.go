package risk

import "strings"

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
)

func ProjectBuyerFacingActionPath(path ActionPath) ActionPath {
	out := path
	out.ControlState, out.ControlStateReasons = deriveControlState(path)
	out.RiskZone, out.RiskZoneReasons = deriveRiskZone(path)
	out.ReviewBurden, out.ReviewBurdenReasons = deriveReviewBurden(out)
	return out
}

func deriveControlState(path ActionPath) (string, []string) {
	reasons := []string{}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}

	highBlastRadius := path.ProductionWrite ||
		path.DeployWrite ||
		path.MergeExecute ||
		containsPathValue(path.ActionClasses, "deploy") ||
		containsPathValue(path.ActionClasses, "delete") ||
		containsPathValue(path.ActionClasses, "execute")
	controlledPath := highBlastRadius ||
		path.WriteCapable ||
		path.PullRequestWrite ||
		path.CredentialAccess ||
		len(path.MatchedProductionTargets) > 0
	missingPolicyOrProof := strings.TrimSpace(path.PolicyCoverageStatus) == "" ||
		strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone ||
		strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusStale ||
		strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusConflict ||
		len(path.PolicyMissingReasons) > 0 ||
		path.GaitCoverage == nil ||
		strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) == GaitStatusMissing ||
		strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) == GaitStatusConflict ||
		strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) == GaitStatusStale

	switch {
	case path.ControlPriority == ControlPriorityInventoryHygiene &&
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
		if path.GaitCoverage == nil || strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) == GaitStatusMissing {
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
	if path.ApprovalGap {
		add("approval_gap:true", 2)
	}
	if strings.TrimSpace(path.OwnershipStatus) == "" || strings.TrimSpace(path.OwnershipStatus) == "unresolved" || strings.TrimSpace(path.OwnershipState) == "missing" || strings.TrimSpace(path.OwnershipState) == "conflicting" {
		add("ownership_gap:true", 2)
	}
	if len(path.PolicyMissingReasons) > 0 || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusStale || strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusConflict {
		add("policy_gap:true", 2)
	}
	if path.GaitCoverage == nil || strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) == GaitStatusMissing {
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
