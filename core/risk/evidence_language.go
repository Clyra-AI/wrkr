package risk

import "strings"

func BuyerControlResolutionLabel(state string) string {
	switch normalizeControlResolutionState(state) {
	case ControlResolutionStateDetectedControl:
		return "visible control evidence detected"
	case ControlResolutionStateDeclaredControl:
		return "control declared in provided metadata"
	case ControlResolutionStateExternalControlReference:
		return "external control reference declared"
	case ControlResolutionStateContradictoryControl:
		return "control evidence is contradictory"
	case ControlResolutionStateNotApplicable:
		return "control evidence not applicable"
	default:
		return "no visible control evidence found"
	}
}

func BuyerEvidenceStateLabel(kind, state string) string {
	switch strings.TrimSpace(kind) {
	case "approval":
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified:
			return "approval evidence verified"
		case EvidenceStateDeclared:
			return "approval evidence declared"
		case EvidenceStateInferred:
			return "approval evidence inferred"
		case EvidenceStateContradictory:
			return "approval evidence is contradictory"
		default:
			return "approval evidence not found"
		}
	case "owner":
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified:
			return "owner evidence verified"
		case EvidenceStateDeclared:
			return "owner evidence declared"
		case EvidenceStateInferred:
			return "owner evidence inferred"
		case EvidenceStateContradictory:
			return "owner evidence is contradictory"
		default:
			return "owner evidence is unknown"
		}
	case "proof":
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified:
			return "path-specific proof verified"
		case EvidenceStateDeclared:
			return "path-specific proof declared"
		case EvidenceStateInferred:
			return "path-specific proof inferred"
		case EvidenceStateContradictory:
			return "path-specific proof is contradictory"
		default:
			return "path-specific proof not found"
		}
	case "runtime":
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified:
			return "runtime evidence verified"
		case EvidenceStateDeclared:
			return "runtime evidence declared"
		case EvidenceStateInferred:
			return "runtime evidence inferred"
		case EvidenceStateContradictory:
			return "runtime evidence is contradictory"
		default:
			return "runtime evidence not collected"
		}
	case "target":
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified:
			return "target evidence verified"
		case EvidenceStateDeclared:
			return "target evidence declared"
		case EvidenceStateInferred:
			return "target evidence inferred"
		case EvidenceStateContradictory:
			return "target evidence is contradictory"
		default:
			return "target evidence unknown"
		}
	case "credential":
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified:
			return "credential evidence verified"
		case EvidenceStateDeclared:
			return "credential evidence declared"
		case EvidenceStateInferred:
			return "credential evidence inferred"
		case EvidenceStateContradictory:
			return "credential evidence is contradictory"
		default:
			return "credential evidence unknown"
		}
	default:
		return "evidence state unknown"
	}
}

func BuyerRuntimeEvidenceLabel(state string, absenceStatus string, coverage *GaitCoverage) string {
	switch {
	case GaitCoverageHasStatus(coverage, GaitStatusConflict), normalizeEvidenceState(state) == EvidenceStateContradictory:
		return "runtime evidence is contradictory"
	case GaitCoverageHasStatus(coverage, GaitStatusStale):
		return "runtime evidence is stale"
	}

	switch strings.TrimSpace(absenceStatus) {
	case RuntimeEvidenceAbsenceNotApplicable:
		return "runtime evidence not applicable"
	case RuntimeEvidenceAbsenceMissingRequired:
		return "runtime evidence required but not linked"
	case RuntimeEvidenceAbsenceMissingForClaim:
		return "runtime evidence missing for a control claim"
	case RuntimeEvidenceAbsenceNotCollected:
		return "runtime evidence not collected"
	default:
		return BuyerEvidenceStateLabel("runtime", state)
	}
}

func BuyerEvidenceCompletenessLabel(completeness *EvidenceCompleteness) string {
	if completeness == nil {
		return "evidence completeness unavailable"
	}
	switch strings.TrimSpace(completeness.Label) {
	case EvidenceCompletenessStrong:
		return "strong evidence coverage"
	case EvidenceCompletenessPartial:
		return "partial evidence coverage"
	default:
		return "insufficient evidence coverage"
	}
}

func BuyerEvidenceCompletenessSummaryLabel(summary *EvidenceCompletenessSummary) string {
	if summary == nil {
		return "aggregate evidence completeness unavailable"
	}
	switch strings.TrimSpace(summary.Label) {
	case EvidenceCompletenessStrong:
		return "aggregate evidence coverage is strong"
	case EvidenceCompletenessPartial:
		return "aggregate evidence coverage is partial"
	default:
		return "aggregate evidence coverage is insufficient"
	}
}

func BuyerAutonomyTierLabel(tier string) string {
	switch strings.TrimSpace(tier) {
	case AutonomyTier0SafeMetadata:
		return "safe metadata only"
	case AutonomyTier1LowRiskInternal:
		return "low-risk internal changes"
	case AutonomyTier2AppCodeOwnerReview:
		return "app code that needs owner review"
	case AutonomyTier3SensitiveCodeOrInfra:
		return "sensitive code or infrastructure"
	case AutonomyTier4ProdPrivilegedCustomerImpact:
		return "production, privileged, or customer-impacting"
	default:
		return "autonomy tier unknown"
	}
}

func BuyerAutonomyTierShortLabel(tier string) string {
	switch strings.TrimSpace(tier) {
	case AutonomyTier0SafeMetadata:
		return "safe metadata"
	case AutonomyTier1LowRiskInternal:
		return "low-risk internal"
	case AutonomyTier2AppCodeOwnerReview:
		return "owner-review app code"
	case AutonomyTier3SensitiveCodeOrInfra:
		return "sensitive code or infra"
	case AutonomyTier4ProdPrivilegedCustomerImpact:
		return "prod or customer impacting"
	default:
		return "unknown tier"
	}
}

func BuyerDelegationReadinessLabel(state string) string {
	switch strings.TrimSpace(state) {
	case DelegationReadinessSafeToDelegate:
		return "safe to delegate"
	case DelegationReadinessReviewRequired:
		return "review required"
	case DelegationReadinessApprovalRequired:
		return "approval required"
	case DelegationReadinessProofRequired:
		return "proof required"
	case DelegationReadinessReadyForControl:
		return "ready for control"
	case DelegationReadinessBlocked:
		return "blocked"
	case DelegationReadinessBlockedByContradiction:
		return "blocked by contradiction"
	default:
		return "delegation readiness unknown"
	}
}

func BuyerRecommendedControlLabel(value string) string {
	switch strings.TrimSpace(value) {
	case RecommendedControlAllow:
		return "allow"
	case RecommendedControlOwnerReview:
		return "owner review"
	case RecommendedControlSecurityReview:
		return "security review"
	case RecommendedControlApprovalRequired:
		return "approval required"
	case RecommendedControlJITCredentialRequired:
		return "JIT credential required"
	case RecommendedControlProofRequired:
		return "proof required"
	case RecommendedControlBlockStandingCredential:
		return "block standing credential"
	case RecommendedControlBlock:
		return "block"
	default:
		return "control recommendation unknown"
	}
}

func BuyerActionContractReadinessLabel(value string) string {
	switch strings.TrimSpace(value) {
	case ActionContractReadinessBlocked:
		return "blocked"
	case ActionContractReadinessNeedsOwner:
		return "needs owner evidence"
	case ActionContractReadinessNeedsApproval:
		return "needs approval evidence"
	case ActionContractReadinessNeedsProof:
		return "needs proof evidence"
	case ActionContractReadinessNeedsCorrelation:
		return "needs correlation evidence"
	case ActionContractReadinessReadyForReportOnly:
		return "ready for report only"
	case ActionContractReadinessReadyForControl:
		return "ready for control"
	case ActionContractReadinessBlockedContradict:
		return "blocked by contradiction"
	default:
		return "draft contract"
	}
}
