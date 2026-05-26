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
