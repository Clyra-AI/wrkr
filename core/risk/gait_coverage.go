package risk

import "strings"

const (
	GaitStatusPresent       = "present"
	GaitStatusMissing       = "missing"
	GaitStatusStale         = "stale"
	GaitStatusConflict      = "conflict"
	GaitStatusNotApplicable = "not_applicable"

	RuntimeEvidenceAbsenceNotCollected    = "not_collected"
	RuntimeEvidenceAbsenceNotApplicable   = "not_applicable"
	RuntimeEvidenceAbsenceMissingRequired = "missing_required"
	RuntimeEvidenceAbsenceMissingForClaim = "missing_for_control_claim"
)

type GaitCoverageDetail struct {
	Status       string   `json:"status"`
	Reasons      []string `json:"reasons,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type GaitCoverage struct {
	PolicyDecision    GaitCoverageDetail `json:"policy_decision"`
	Approval          GaitCoverageDetail `json:"approval"`
	JITCredential     GaitCoverageDetail `json:"jit_credential"`
	FreezeWindow      GaitCoverageDetail `json:"freeze_window"`
	KillSwitch        GaitCoverageDetail `json:"kill_switch"`
	ActionOutcome     GaitCoverageDetail `json:"action_outcome"`
	ProofVerification GaitCoverageDetail `json:"proof_verification"`
}

func MergeGaitCoverage(current, incoming *GaitCoverage) *GaitCoverage {
	switch {
	case current == nil:
		return CloneGaitCoverage(incoming)
	case incoming == nil:
		return CloneGaitCoverage(current)
	}
	return &GaitCoverage{
		PolicyDecision:    mergeGaitCoverageDetail(current.PolicyDecision, incoming.PolicyDecision),
		Approval:          mergeGaitCoverageDetail(current.Approval, incoming.Approval),
		JITCredential:     mergeGaitCoverageDetail(current.JITCredential, incoming.JITCredential),
		FreezeWindow:      mergeGaitCoverageDetail(current.FreezeWindow, incoming.FreezeWindow),
		KillSwitch:        mergeGaitCoverageDetail(current.KillSwitch, incoming.KillSwitch),
		ActionOutcome:     mergeGaitCoverageDetail(current.ActionOutcome, incoming.ActionOutcome),
		ProofVerification: mergeGaitCoverageDetail(current.ProofVerification, incoming.ProofVerification),
	}
}

func ValidRuntimeEvidenceAbsenceStatus(value string) bool {
	switch strings.TrimSpace(value) {
	case RuntimeEvidenceAbsenceNotCollected,
		RuntimeEvidenceAbsenceNotApplicable,
		RuntimeEvidenceAbsenceMissingRequired,
		RuntimeEvidenceAbsenceMissingForClaim:
		return true
	default:
		return false
	}
}

func CloneGaitCoverage(in *GaitCoverage) *GaitCoverage {
	if in == nil {
		return nil
	}
	return &GaitCoverage{
		PolicyDecision:    cloneGaitCoverageDetail(in.PolicyDecision),
		Approval:          cloneGaitCoverageDetail(in.Approval),
		JITCredential:     cloneGaitCoverageDetail(in.JITCredential),
		FreezeWindow:      cloneGaitCoverageDetail(in.FreezeWindow),
		KillSwitch:        cloneGaitCoverageDetail(in.KillSwitch),
		ActionOutcome:     cloneGaitCoverageDetail(in.ActionOutcome),
		ProofVerification: cloneGaitCoverageDetail(in.ProofVerification),
	}
}

func cloneGaitCoverageDetail(in GaitCoverageDetail) GaitCoverageDetail {
	return GaitCoverageDetail{
		Status:       strings.TrimSpace(in.Status),
		Reasons:      dedupeSortedStrings(append([]string(nil), in.Reasons...)),
		EvidenceRefs: dedupeSortedStrings(append([]string(nil), in.EvidenceRefs...)),
	}
}

func mergeGaitCoverageDetail(current, incoming GaitCoverageDetail) GaitCoverageDetail {
	status := strings.TrimSpace(current.Status)
	if gaitStatusRank(strings.TrimSpace(incoming.Status)) < gaitStatusRank(status) {
		status = strings.TrimSpace(incoming.Status)
	}
	return GaitCoverageDetail{
		Status:       firstNonEmptyString(status, strings.TrimSpace(incoming.Status)),
		Reasons:      dedupeSortedStrings(append(append([]string(nil), current.Reasons...), incoming.Reasons...)),
		EvidenceRefs: dedupeSortedStrings(append(append([]string(nil), current.EvidenceRefs...), incoming.EvidenceRefs...)),
	}
}

func gaitStatusRank(value string) int {
	switch strings.TrimSpace(value) {
	case GaitStatusConflict:
		return 0
	case GaitStatusStale:
		return 1
	case GaitStatusMissing:
		return 2
	case GaitStatusPresent:
		return 3
	case GaitStatusNotApplicable:
		return 4
	default:
		return 5
	}
}

func RuntimeEvidenceAbsenceStatus(path ActionPath) string {
	if path.GaitCoverage == nil {
		return ""
	}
	status := ""
	allNotApplicable := true
	for _, detail := range []GaitCoverageDetail{
		path.GaitCoverage.PolicyDecision,
		path.GaitCoverage.Approval,
		path.GaitCoverage.JITCredential,
		path.GaitCoverage.FreezeWindow,
		path.GaitCoverage.KillSwitch,
		path.GaitCoverage.ActionOutcome,
		path.GaitCoverage.ProofVerification,
	} {
		if strings.TrimSpace(detail.Status) != GaitStatusNotApplicable {
			allNotApplicable = false
		}
		for _, reason := range detail.Reasons {
			const prefix = "runtime_absence_status:"
			if !strings.HasPrefix(strings.TrimSpace(reason), prefix) {
				continue
			}
			candidate := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reason), prefix))
			if !ValidRuntimeEvidenceAbsenceStatus(candidate) {
				continue
			}
			if status == "" || runtimeEvidenceAbsenceRank(candidate) < runtimeEvidenceAbsenceRank(status) {
				status = candidate
			}
		}
	}
	if status != "" {
		return status
	}
	if allNotApplicable {
		return RuntimeEvidenceAbsenceNotApplicable
	}
	return ""
}

func GaitCoverageHasStatus(coverage *GaitCoverage, want string) bool {
	if coverage == nil {
		return false
	}
	for _, detail := range []GaitCoverageDetail{
		coverage.PolicyDecision,
		coverage.Approval,
		coverage.JITCredential,
		coverage.FreezeWindow,
		coverage.KillSwitch,
		coverage.ActionOutcome,
		coverage.ProofVerification,
	} {
		if strings.TrimSpace(detail.Status) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func runtimeEvidenceAbsenceRank(value string) int {
	switch strings.TrimSpace(value) {
	case RuntimeEvidenceAbsenceMissingForClaim:
		return 0
	case RuntimeEvidenceAbsenceMissingRequired:
		return 1
	case RuntimeEvidenceAbsenceNotCollected:
		return 2
	case RuntimeEvidenceAbsenceNotApplicable:
		return 3
	default:
		return 4
	}
}
