package risk

import "strings"

const (
	GaitStatusPresent       = "present"
	GaitStatusMissing       = "missing"
	GaitStatusStale         = "stale"
	GaitStatusConflict      = "conflict"
	GaitStatusNotApplicable = "not_applicable"
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
