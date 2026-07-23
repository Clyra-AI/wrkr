package risk

import "strings"

const (
	GaitStatusPresent       = "present"
	GaitStatusMissing       = "missing"
	GaitStatusStale         = "stale"
	GaitStatusConflict      = "conflict"
	GaitStatusNotApplicable = "not_applicable"

	ContainmentCoverageContained     = "contained"
	ContainmentCoveragePartial       = "partially_contained"
	ContainmentCoverageUnresolved    = "unresolved"
	ContainmentCoverageOutOfScope    = "out_of_scope"
	ContainmentCoverageNotObserved   = "not_observed"
	ContainmentCoverageNotApplicable = "not_applicable"
	ContainmentCoverageStale         = "stale"
	ContainmentCoverageConflict      = "conflict"

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
	PolicyDecision    GaitCoverageDetail   `json:"policy_decision"`
	Approval          GaitCoverageDetail   `json:"approval"`
	JITCredential     GaitCoverageDetail   `json:"jit_credential"`
	FreezeWindow      GaitCoverageDetail   `json:"freeze_window"`
	KillSwitch        GaitCoverageDetail   `json:"kill_switch"`
	ActionOutcome     GaitCoverageDetail   `json:"action_outcome"`
	ProofVerification GaitCoverageDetail   `json:"proof_verification"`
	Containment       *ContainmentCoverage `json:"containment,omitempty"`
}

type ContainmentCoverage struct {
	Status                            string             `json:"status"`
	StopRequest                       GaitCoverageDetail `json:"stop_request"`
	CoveredActionDenial               GaitCoverageDetail `json:"covered_action_denial"`
	CapabilityInvalidation            GaitCoverageDetail `json:"capability_invalidation"`
	DescendantInvalidation            GaitCoverageDetail `json:"descendant_invalidation"`
	ExternalRevocationAttempt         GaitCoverageDetail `json:"external_revocation_attempt"`
	ExternalRevocationAcknowledgement GaitCoverageDetail `json:"external_revocation_acknowledgement"`
	ContainmentReceipt                GaitCoverageDetail `json:"containment_receipt"`
	ScopeRefs                         []string           `json:"scope_refs,omitempty"`
	AcknowledgedBoundaryRefs          []string           `json:"acknowledged_boundary_refs,omitempty"`
	UnresolvedBoundaryRefs            []string           `json:"unresolved_boundary_refs,omitempty"`
	OutOfScopeBoundaryRefs            []string           `json:"out_of_scope_boundary_refs,omitempty"`
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
		Containment:       mergeContainmentCoverage(current.Containment, incoming.Containment),
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
		Containment:       cloneContainmentCoverage(in.Containment),
	}
}

func cloneContainmentCoverage(in *ContainmentCoverage) *ContainmentCoverage {
	if in == nil {
		return nil
	}
	return &ContainmentCoverage{
		Status:                            strings.TrimSpace(in.Status),
		StopRequest:                       cloneGaitCoverageDetail(in.StopRequest),
		CoveredActionDenial:               cloneGaitCoverageDetail(in.CoveredActionDenial),
		CapabilityInvalidation:            cloneGaitCoverageDetail(in.CapabilityInvalidation),
		DescendantInvalidation:            cloneGaitCoverageDetail(in.DescendantInvalidation),
		ExternalRevocationAttempt:         cloneGaitCoverageDetail(in.ExternalRevocationAttempt),
		ExternalRevocationAcknowledgement: cloneGaitCoverageDetail(in.ExternalRevocationAcknowledgement),
		ContainmentReceipt:                cloneGaitCoverageDetail(in.ContainmentReceipt),
		ScopeRefs:                         dedupeSortedStrings(append([]string(nil), in.ScopeRefs...)),
		AcknowledgedBoundaryRefs:          dedupeSortedStrings(append([]string(nil), in.AcknowledgedBoundaryRefs...)),
		UnresolvedBoundaryRefs:            dedupeSortedStrings(append([]string(nil), in.UnresolvedBoundaryRefs...)),
		OutOfScopeBoundaryRefs:            dedupeSortedStrings(append([]string(nil), in.OutOfScopeBoundaryRefs...)),
	}
}

func mergeContainmentCoverage(current, incoming *ContainmentCoverage) *ContainmentCoverage {
	switch {
	case current == nil:
		return cloneContainmentCoverage(incoming)
	case incoming == nil:
		return cloneContainmentCoverage(current)
	}
	status := strings.TrimSpace(current.Status)
	if containmentCoverageStatusRank(incoming.Status) < containmentCoverageStatusRank(status) {
		status = strings.TrimSpace(incoming.Status)
	}
	return &ContainmentCoverage{
		Status:                            firstNonEmptyString(status, strings.TrimSpace(incoming.Status)),
		StopRequest:                       mergeGaitCoverageDetail(current.StopRequest, incoming.StopRequest),
		CoveredActionDenial:               mergeGaitCoverageDetail(current.CoveredActionDenial, incoming.CoveredActionDenial),
		CapabilityInvalidation:            mergeGaitCoverageDetail(current.CapabilityInvalidation, incoming.CapabilityInvalidation),
		DescendantInvalidation:            mergeGaitCoverageDetail(current.DescendantInvalidation, incoming.DescendantInvalidation),
		ExternalRevocationAttempt:         mergeGaitCoverageDetail(current.ExternalRevocationAttempt, incoming.ExternalRevocationAttempt),
		ExternalRevocationAcknowledgement: mergeGaitCoverageDetail(current.ExternalRevocationAcknowledgement, incoming.ExternalRevocationAcknowledgement),
		ContainmentReceipt:                mergeGaitCoverageDetail(current.ContainmentReceipt, incoming.ContainmentReceipt),
		ScopeRefs:                         dedupeSortedStrings(append(append([]string(nil), current.ScopeRefs...), incoming.ScopeRefs...)),
		AcknowledgedBoundaryRefs:          dedupeSortedStrings(append(append([]string(nil), current.AcknowledgedBoundaryRefs...), incoming.AcknowledgedBoundaryRefs...)),
		UnresolvedBoundaryRefs:            dedupeSortedStrings(append(append([]string(nil), current.UnresolvedBoundaryRefs...), incoming.UnresolvedBoundaryRefs...)),
		OutOfScopeBoundaryRefs:            dedupeSortedStrings(append(append([]string(nil), current.OutOfScopeBoundaryRefs...), incoming.OutOfScopeBoundaryRefs...)),
	}
}

func containmentCoverageStatusRank(value string) int {
	switch strings.TrimSpace(value) {
	case ContainmentCoverageConflict:
		return 0
	case ContainmentCoverageUnresolved:
		return 1
	case ContainmentCoverageOutOfScope:
		return 2
	case ContainmentCoverageStale:
		return 3
	case ContainmentCoverageNotObserved:
		return 4
	case ContainmentCoveragePartial:
		return 5
	case ContainmentCoverageContained:
		return 6
	case ContainmentCoverageNotApplicable:
		return 7
	default:
		return 8
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
	for _, detail := range gaitCoverageDetails(path.GaitCoverage) {
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
			if candidate == RuntimeEvidenceAbsenceNotApplicable {
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
	for _, detail := range gaitCoverageDetails(coverage) {
		if strings.TrimSpace(detail.Status) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func gaitCoverageDetails(coverage *GaitCoverage) []GaitCoverageDetail {
	if coverage == nil {
		return nil
	}
	return []GaitCoverageDetail{
		coverage.PolicyDecision,
		coverage.Approval,
		coverage.JITCredential,
		coverage.FreezeWindow,
		coverage.KillSwitch,
		coverage.ActionOutcome,
		coverage.ProofVerification,
	}
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
