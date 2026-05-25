package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func gaitCoverageForPath(path risk.ActionPath, runtime ingest.Correlation) *risk.GaitCoverage {
	return &risk.GaitCoverage{
		PolicyDecision:    gaitCoverageDetail(path, appliesPolicyDecision(path), runtime, ingest.EvidenceClassPolicyDecision, "policy_decision"),
		Approval:          gaitCoverageDetail(path, appliesApprovalCoverage(path), runtime, ingest.EvidenceClassApproval, "approval"),
		JITCredential:     gaitCoverageDetail(path, appliesJITCredentialCoverage(path), runtime, ingest.EvidenceClassJITCredential, "jit_credential"),
		FreezeWindow:      gaitCoverageDetail(path, appliesFreezeWindowCoverage(path), runtime, ingest.EvidenceClassFreezeWindow, "freeze_window"),
		KillSwitch:        gaitCoverageDetail(path, appliesKillSwitchCoverage(path), runtime, ingest.EvidenceClassKillSwitch, "kill_switch"),
		ActionOutcome:     gaitCoverageDetail(path, appliesActionOutcomeCoverage(path), runtime, ingest.EvidenceClassActionOutcome, "action_outcome"),
		ProofVerification: gaitCoverageDetail(path, appliesProofVerificationCoverage(path), runtime, ingest.EvidenceClassProofVerify, "proof_verification"),
	}
}

func gaitCoverageDetail(path risk.ActionPath, applicable bool, runtime ingest.Correlation, evidenceClass string, reasonKey string) risk.GaitCoverageDetail {
	if !applicable {
		return risk.GaitCoverageDetail{
			Status: risk.GaitStatusNotApplicable,
			Reasons: []string{
				"not_applicable:" + reasonKey,
				"runtime_absence_status:" + risk.RuntimeEvidenceAbsenceNotApplicable,
			},
		}
	}
	if strings.TrimSpace(runtime.Status) == ingest.CorrelationStatusConflict {
		return risk.GaitCoverageDetail{
			Status:       risk.GaitStatusConflict,
			Reasons:      []string{"runtime_evidence_conflict:" + reasonKey},
			EvidenceRefs: append([]string(nil), runtime.RecordIDs...),
		}
	}
	if strings.TrimSpace(runtime.Status) == ingest.CorrelationStatusStale {
		return risk.GaitCoverageDetail{
			Status:       risk.GaitStatusStale,
			Reasons:      []string{"runtime_evidence_stale:" + reasonKey},
			EvidenceRefs: append([]string(nil), runtime.RecordIDs...),
		}
	}
	if status, refs, ok := constraintCoverageDetail(path, evidenceClass, reasonKey); ok {
		return risk.GaitCoverageDetail{
			Status:       status,
			Reasons:      []string{"constraint_evidence_present:" + reasonKey},
			EvidenceRefs: refs,
		}
	}
	if containsEvidenceClass(runtime.EvidenceClasses, evidenceClass) {
		return risk.GaitCoverageDetail{
			Status:       risk.GaitStatusPresent,
			Reasons:      []string{"runtime_evidence_present:" + reasonKey},
			EvidenceRefs: append([]string(nil), runtime.RecordIDs...),
		}
	}
	if strings.TrimSpace(runtime.Status) == ingest.CorrelationStatusMatched {
		absenceStatus := risk.RuntimeEvidenceAbsenceMissingRequired
		reason := "runtime_class_missing:" + reasonKey
		if runtimeControlClaimMissing(path) {
			absenceStatus = risk.RuntimeEvidenceAbsenceMissingForClaim
			reason = "runtime_control_claim_missing:" + reasonKey
		}
		return risk.GaitCoverageDetail{
			Status: risk.GaitStatusMissing,
			Reasons: []string{
				reason,
				"runtime_absence_status:" + absenceStatus,
			},
		}
	}
	if runtimeControlClaimMissing(path) {
		return risk.GaitCoverageDetail{
			Status:  risk.GaitStatusMissing,
			Reasons: []string{"runtime_control_claim_missing:" + reasonKey, "runtime_absence_status:" + risk.RuntimeEvidenceAbsenceMissingForClaim},
		}
	}
	return risk.GaitCoverageDetail{
		Status:  risk.GaitStatusMissing,
		Reasons: []string{"runtime_evidence_not_collected:" + reasonKey, "runtime_absence_status:" + risk.RuntimeEvidenceAbsenceNotCollected},
	}
}

func constraintCoverageDetail(path risk.ActionPath, evidenceClass string, reasonKey string) (string, []string, bool) {
	classes := constraintClassesForEvidence(evidenceClass)
	if len(classes) == 0 {
		return "", nil, false
	}
	for _, class := range classes {
		if containsEvidenceClass(path.ConstraintEvidenceClasses, class) {
			switch strings.TrimSpace(path.ConstraintEvidenceStatus) {
			case "conflict":
				return risk.GaitStatusConflict, append([]string(nil), path.ConstraintEvidenceRefs...), true
			case "stale":
				return risk.GaitStatusStale, append([]string(nil), path.ConstraintEvidenceRefs...), true
			case "unmatched":
				return "", nil, false
			default:
				return risk.GaitStatusPresent, append([]string(nil), path.ConstraintEvidenceRefs...), true
			}
		}
	}
	return "", nil, false
}

func constraintClassesForEvidence(evidenceClass string) []string {
	switch strings.TrimSpace(evidenceClass) {
	case ingest.EvidenceClassPolicyDecision:
		return []string{"branch_protection", "required_check", "security_gate", "policy_record"}
	case ingest.EvidenceClassApproval:
		return []string{"deployment_approval", "protected_environment", "branch_protection"}
	case ingest.EvidenceClassFreezeWindow:
		return []string{"freeze_window"}
	case ingest.EvidenceClassKillSwitch:
		return []string{"kill_switch"}
	default:
		return nil
	}
}

func runtimeControlClaimMissing(path risk.ActionPath) bool {
	switch strings.TrimSpace(path.PolicyCoverageStatus) {
	case risk.PolicyCoverageStatusRuntimeProven:
		return true
	}
	switch strings.TrimSpace(path.RuntimeEvidenceState) {
	case risk.EvidenceStateDeclared, risk.EvidenceStateVerified:
		return true
	default:
		return false
	}
}

func appliesPolicyDecision(path risk.ActionPath) bool {
	return len(path.PolicyRefs) > 0 ||
		strings.TrimSpace(path.PolicyCoverageStatus) != "" ||
		path.ControlPriority != risk.ControlPriorityInventoryHygiene
}

func appliesApprovalCoverage(path risk.ActionPath) bool {
	return path.ApprovalGap ||
		path.WriteCapable ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		path.DeployWrite ||
		path.ProductionWrite
}

func appliesJITCredentialCoverage(path risk.ActionPath) bool {
	if path.CredentialProvenance == nil {
		return false
	}
	switch strings.TrimSpace(path.CredentialProvenance.AccessType) {
	case inventory.CredentialAccessTypeJIT, inventory.CredentialAccessTypeWorkload:
		return true
	default:
		return strings.TrimSpace(path.CredentialProvenance.CredentialKind) == inventory.CredentialKindJITCredential ||
			strings.TrimSpace(path.CredentialProvenance.CredentialKind) == inventory.CredentialKindOIDCWorkloadID
	}
}

func appliesFreezeWindowCoverage(path risk.ActionPath) bool {
	return path.DeployWrite ||
		path.ProductionWrite ||
		len(path.MatchedProductionTargets) > 0 ||
		strings.TrimSpace(path.WorkflowTriggerClass) == "deploy_pipeline"
}

func appliesKillSwitchCoverage(path risk.ActionPath) bool {
	return appliesFreezeWindowCoverage(path)
}

func appliesActionOutcomeCoverage(path risk.ActionPath) bool {
	return path.WriteCapable ||
		path.DeployWrite ||
		path.MergeExecute ||
		path.ProductionWrite ||
		containsActionClass(path.ActionClasses, "execute") ||
		containsActionClass(path.ActionClasses, "deploy") ||
		containsActionClass(path.ActionClasses, "write")
}

func appliesProofVerificationCoverage(path risk.ActionPath) bool {
	return path.ControlPriority != risk.ControlPriorityInventoryHygiene ||
		path.CredentialAccess ||
		path.WriteCapable
}

func containsActionClass(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
