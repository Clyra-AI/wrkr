package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func gaitCoverageForPath(path risk.ActionPath, runtime ingest.Correlation) *risk.GaitCoverage {
	return &risk.GaitCoverage{
		PolicyDecision:    gaitCoverageDetail(appliesPolicyDecision(path), runtime, ingest.EvidenceClassPolicyDecision, "policy_decision"),
		Approval:          gaitCoverageDetail(appliesApprovalCoverage(path), runtime, ingest.EvidenceClassApproval, "approval"),
		JITCredential:     gaitCoverageDetail(appliesJITCredentialCoverage(path), runtime, ingest.EvidenceClassJITCredential, "jit_credential"),
		FreezeWindow:      gaitCoverageDetail(appliesFreezeWindowCoverage(path), runtime, ingest.EvidenceClassFreezeWindow, "freeze_window"),
		KillSwitch:        gaitCoverageDetail(appliesKillSwitchCoverage(path), runtime, ingest.EvidenceClassKillSwitch, "kill_switch"),
		ActionOutcome:     gaitCoverageDetail(appliesActionOutcomeCoverage(path), runtime, ingest.EvidenceClassActionOutcome, "action_outcome"),
		ProofVerification: gaitCoverageDetail(appliesProofVerificationCoverage(path), runtime, ingest.EvidenceClassProofVerify, "proof_verification"),
	}
}

func gaitCoverageDetail(applicable bool, runtime ingest.Correlation, evidenceClass string, reasonKey string) risk.GaitCoverageDetail {
	if !applicable {
		return risk.GaitCoverageDetail{
			Status:  risk.GaitStatusNotApplicable,
			Reasons: []string{"not_applicable:" + reasonKey},
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
	if containsEvidenceClass(runtime.EvidenceClasses, evidenceClass) {
		return risk.GaitCoverageDetail{
			Status:       risk.GaitStatusPresent,
			Reasons:      []string{"runtime_evidence_present:" + reasonKey},
			EvidenceRefs: append([]string(nil), runtime.RecordIDs...),
		}
	}
	if strings.TrimSpace(runtime.Status) == ingest.CorrelationStatusMatched {
		return risk.GaitCoverageDetail{
			Status:  risk.GaitStatusMissing,
			Reasons: []string{"runtime_class_missing:" + reasonKey},
		}
	}
	return risk.GaitCoverageDetail{
		Status:  risk.GaitStatusMissing,
		Reasons: []string{"runtime_evidence_missing:" + reasonKey},
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
