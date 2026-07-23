package risk

import "testing"

func TestContainmentGapsDoNotEraseVerifiedRuntimeEvidence(t *testing.T) {
	t.Parallel()

	path := ActionPath{GaitCoverage: &GaitCoverage{
		PolicyDecision:    GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"policy:1"}},
		Approval:          GaitCoverageDetail{Status: GaitStatusNotApplicable},
		JITCredential:     GaitCoverageDetail{Status: GaitStatusNotApplicable},
		FreezeWindow:      GaitCoverageDetail{Status: GaitStatusNotApplicable},
		KillSwitch:        GaitCoverageDetail{Status: GaitStatusNotApplicable},
		ActionOutcome:     GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"outcome:1"}},
		ProofVerification: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"proof:1"}},
		Containment: &ContainmentCoverage{
			Status:             ContainmentCoverageNotObserved,
			StopRequest:        missingContainmentDetailForTest("stop_request"),
			ContainmentReceipt: missingContainmentDetailForTest("containment_receipt"),
		},
	}}

	state, reasons, refs := deriveRuntimeEvidenceState(path)
	if state != EvidenceStateVerified {
		t.Fatalf("expected verified runtime evidence to remain verified, got state=%q reasons=%v refs=%v", state, reasons, refs)
	}
	if absence := RuntimeEvidenceAbsenceStatus(path); absence != "" {
		t.Fatalf("expected containment absence to stay separate from runtime evidence absence, got %q", absence)
	}
}

func missingContainmentDetailForTest(class string) GaitCoverageDetail {
	return GaitCoverageDetail{
		Status:  GaitStatusMissing,
		Reasons: []string{"runtime_absence_status:missing_for_control_claim", "runtime_control_claim_missing:" + class},
	}
}
