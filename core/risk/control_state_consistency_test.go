package risk

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestControlStateConsistencySafeByDefaultCannotBeControlFirstCritical(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:            "apc-critical-consistency",
		Org:               "acme",
		Repo:              "acme/release",
		ToolType:          "compiled_action",
		Location:          ".github/workflows/release.yml",
		WriteCapable:      true,
		CredentialAccess:  true,
		StandingPrivilege: true,
		StandingPrivilegeReasons: []string{
			"credential_authority:standing",
		},
		DeployWrite:              true,
		ProductionWrite:          true,
		MatchedProductionTargets: []string{"built_in:deploy_workflow"},
		PolicyCoverageStatus:     PolicyCoverageStatusMatched,
		PolicyEvidenceRefs:       []string{"gait://release"},
		GaitCoverage: &GaitCoverage{
			ProofVerification: GaitCoverageDetail{
				Status:       GaitStatusPresent,
				EvidenceRefs: []string{"proof_record:rec-123"},
			},
		},
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].ControlPriority != ControlPriorityControlFirst {
		t.Fatalf("expected control_first priority, got %+v", paths[0])
	}
	if paths[0].ReviewBurden != ReviewBurdenCritical {
		t.Fatalf("expected critical review burden, got %+v", paths[0])
	}
	if paths[0].ControlState == ControlStateSafeByDefault {
		t.Fatalf("did not expect safe_by_default on a critical control-first path, got %+v", paths[0])
	}
	if paths[0].RiskTier != RiskTierCritical {
		t.Fatalf("expected critical risk tier for critical control-first path, got %+v", paths[0])
	}
}

func TestControlStateConsistencyContradictoryControlEvidenceCannotRenderLowRisk(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:               "apc-contradictory-consistency",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		CredentialAccess:     true,
		OperationalOwner:     "@acme/release",
		OwnershipStatus:      "unresolved",
		OwnershipState:       "conflicting_owner",
		OwnershipEvidence:    []string{"codeowners:CODEOWNERS:*"},
		OwnershipConflicts:   []string{"@acme/release", "@acme/security"},
		ApprovalGap:          true,
		ApprovalGapReasons:   []string{"approval_source_missing"},
		PolicyCoverageStatus: PolicyCoverageStatusMatched,
		GaitCoverage: &GaitCoverage{
			ProofVerification: GaitCoverageDetail{
				Status:       GaitStatusPresent,
				EvidenceRefs: []string{"proof_record:rec-321"},
			},
		},
		PathContext: &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].ControlResolutionState != ControlResolutionStateContradictoryControl {
		t.Fatalf("expected contradictory control resolution state, got %+v", paths[0])
	}
	if paths[0].ReviewBurden != ReviewBurdenCritical {
		t.Fatalf("expected contradictory control evidence to require critical review, got %+v", paths[0])
	}
	if paths[0].ControlPriority != ControlPriorityControlFirst {
		t.Fatalf("expected contradictory control evidence to route to control-first, got %+v", paths[0])
	}
	if paths[0].RiskTier != RiskTierHigh && paths[0].RiskTier != RiskTierCritical {
		t.Fatalf("expected contradictory control evidence to stay high-risk, got %+v", paths[0])
	}
	if paths[0].ControlState == ControlStateSafeByDefault || paths[0].ControlState == ControlStateInventoryOnly {
		t.Fatalf("expected contradictory control evidence to avoid clean control states, got %+v", paths[0])
	}
}
