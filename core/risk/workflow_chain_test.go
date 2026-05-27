package risk

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestWorkflowChainsDecorateActionPathsAndExtendedLineage(t *testing.T) {
	t.Parallel()

	paths := DecorateEvidenceContext([]ActionPath{{
		PathID:                   "apc-wave2-lineage",
		Org:                      "acme",
		Repo:                     "acme/release",
		AgentID:                  "wrkr:compiled_action:acme",
		ToolType:                 "compiled_action",
		Location:                 ".github/workflows/release.yml",
		Purpose:                  "release automation",
		PurposeSource:            "workflow_name",
		WriteCapable:             true,
		CredentialAccess:         true,
		CredentialProvenance:     &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		CredentialAuthority:      &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		ActionClasses:            []string{"deploy", "write"},
		MatchedProductionTargets: []string{"cluster/prod"},
		OperationalOwner:         "@acme/release",
		OwnershipStatus:          "explicit",
		ApprovalGap:              false,
		ApprovalEvidenceState:    EvidenceStateVerified,
		ProofEvidenceState:       EvidenceStateVerified,
		RuntimeEvidenceState:     EvidenceStateDeclared,
		TargetEvidenceState:      EvidenceStateVerified,
		PolicyCoverageStatus:     PolicyCoverageStatusMatched,
		PolicyEvidenceRefs:       []string{"proof://release"},
		GovernanceControls: []agginventory.GovernanceControlMapping{
			{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusSatisfied},
			{Control: agginventory.GovernanceControlProof, Status: agginventory.ControlStatusSatisfied},
		},
		IntroducedBy:             &attribution.Result{Source: attribution.SourceSidecar, Confidence: attribution.ConfidenceHigh, PRNumber: 17, Author: "octocat"},
		AutonomyTier:             "tier_4_prod_privileged_or_customer_impacting",
		DelegationReadinessState: "approval_required",
		RecommendedControl:       "approval_required",
		TargetClass:              "production_impacting",
	}}, nil)

	graph := BuildControlPathGraph(paths)
	chains := BuildWorkflowChains(paths, graph)
	paths = DecorateWorkflowChainRefs(paths, chains)
	paths = DecorateActionLineage(paths, graph)
	if len(paths) != 1 {
		t.Fatalf("expected one path, got %+v", paths)
	}
	if len(paths[0].WorkflowChainRefs) == 0 {
		t.Fatalf("expected workflow chain refs on action path, got %+v", paths[0])
	}
	if paths[0].ActionLineage == nil {
		t.Fatalf("expected action lineage, got %+v", paths[0])
	}

	segments := map[string]ActionLineageSegment{}
	for _, segment := range paths[0].ActionLineage.Segments {
		segments[segment.Kind] = segment
	}
	for _, kind := range []string{"intent", "task", "human", "pr", "deployment", "outcome", "evidence"} {
		if _, ok := segments[kind]; !ok {
			t.Fatalf("expected extended lineage segment %q, got %+v", kind, paths[0].ActionLineage)
		}
	}
	if segments["pr"].Status != EvidenceStateVerified {
		t.Fatalf("expected PR lineage to use attribution confidence, got %+v", segments["pr"])
	}
	if segments["deployment"].Status == "missing" {
		t.Fatalf("expected deployment lineage for deploy path, got %+v", segments["deployment"])
	}
	if segments["evidence"].Status != EvidenceStateVerified {
		t.Fatalf("expected evidence lineage to reflect proof/runtime state, got %+v", segments["evidence"])
	}
}
