package attackpath

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestControlPathGraphV2AddsNodeEdgeKindsAndSummaryRollups(t *testing.T) {
	t.Parallel()

	graph := BuildControlPathGraph([]ControlPathInput{{
		PathID:                    "apc-v2-graph",
		AgentID:                   "wrkr:compiled_action:acme",
		Org:                       "acme",
		Repo:                      "acme/payments",
		ToolType:                  "compiled_action",
		Location:                  ".github/workflows/release.yml",
		Purpose:                   "release automation",
		PurposeSource:             "workflow_name",
		ExecutionIdentity:         "release-bot",
		ExecutionIdentityStatus:   "known",
		CredentialAccess:          true,
		CredentialProvenance:      &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		CredentialAuthority:       &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		GovernanceControls:        []agginventory.GovernanceControlMapping{{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusSatisfied}, {Control: agginventory.GovernanceControlProof, Status: agginventory.ControlStatusSatisfied}},
		MatchedProductionTargets:  []string{"cluster:prod"},
		PullRequestWrite:          true,
		DeployWrite:               true,
		ProductionWrite:           true,
		IntroducedBy:              &attribution.Result{Source: attribution.SourceSidecar, Confidence: attribution.ConfidenceHigh, PRNumber: 17, Author: "octocat"},
		AutonomyTier:              "tier_4_prod_privileged_or_customer_impacting",
		DelegationReadinessState:  "approval_required",
		ApprovalEvidenceState:     "verified",
		ProofEvidenceState:        "verified",
		RuntimeEvidenceState:      "declared",
		TargetEvidenceState:       "verified",
		EvidenceCompletenessLabel: "strong_evidence",
	}})
	if graph == nil {
		t.Fatal("expected control_path_graph")
	}

	for _, want := range []string{
		ControlPathNodeIntent,
		ControlPathNodeTask,
		ControlPathNodeHumanIdentity,
		ControlPathNodeAgentTeam,
		ControlPathNodePullRequest,
		ControlPathNodeWorkflowRun,
		ControlPathNodeApprovalIdentity,
		ControlPathNodePolicyIdentity,
		ControlPathNodeDeploymentPath,
		ControlPathNodeAssetIdentity,
		ControlPathNodeEvidenceIdentity,
		ControlPathNodeOutcome,
	} {
		if !hasControlPathNodeKind(graph.Nodes, want) {
			t.Fatalf("expected v2 node kind %s in %+v", want, graph.Nodes)
		}
	}

	for _, want := range []string{
		ControlPathEdgeRequestToHuman,
		ControlPathEdgeHumanDelegatesTask,
		ControlPathEdgeTaskExecutedByAgentTeam,
		ControlPathEdgeAgentTeamUsesTool,
		ControlPathEdgeToolUsesCredential,
		ControlPathEdgeCredentialAuthorizesWorkflow,
		ControlPathEdgeWorkflowChangesRepo,
		ControlPathEdgeRepoProducesPullRequest,
		ControlPathEdgePullRequestRunsChecks,
		ControlPathEdgeChecksGateApproval,
		ControlPathEdgeApprovalAuthorizesDeploy,
		ControlPathEdgeDeployAffectsAsset,
		ControlPathEdgeEvidenceProvesOutcome,
	} {
		if !hasControlPathEdgeKind(graph.Edges, want) {
			t.Fatalf("expected v2 edge kind %s in %+v", want, graph.Edges)
		}
	}

	if !containsControlPathRollup(graph.Summary.AutonomyTiers, "tier_4_prod_privileged_or_customer_impacting", 1) {
		t.Fatalf("expected autonomy tier rollup, got %+v", graph.Summary.AutonomyTiers)
	}
	if !containsControlPathRollup(graph.Summary.DelegationReadinessStates, "approval_required", 1) {
		t.Fatalf("expected readiness rollup, got %+v", graph.Summary.DelegationReadinessStates)
	}
	if !containsControlPathRollup(graph.Summary.EvidenceStates, "strong_evidence", 1) {
		t.Fatalf("expected evidence-state rollup, got %+v", graph.Summary.EvidenceStates)
	}
}

func TestControlPathHumanLabelSuppressesLowConfidenceAuthor(t *testing.T) {
	t.Parallel()

	if got := controlPathHumanLabel(&attribution.Result{
		Source:     attribution.SourceLocalGit,
		Confidence: attribution.ConfidenceLow,
		Author:     "tip-author",
	}); got != "unknown_human" {
		t.Fatalf("expected low-confidence human label to be suppressed, got %q", got)
	}
}

func containsControlPathRollup(values []ControlPathKindRollup, wantKind string, wantCount int) bool {
	for _, value := range values {
		if value.Kind == wantKind && value.Count == wantCount {
			return true
		}
	}
	return false
}
