package agentresolver

import (
	"reflect"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestBuildWorkflowChainsStableGroupingAndUnknownStates(t *testing.T) {
	t.Parallel()

	inputs := []WorkflowChainInput{
		{
			PathID:                    "apc-chain-a",
			Org:                       "acme",
			Repo:                      "acme/payments",
			ToolType:                  "compiled_action",
			Location:                  ".github/workflows/release.yml",
			Purpose:                   "release automation",
			PurposeSource:             "workflow_name",
			CredentialAccess:          true,
			CredentialProvenance:      &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
			CredentialAuthority:       &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
			OperationalOwner:          "@acme/release",
			ApprovalEvidenceState:     "unknown",
			ProofEvidenceState:        "unknown",
			TargetEvidenceState:       "declared",
			TargetClass:               "production_impacting",
			AutonomyTier:              "tier_4_prod_privileged_or_customer_impacting",
			DelegationReadinessState:  "approval_required",
			RecommendedControl:        "approval_required",
			MatchedProductionTargets:  []string{"cluster/prod"},
			EvidenceCompletenessLabel: "partial_evidence",
			GraphNodeRefs:             []string{"node-a"},
			GraphEdgeRefs:             []string{"edge-a"},
			ProofRefs:                 []string{"proof://release"},
			EvidenceRefs:              []string{"evidence://release"},
			SourceFindingKeys:         []string{"finding:a"},
		},
		{
			PathID:                    "apc-chain-b",
			Org:                       "acme",
			Repo:                      "acme/payments",
			ToolType:                  "compiled_action",
			Location:                  ".github/workflows/release.yml",
			Purpose:                   "release automation",
			PurposeSource:             "workflow_name",
			CredentialAccess:          true,
			CredentialProvenance:      &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
			CredentialAuthority:       &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
			OperationalOwner:          "@acme/release",
			ApprovalEvidenceState:     "unknown",
			ProofEvidenceState:        "unknown",
			TargetEvidenceState:       "declared",
			TargetClass:               "production_impacting",
			AutonomyTier:              "tier_4_prod_privileged_or_customer_impacting",
			DelegationReadinessState:  "approval_required",
			RecommendedControl:        "approval_required",
			MatchedProductionTargets:  []string{"cluster/prod"},
			EvidenceCompletenessLabel: "partial_evidence",
			GraphNodeRefs:             []string{"node-b"},
			GraphEdgeRefs:             []string{"edge-b"},
			ProofRefs:                 []string{"proof://release"},
			EvidenceRefs:              []string{"evidence://release"},
			SourceFindingKeys:         []string{"finding:b"},
		},
		{
			PathID:                    "apc-chain-c",
			Org:                       "acme",
			Repo:                      "acme/payments",
			ToolType:                  "compiled_action",
			Location:                  ".github/workflows/release.yml",
			Purpose:                   "release automation",
			PurposeSource:             "workflow_name",
			CredentialAccess:          true,
			CredentialProvenance:      &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceJIT, CredentialKind: agginventory.CredentialKindJITCredential, AccessType: agginventory.CredentialAccessTypeJIT},
			CredentialAuthority:       &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindJITCredential, AccessType: agginventory.CredentialAccessTypeJIT},
			OperationalOwner:          "@acme/platform",
			ApprovalEvidenceState:     "verified",
			ProofEvidenceState:        "verified",
			TargetEvidenceState:       "verified",
			TargetClass:               "internal_tooling",
			AutonomyTier:              "tier_2_app_code_owner_review",
			DelegationReadinessState:  "review_required",
			RecommendedControl:        "owner_review",
			IntroducedBy:              &attribution.Result{Source: attribution.SourceSidecar, Confidence: attribution.ConfidenceHigh, PRNumber: 17, Author: "octocat"},
			MatchedProductionTargets:  []string{"repo:release"},
			EvidenceCompletenessLabel: "strong_evidence",
			GraphNodeRefs:             []string{"node-c"},
			GraphEdgeRefs:             []string{"edge-c"},
			ProofRefs:                 []string{"proof://review"},
			EvidenceRefs:              []string{"evidence://review"},
			SourceFindingKeys:         []string{"finding:c"},
		},
	}

	first := BuildWorkflowChains(inputs)
	second := BuildWorkflowChains([]WorkflowChainInput{inputs[2], inputs[1], inputs[0]})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic workflow-chain artifact\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first == nil {
		t.Fatal("expected workflow chains")
	}
	if first.Summary.TotalChains != 2 {
		t.Fatalf("expected 2 chains after duplicate collapse, got %+v", first.Summary)
	}

	var collapsed WorkflowChain
	for _, chain := range first.Chains {
		if len(chain.PathIDs) == 2 {
			collapsed = chain
			break
		}
	}
	if collapsed.ChainID == "" {
		t.Fatalf("expected collapsed chain, got %+v", first.Chains)
	}
	if !reflect.DeepEqual(collapsed.PathIDs, []string{"apc-chain-a", "apc-chain-b"}) {
		t.Fatalf("expected stable grouped path ids, got %+v", collapsed.PathIDs)
	}
	if collapsed.PullRequest.Status != "unknown" {
		t.Fatalf("expected missing PR metadata to become explicit unknown state, got %+v", collapsed.PullRequest)
	}
	if collapsed.Outcome.Status != "unknown" {
		t.Fatalf("expected missing outcome metadata to become explicit unknown state, got %+v", collapsed.Outcome)
	}
	if !containsWorkflowChainRollup(first.Summary.AutonomyTiers, "tier_4_prod_privileged_or_customer_impacting", 1) {
		t.Fatalf("expected autonomy tier rollup, got %+v", first.Summary.AutonomyTiers)
	}
	if !containsWorkflowChainRollup(first.Summary.DelegationReadinessStates, "approval_required", 1) {
		t.Fatalf("expected readiness rollup, got %+v", first.Summary.DelegationReadinessStates)
	}
	if !containsWorkflowChainRollup(first.Summary.EvidenceCompleteness, "partial_evidence", 1) {
		t.Fatalf("expected evidence completeness rollup, got %+v", first.Summary.EvidenceCompleteness)
	}
}

func containsWorkflowChainRollup(values []WorkflowChainRollup, wantValue string, wantCount int) bool {
	for _, value := range values {
		if value.Value == wantValue && value.Count == wantCount {
			return true
		}
	}
	return false
}
