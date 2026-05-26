package controlbacklog

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildCarriesWave1ProjectionFieldsFromActionPaths(t *testing.T) {
	t.Parallel()

	path := risk.ProjectActionPath(risk.ActionPath{
		PathID:                "apc-wave1-backlog",
		Org:                   "acme",
		Repo:                  "acme/payments",
		ToolType:              "ci_agent",
		Location:              ".github/workflows/deploy.yml",
		WriteCapable:          true,
		CredentialAccess:      true,
		ProductionWrite:       true,
		DeployWrite:           true,
		ApprovalEvidenceState: risk.EvidenceStateVerified,
		ProofEvidenceState:    risk.EvidenceStateVerified,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			StandingAccess:         true,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
	})

	backlog := Build(Input{ActionPaths: []risk.ActionPath{path}})
	if len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", backlog.Items)
	}
	item := backlog.Items[0]
	if item.AutonomyTier != risk.AutonomyTier4ProdPrivilegedCustomerImpact {
		t.Fatalf("expected autonomy tier on backlog item, got %+v", item)
	}
	if item.DelegationReadinessState != risk.DelegationReadinessBlocked {
		t.Fatalf("expected blocked readiness on backlog item, got %+v", item)
	}
	if item.RecommendedControl != risk.RecommendedControlBlockStandingCredential {
		t.Fatalf("expected standing-credential block recommendation, got %+v", item)
	}
	if item.RecommendedActionContract == nil || item.TodayPath == nil || item.RecommendedGovernedPath == nil {
		t.Fatalf("expected Wave 1 governed-path artifacts on backlog item, got %+v", item)
	}
	if backlog.Summary.AutonomyTiers.Tier4ProdPrivilegedCustomerImpact != 1 {
		t.Fatalf("expected autonomy summary count, got %+v", backlog.Summary)
	}
	if backlog.Summary.DelegationReadiness.Blocked != 1 {
		t.Fatalf("expected readiness summary count, got %+v", backlog.Summary)
	}
	if backlog.Summary.RecommendedControls.BlockStandingCredential != 1 {
		t.Fatalf("expected control summary count, got %+v", backlog.Summary)
	}
}
