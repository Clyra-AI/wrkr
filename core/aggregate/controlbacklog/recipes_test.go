package controlbacklog

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestSecurityTestBacklogRecipesStableByCapabilityClass(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		ActionPaths: []risk.ActionPath{{
			PathID:                   "apc-123",
			Org:                      "acme",
			Repo:                     "repo",
			ToolType:                 "mcp",
			Location:                 ".mcp.json",
			WriteCapable:             true,
			CredentialAccess:         true,
			RecommendedAction:        "control",
			SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
			TrustDepth: &agginventory.TrustDepth{
				Surface:         agginventory.TrustSurfaceMCP,
				Exposure:        agginventory.TrustExposurePublic,
				GatewayCoverage: agginventory.TrustCoverageUnprotected,
			},
		}},
	})
	if len(backlog.Items) == 0 {
		t.Fatal("expected backlog item")
	}
	if len(backlog.Items[0].SecurityTestRecipes) == 0 {
		t.Fatalf("expected security test recipes, got %+v", backlog.Items[0])
	}
	if backlog.Items[0].SecurityTestRecipes[0].DryRunFlag != "--dry-run" {
		t.Fatalf("expected dry-run recipe flag, got %+v", backlog.Items[0].SecurityTestRecipes[0])
	}
}
