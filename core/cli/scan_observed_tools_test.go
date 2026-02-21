package cli

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/source"
)

func TestObservedToolsExcludesPolicyAndParseFindingTypes(t *testing.T) {
	t.Parallel()

	findings := []source.Finding{
		{
			FindingType: "source_discovery",
			ToolType:    "source_repo",
			Location:    "acme/backend",
			Repo:        "acme/backend",
			Org:         "acme",
		},
		{
			FindingType: "policy_violation",
			ToolType:    "policy",
			Location:    ".wrkr/policy.yaml",
			Repo:        "acme/backend",
			Org:         "acme",
		},
		{
			FindingType: "parse_error",
			ToolType:    "yaml",
			Location:    ".github/workflows/ci.yml",
			Repo:        "acme/backend",
			Org:         "acme",
		},
	}
	contexts := map[string]agginventory.ToolContext{}
	for _, finding := range findings {
		contexts[agginventory.KeyForFinding(finding)] = agginventory.ToolContext{RiskScore: 1.0}
	}

	observed := observedTools(findings, contexts)
	if len(observed) != 1 {
		t.Fatalf("expected one identity-bearing observed tool, got %d (%+v)", len(observed), observed)
	}
	if observed[0].ToolType != "source_repo" {
		t.Fatalf("unexpected observed tool: %+v", observed[0])
	}
}
