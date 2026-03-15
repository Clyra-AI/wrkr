package cli

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
)

func TestObservedToolsExcludesPolicyAndParseFindingTypes(t *testing.T) {
	t.Parallel()

	findings := []source.Finding{
		{
			FindingType: "tool_config",
			ToolType:    "codex",
			Location:    "AGENTS.md",
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
		{
			FindingType: "secret_presence",
			ToolType:    "secret",
			Location:    ".env",
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
	if observed[0].ToolType != "codex" {
		t.Fatalf("unexpected observed tool: %+v", observed[0])
	}
}

func TestObservedTools_IgnoresCorrelationFindings(t *testing.T) {
	t.Parallel()

	findings := []source.Finding{
		{
			FindingType: "tool_config",
			ToolType:    "codex",
			Location:    "AGENTS.md",
			Repo:        "acme/backend",
			Org:         "acme",
		},
		{
			FindingType: "skill_metrics",
			ToolType:    "skill",
			Location:    ".agents/skills",
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
		t.Fatalf("expected one observed tool after filtering correlation findings, got %d (%+v)", len(observed), observed)
	}
	if observed[0].ToolType != "codex" {
		t.Fatalf("unexpected observed canonical finding: %+v", observed[0])
	}
}

func TestObservedToolsUsesInstanceIdentityForSameFileDefinitions(t *testing.T) {
	t.Parallel()

	findings := []source.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "langchain",
			Location:    "agents.py",
			Repo:        "acme/backend",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "symbol", Value: "research_agent"}},
		},
		{
			FindingType: "agent_framework",
			ToolType:    "langchain",
			Location:    "agents.py",
			Repo:        "acme/backend",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "symbol", Value: "ops_agent"}},
		},
	}
	contexts := map[string]agginventory.ToolContext{}
	for _, finding := range findings {
		contexts[agginventory.KeyForFinding(finding)] = agginventory.ToolContext{RiskScore: 1.0}
	}

	observed := observedTools(findings, contexts)
	if len(observed) != 2 {
		t.Fatalf("expected two observed instance identities, got %d (%+v)", len(observed), observed)
	}
	if observed[0].AgentID == observed[1].AgentID {
		t.Fatalf("expected distinct instance agent IDs, got %+v", observed)
	}
}

func TestEnrichFindingContextsFallsBackToLegacyIdentity(t *testing.T) {
	t.Parallel()

	finding := source.Finding{
		FindingType: "tool_config",
		ToolType:    "codex",
		Location:    "AGENTS.md",
		Repo:        "acme/backend",
		Org:         "acme",
		Evidence:    []model.Evidence{{Key: "symbol", Value: "release_agent"}},
	}
	base := map[string]agginventory.ToolContext{
		agginventory.KeyForFinding(finding): {RiskScore: 3.0},
	}
	legacyAgentID := identity.LegacyAgentID(finding.ToolType, finding.Location, finding.Org)
	identities := map[string]manifest.IdentityRecord{
		legacyAgentID: {
			AgentID:       legacyAgentID,
			Status:        "active",
			ApprovalState: "valid",
			DataClass:     "code",
			EndpointClass: "workspace",
			AutonomyLevel: "interactive",
			RiskScore:     7.3,
		},
	}

	enriched := enrichFindingContexts([]source.Finding{finding}, base, identities)
	ctx := enriched[agginventory.KeyForFinding(finding)]
	if ctx.LifecycleState != "active" || ctx.ApprovalStatus != "valid" {
		t.Fatalf("expected legacy identity context fallback, got %+v", ctx)
	}
	if ctx.RiskScore != 7.3 {
		t.Fatalf("expected risk score from legacy identity, got %.2f", ctx.RiskScore)
	}
}
