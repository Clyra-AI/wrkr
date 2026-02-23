package privilegebudget

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy/productiontargets"
)

func TestBuildComputesPrivilegeBudgetAndPerAgentMap(t *testing.T) {
	t.Parallel()

	mcpToolID := identity.ToolID("mcp", ".mcp.json")
	mcpAgentID := identity.AgentID(mcpToolID, "acme")

	tools := []agginventory.Tool{
		{
			ToolID:      mcpToolID,
			AgentID:     mcpAgentID,
			ToolType:    "mcp",
			Org:         "acme",
			Repos:       []string{"acme/payments"},
			Permissions: []string{"db.write"},
			DataClass:   "code",
		},
		{
			ToolID:      "ci-1",
			AgentID:     "wrkr:ci-1:acme",
			ToolType:    "ci_agent",
			Org:         "acme",
			Repos:       []string{"acme/platform"},
			Permissions: []string{"proc.exec", "secret.read"},
			DataClass:   "credentials",
		},
	}
	findings := []model.Finding{
		{
			ToolType:    "mcp",
			Location:    ".mcp.json",
			Repo:        "acme/payments",
			Org:         "acme",
			Permissions: []string{"db.write"},
			Evidence: []model.Evidence{
				{Key: "server", Value: "postgres-prod"},
			},
		},
	}
	rules := &productiontargets.Config{
		SchemaVersion: "v1",
		Targets: productiontargets.Targets{
			MCPServers: productiontargets.MatchSet{Exact: []string{"postgres-prod"}},
		},
		WritePermissions: []string{"db.write", "filesystem.write"},
	}
	rules.Normalize()

	budget, entries := Build(tools, findings, rules)
	if budget.TotalTools != 2 {
		t.Fatalf("expected total_tools=2 got %d", budget.TotalTools)
	}
	if budget.WriteCapableTools != 1 {
		t.Fatalf("expected write_capable_tools=1 got %d", budget.WriteCapableTools)
	}
	if budget.CredentialAccessTools != 1 {
		t.Fatalf("expected credential_access_tools=1 got %d", budget.CredentialAccessTools)
	}
	if budget.ExecCapableTools != 1 {
		t.Fatalf("expected exec_capable_tools=1 got %d", budget.ExecCapableTools)
	}
	if !budget.ProductionWrite.Configured {
		t.Fatal("expected production_write.configured=true")
	}
	if budget.ProductionWrite.Count != 1 {
		t.Fatalf("expected production_write.count=1 got %d", budget.ProductionWrite.Count)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 agent map entries, got %d", len(entries))
	}
	foundProduction := false
	for _, item := range entries {
		if item.AgentID == mcpAgentID {
			if !item.WriteCapable {
				t.Fatal("expected mcp tool write_capable=true")
			}
			if !item.ProductionWrite {
				t.Fatal("expected mcp tool production_write=true")
			}
			foundProduction = true
		}
	}
	if !foundProduction {
		t.Fatal("expected to find mcp production-write entry")
	}
}

func TestBuildWithoutRulesLeavesProductionWriteUnconfigured(t *testing.T) {
	t.Parallel()

	budget, entries := Build([]agginventory.Tool{}, nil, nil)
	if budget.ProductionWrite.Configured {
		t.Fatal("expected production_write.configured=false when no rules provided")
	}
	if budget.ProductionWrite.Count != 0 {
		t.Fatalf("expected zero production count, got %d", budget.ProductionWrite.Count)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}
