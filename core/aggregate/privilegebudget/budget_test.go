package privilegebudget

import (
	"encoding/json"
	"strings"
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
	if budget.ProductionWrite.Status != agginventory.ProductionTargetsStatusConfigured {
		t.Fatalf("expected production_write.status=%q got %q", agginventory.ProductionTargetsStatusConfigured, budget.ProductionWrite.Status)
	}
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 1 {
		t.Fatalf("expected production_write.count=1 got %v", budget.ProductionWrite.Count)
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
	if budget.ProductionWrite.Status != agginventory.ProductionTargetsStatusNotConfigured {
		t.Fatalf("expected production_write.status=%q got %q", agginventory.ProductionTargetsStatusNotConfigured, budget.ProductionWrite.Status)
	}
	if budget.ProductionWrite.Count != nil {
		t.Fatalf("expected nil production count when not configured, got %v", *budget.ProductionWrite.Count)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

func TestBuildKeepsRequiredArrayFieldsAsArrays(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{
		{
			ToolID:      "tool-1",
			AgentID:     "wrkr:tool-1:acme",
			ToolType:    "mcp",
			Org:         "acme",
			Permissions: nil,
			Repos:       nil,
		},
	}
	_, entries := Build(tools, nil, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	if entries[0].Permissions == nil {
		t.Fatal("expected permissions to be empty array, got nil")
	}
	if entries[0].Repos == nil {
		t.Fatal("expected repos to be empty array, got nil")
	}
	encoded, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	asJSON := string(encoded)
	if !strings.Contains(asJSON, "\"permissions\":[]") {
		t.Fatalf("expected permissions to serialize as [], got %s", asJSON)
	}
	if !strings.Contains(asJSON, "\"repos\":[]") {
		t.Fatalf("expected repos to serialize as [], got %s", asJSON)
	}
}

func TestBuildPreservesMixedCaseOrgSignalAgentMatch(t *testing.T) {
	t.Parallel()

	mcpToolID := identity.ToolID("mcp", ".mcp.json")
	mixedCaseOrg := "Acme"
	mcpAgentID := identity.AgentID(mcpToolID, mixedCaseOrg)

	tools := []agginventory.Tool{
		{
			ToolID:      mcpToolID,
			AgentID:     mcpAgentID,
			ToolType:    "mcp",
			Org:         mixedCaseOrg,
			Repos:       []string{"acme/shared"},
			Permissions: []string{"db.write"},
		},
	}
	findings := []model.Finding{
		{
			ToolType: "mcp",
			Location: ".mcp.json",
			Org:      mixedCaseOrg,
			Repo:     "acme/shared",
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
		WritePermissions: []string{"db.write"},
	}
	rules.Normalize()

	budget, entries := Build(tools, findings, rules)
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 1 {
		t.Fatalf("expected production write count=1, got %v", budget.ProductionWrite.Count)
	}
	if len(entries) != 1 || !entries[0].ProductionWrite {
		t.Fatalf("expected entry production_write=true, got %+v", entries)
	}
}
