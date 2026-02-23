package appendix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestBuildWithOptionsDeterministicAndAnonymized(t *testing.T) {
	t.Parallel()

	one := 1
	inv := agginventory.Inventory{
		Org: "acme",
		Tools: []agginventory.Tool{
			{
				ToolID:          "wrkr:codex:.codex/config.toml",
				AgentID:         "wrkr:wrkr:codex:.codex/config.toml:acme",
				ToolType:        "codex",
				ToolCategory:    "assistant",
				ConfidenceScore: 0.90,
				Org:             "acme",
				Repos:           []string{"acme/backend"},
				PermissionTier:  "write",
				RiskTier:        "high",
				AdoptionPattern: "team_level",
				ApprovalClass:   "approved",
				LifecycleState:  "active",
				RegulatoryMapping: []agginventory.RegulatoryStatus{
					{Regulation: "eu_ai_act", ControlID: "article_9_risk_management", Status: "gap"},
				},
			},
		},
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                  "wrkr:wrkr:codex:.codex/config.toml:acme",
				ToolID:                   "wrkr:codex:.codex/config.toml",
				ToolType:                 "codex",
				Org:                      "acme",
				Repos:                    []string{"acme/backend"},
				Permissions:              []string{"filesystem.write"},
				EndpointClass:            "workspace",
				DataClass:                "code",
				AutonomyLevel:            "interactive",
				RiskScore:                8.1,
				WriteCapable:             true,
				CredentialAccess:         false,
				ExecCapable:              false,
				ProductionWrite:          true,
				MatchedProductionTargets: []string{"repo:acme/backend"},
			},
		},
		PrivilegeBudget: agginventory.PrivilegeBudget{
			ProductionWrite: agginventory.ProductionWriteBudget{
				Configured: true,
				Status:     agginventory.ProductionTargetsStatusConfigured,
				Count:      &one,
			},
		},
	}

	now := time.Date(2026, 2, 23, 20, 30, 0, 0, time.UTC)
	clear := Build(inv, now)
	if clear.ExportedAt != "2026-02-23T20:30:00Z" {
		t.Fatalf("unexpected exported_at: %s", clear.ExportedAt)
	}
	if len(clear.InventoryRows) != 1 || clear.InventoryRows[0].Org != "acme" {
		t.Fatalf("unexpected inventory rows: %+v", clear.InventoryRows)
	}
	if len(clear.RegulatoryRows) != 1 {
		t.Fatalf("unexpected regulatory rows: %+v", clear.RegulatoryRows)
	}

	anon := BuildWithOptions(inv, now, BuildOptions{Anonymize: true})
	if strings.Contains(anon.Org, "acme") {
		t.Fatalf("expected anonymized org, got %q", anon.Org)
	}
	if strings.Contains(anon.InventoryRows[0].ToolID, "wrkr:codex") {
		t.Fatalf("expected anonymized tool_id, got %q", anon.InventoryRows[0].ToolID)
	}
	if anon.InventoryRows[0].ToolID != anon.ApprovalGapRows[0].ToolID {
		t.Fatalf("expected stable pseudonym across tables, got inventory=%q approval=%q", anon.InventoryRows[0].ToolID, anon.ApprovalGapRows[0].ToolID)
	}
}

func TestWriteCSVCreatesDeterministicTables(t *testing.T) {
	t.Parallel()

	snapshot := Snapshot{
		InventoryRows: []InventoryRow{
			{ToolID: "t1", AgentID: "a1", ToolType: "codex", ToolCategory: "assistant", ConfidenceScore: 0.9, Org: "o1", RepoCount: 1, PermissionTier: "write", RiskTier: "high", AdoptionPattern: "team_level", ApprovalClass: "approved", LifecycleState: "active"},
		},
		PrivilegeRows: []PrivilegeRow{
			{AgentID: "a1", ToolID: "t1", ToolType: "codex", Org: "o1", RepoCount: 1, PermissionCount: 1, EndpointClass: "workspace", DataClass: "code", AutonomyLevel: "interactive", RiskScore: 8.1, WriteCapable: true},
		},
		ApprovalGapRows: []ApprovalGapRow{
			{ToolID: "t1", AgentID: "a1", ToolType: "codex", Org: "o1", ApprovalClass: "approved", AdoptionPattern: "team_level", RiskTier: "high"},
		},
		RegulatoryRows: []RegulatoryMatrixRow{
			{ToolID: "t1", AgentID: "a1", ToolType: "codex", Org: "o1", Regulation: "eu_ai_act", ControlID: "article_9_risk_management", Status: "gap", RiskTier: "high", PermissionTier: "write"},
		},
	}

	dir := t.TempDir()
	paths, err := WriteCSV(snapshot, dir)
	if err != nil {
		t.Fatalf("write csv tables: %v", err)
	}
	if len(paths) != 4 {
		t.Fatalf("expected 4 csv files, got %d (%v)", len(paths), paths)
	}
	for _, key := range []string{"inventory", "privilege_map", "approval_gap", "regulatory_matrix"} {
		path := paths[key]
		if strings.TrimSpace(path) == "" {
			t.Fatalf("missing csv path for key %s in %v", key, paths)
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read csv %s: %v", path, readErr)
		}
		if !strings.Contains(string(payload), ",") {
			t.Fatalf("expected csv content in %s", path)
		}
	}
	if !strings.HasSuffix(paths["inventory"], filepath.Join(dir, "inventory.csv")) {
		t.Fatalf("unexpected inventory csv path: %s", paths["inventory"])
	}
}
