package approvedtools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestLoadNormalizesPolicyAndMatchesCandidate(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "approved.yaml")
	payload := []byte(`
schema_version: v1
approved:
  tool_ids:
    exact: ["wrkr:mcp:.mcp.json"]
  repos:
    prefix: ["acme/"]
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if !cfg.Match(ToolCandidate{ToolID: "wrkr:mcp:.mcp.json"}) {
		t.Fatal("expected exact tool id match")
	}
	if !cfg.Match(ToolCandidate{Repos: []string{"acme/backend"}}) {
		t.Fatal("expected repo prefix match")
	}
	if cfg.Match(ToolCandidate{Repos: []string{"other/backend"}}) {
		t.Fatal("did not expect non-matching repo to pass")
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "approved.yaml")
	payload := []byte(`
schema_version: v1
approved:
  orgs:
    exact: ["acme"]
  unexpected: true
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected schema validation error for unknown field")
	}
}

func TestEmbeddedSchemaMatchesCanonicalContract(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	canonicalPath := filepath.Join(repoRoot, "schemas", "v1", "policy", "approved-tools.schema.json")

	canonicalBytes, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(canonicalBytes, &canonical); err != nil {
		t.Fatalf("parse canonical schema: %v", err)
	}
	var embedded map[string]any
	if err := json.Unmarshal(approvedToolsSchemaJSON, &embedded); err != nil {
		t.Fatalf("parse embedded schema: %v", err)
	}
	if !reflect.DeepEqual(canonical, embedded) {
		t.Fatal("embedded approved tools schema drifted from canonical schema contract")
	}
}

func TestCompareLocalInventoryBuildsGovernanceSummaryAndGapFindings(t *testing.T) {
	t.Parallel()

	inv := agginventory.Inventory{
		Tools: []agginventory.Tool{
			{
				ToolID:         "wrkr:codex:.codex/config.toml",
				ToolType:       "codex",
				Org:            "local",
				Repos:          []string{"local-machine"},
				ApprovalClass:  "approved",
				PermissionTier: "read",
				Locations:      []agginventory.ToolLocation{{Repo: "local-machine", Location: ".codex/config.toml", Owner: "@local"}},
			},
			{
				ToolID:         "wrkr:cursor:.cursor/mcp.json",
				ToolType:       "cursor",
				Org:            "local",
				Repos:          []string{"local-machine"},
				ApprovalClass:  "unapproved",
				PermissionTier: "write",
				Locations:      []agginventory.ToolLocation{{Repo: "local-machine", Location: ".cursor/mcp.json", Owner: "@local"}},
			},
		},
	}

	findings := CompareLocalInventory(&inv, true, "/tmp/approved-tools.yaml")
	if inv.LocalGovernance == nil {
		t.Fatal("expected local governance summary")
	}
	if inv.LocalGovernance.SanctionedTools != 1 || inv.LocalGovernance.UnsanctionedTools != 1 {
		t.Fatalf("unexpected local governance summary: %+v", inv.LocalGovernance)
	}
	if len(findings) != 1 || findings[0].FindingType != "local_governance_gap" || findings[0].ToolType != "cursor" {
		t.Fatalf("expected one cursor governance gap finding, got %+v", findings)
	}
}

func TestCompareLocalInventoryMarksReferenceUnavailableWithoutBaseline(t *testing.T) {
	t.Parallel()

	inv := agginventory.Inventory{}
	findings := CompareLocalInventory(&inv, false, "")
	if len(findings) != 0 {
		t.Fatalf("expected no findings without baseline, got %+v", findings)
	}
	if inv.LocalGovernance == nil || inv.LocalGovernance.ReferenceBasis != LocalGovernanceBasisUnavailable {
		t.Fatalf("expected unavailable local governance basis, got %+v", inv.LocalGovernance)
	}
}
