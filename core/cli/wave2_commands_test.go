package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRootHelpListsInventoryAndMCPListExamples(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	for _, token := range []string{
		"  mcp-list   list MCP servers with trust and privilege posture",
		"  inventory  emit inventory export or deterministic inventory drift",
		"  wrkr scan --my-setup --json",
		"  wrkr mcp-list --state ./.wrkr/last-scan.json --json",
		"  wrkr scan --github-org acme --github-api https://api.github.com --json",
		"  wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --json",
	} {
		if !strings.Contains(errOut.String(), token) {
			t.Fatalf("expected root help to contain %q, got %q", token, errOut.String())
		}
	}
}

func TestInventoryCommandMatchesInventoryExportContract(t *testing.T) {
	t.Parallel()

	statePath := writeWave2State(t, inventoryFixtureSnapshot())

	var exportOut bytes.Buffer
	var exportErr bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--state", statePath, "--json"}, &exportOut, &exportErr); code != 0 {
		t.Fatalf("export failed: code=%d stderr=%s", code, exportErr.String())
	}

	var inventoryOut bytes.Buffer
	var inventoryErr bytes.Buffer
	if code := Run([]string{"inventory", "--state", statePath, "--json"}, &inventoryOut, &inventoryErr); code != 0 {
		t.Fatalf("inventory failed: code=%d stderr=%s", code, inventoryErr.String())
	}

	if exportOut.String() != inventoryOut.String() {
		t.Fatalf("inventory output drifted from export contract\nexport=%s\ninventory=%s", exportOut.String(), inventoryOut.String())
	}
}

func TestInventoryDiffReportsAddedRemovedChangedDeterministically(t *testing.T) {
	t.Parallel()

	baselinePath := writeWave2State(t, state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"mcp.access"},
				Evidence: []model.Evidence{
					{Key: "server", Value: "alpha"},
					{Key: "transport", Value: "stdio"},
				},
			},
			{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "cursor",
				Location:    ".cursor/mcp.json",
				Repo:        "local-machine",
				Org:         "local",
			},
			{
				FindingType: "secret_presence",
				Severity:    model.SeverityHigh,
				ToolType:    "secret",
				Location:    "process:env",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"env.read"},
			},
		},
	})

	currentPath := writeWave2State(t, state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"mcp.access"},
				Evidence: []model.Evidence{
					{Key: "server", Value: "beta"},
					{Key: "transport", Value: "stdio"},
				},
			},
			{
				FindingType: "secret_presence",
				Severity:    model.SeverityHigh,
				ToolType:    "secret",
				Location:    "process:env",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"env.read", "env.write"},
			},
		},
	})

	args := []string{"inventory", "--diff", "--baseline", baselinePath, "--state", currentPath, "--json"}
	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := Run(args, &firstOut, &firstErr); code != 5 {
		t.Fatalf("expected exit 5, got %d stderr=%s", code, firstErr.String())
	}

	var secondOut bytes.Buffer
	var secondErr bytes.Buffer
	if code := Run(args, &secondOut, &secondErr); code != 5 {
		t.Fatalf("expected exit 5 on repeat run, got %d stderr=%s", code, secondErr.String())
	}

	if firstOut.String() != secondOut.String() {
		t.Fatalf("inventory diff output was not deterministic\nfirst=%s\nsecond=%s", firstOut.String(), secondOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(firstOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse inventory diff payload: %v", err)
	}
	if payload["status"] != "drift" {
		t.Fatalf("expected drift status, got %v", payload["status"])
	}
	if payload["added_count"] != float64(1) || payload["removed_count"] != float64(2) || payload["changed_count"] != float64(1) {
		t.Fatalf("unexpected diff counts: %v", payload)
	}
}

func TestMCPListJSONStableRowsAndTrustStatus(t *testing.T) {
	t.Parallel()

	statePath := writeWave2State(t, mcpListFixtureSnapshot())
	overlayPath := filepath.Join(t.TempDir(), "trust.yaml")
	if err := os.WriteFile(overlayPath, []byte("servers:\n  alpha:\n    trust_status: trusted\n  beta:\n    trust_status: blocked\n"), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	args := []string{"mcp-list", "--state", statePath, "--gait-trust", overlayPath, "--json"}
	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := Run(args, &firstOut, &firstErr); code != 0 {
		t.Fatalf("mcp-list failed: code=%d stderr=%s", code, firstErr.String())
	}
	var secondOut bytes.Buffer
	var secondErr bytes.Buffer
	if code := Run(args, &secondOut, &secondErr); code != 0 {
		t.Fatalf("mcp-list repeat failed: code=%d stderr=%s", code, secondErr.String())
	}
	if firstOut.String() != secondOut.String() {
		t.Fatalf("mcp-list output was not deterministic\nfirst=%s\nsecond=%s", firstOut.String(), secondOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(firstOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse mcp-list payload: %v", err)
	}
	rows, ok := payload["rows"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("expected two rows, got %v", payload["rows"])
	}
	firstRow := rows[0].(map[string]any)
	secondRow := rows[1].(map[string]any)
	if firstRow["server_name"] != "alpha" || firstRow["trust_status"] != "trusted" {
		t.Fatalf("unexpected first row: %v", firstRow)
	}
	if secondRow["server_name"] != "beta" || secondRow["trust_status"] != "blocked" {
		t.Fatalf("unexpected second row: %v", secondRow)
	}
}

func TestMCPListWithoutGaitDegradesExplicitly(t *testing.T) {
	t.Parallel()

	statePath := writeWave2State(t, mcpListFixtureSnapshot())

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"mcp-list", "--state", statePath, "--gait-trust", filepath.Join(t.TempDir(), "missing.yaml"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("mcp-list failed: code=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse mcp-list payload: %v", err)
	}
	rows, ok := payload["rows"].([]any)
	if !ok || len(rows) == 0 {
		t.Fatalf("expected rows in payload: %v", payload)
	}
	firstRow := rows[0].(map[string]any)
	if firstRow["trust_status"] != "unavailable" {
		t.Fatalf("expected trust_status=unavailable, got %v", firstRow["trust_status"])
	}
	warnings, ok := payload["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected warning context for unavailable overlay, got %v", payload["warnings"])
	}
}

func TestMCPListWarnsWhenKnownMCPDeclarationFilesFailedToParse(t *testing.T) {
	t.Parallel()

	statePath := writeWave2State(t, state.Snapshot{
		Findings: []source.Finding{
			{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "claude",
				Location:    ".claude/settings.json",
				Repo:        "local-machine",
				Org:         "local",
			},
		},
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"mcp-list", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("mcp-list failed: code=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse mcp-list payload: %v", err)
	}
	rows, ok := payload["rows"].([]any)
	if !ok || len(rows) != 0 {
		t.Fatalf("expected zero rows, got %v", payload["rows"])
	}
	warnings, ok := payload["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected MCP visibility warning, got %v", payload["warnings"])
	}
	if got := warnings[0].(string); !strings.Contains(got, ".claude/settings.json") {
		t.Fatalf("expected warning to mention known MCP declaration path, got %q", got)
	}
}

func writeWave2State(t *testing.T, snapshot state.Snapshot) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(path, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	return path
}

func inventoryFixtureSnapshot() state.Snapshot {
	return state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
			Org:         "local",
			Agents: []agginventory.Agent{
				{
					AgentID:         "wrkr:wrkr:mcp:.mcp.json:local",
					AgentInstanceID: "wrkr:mcp:.mcp.json",
					Framework:       "mcp",
					Org:             "local",
					Repo:            "local-machine",
					Location:        ".mcp.json",
				},
			},
			Tools: []agginventory.Tool{
				{
					ToolID:       "wrkr:mcp:.mcp.json",
					AgentID:      "wrkr:wrkr:mcp:.mcp.json:local",
					ToolType:     "mcp",
					ToolCategory: "mcp_integration",
					Org:          "local",
					Repos:        []string{"local-machine"},
					Locations: []agginventory.ToolLocation{
						{Repo: "local-machine", Location: ".mcp.json", Owner: "developer"},
					},
				},
			},
		},
	}
}

func mcpListFixtureSnapshot() state.Snapshot {
	return state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
			Org:         "local",
			Tools: []agginventory.Tool{
				{
					ToolID:       "wrkr:mcp:.mcp.json",
					AgentID:      "wrkr:wrkr:mcp:.mcp.json:local",
					ToolType:     "mcp",
					ToolCategory: "mcp_integration",
					Org:          "local",
					Locations: []agginventory.ToolLocation{
						{Repo: "local-machine", Location: ".mcp.json", Owner: "developer"},
					},
					Permissions: []string{"mcp.access"},
					PermissionSurface: agginventory.PermissionSurface{
						Read:  true,
						Write: true,
					},
				},
			},
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"mcp.access"},
				Evidence: []model.Evidence{
					{Key: "server", Value: "beta"},
					{Key: "transport", Value: "stdio"},
				},
			},
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"mcp.access"},
				Evidence: []model.Evidence{
					{Key: "server", Value: "alpha"},
					{Key: "transport", Value: "stdio"},
				},
			},
			{
				FindingType: "mcp_gateway_posture",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Evidence: []model.Evidence{
					{Key: "declaration_name", Value: "alpha"},
					{Key: "coverage", Value: "unprotected"},
				},
			},
			{
				FindingType: "mcp_gateway_posture",
				Severity:    model.SeverityLow,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Evidence: []model.Evidence{
					{Key: "declaration_name", Value: "beta"},
					{Key: "coverage", Value: "protected"},
				},
			},
		},
	}
}
