package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/state"
)

func TestScanMySetupBuildsLocalGovernanceSummary(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpHome, ".cursor"), 0o755); err != nil {
		t.Fatalf("mkdir cursor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".cursor", "mcp.json"), []byte(`{"mcpServers":{"demo":{"command":"npx","args":["-y","demo@1"]}}}`), 0o600); err != nil {
		t.Fatalf("write cursor config: %v", err)
	}

	approvedPath := filepath.Join(t.TempDir(), "approved-tools.yaml")
	if err := os.WriteFile(approvedPath, []byte(`
schema_version: v1
approved:
  tool_types:
    exact: ["codex", "mcp"]
`), 0o600); err != nil {
		t.Fatalf("write approved tools policy: %v", err)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--approved-tools", approvedPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryObj, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	localGov, ok := inventoryObj["local_governance"].(map[string]any)
	if !ok {
		t.Fatalf("expected local_governance summary, got %v", inventoryObj["local_governance"])
	}
	if localGov["sanctioned_tools"] != float64(2) || localGov["unsanctioned_tools"] != float64(1) {
		t.Fatalf("unexpected local governance summary: %v", localGov)
	}

	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if snapshot.Inventory == nil || snapshot.RiskReport == nil {
		t.Fatalf("expected inventory and risk report in snapshot")
	}
	if len(snapshot.Inventory.RepoExposureSummaries) != 1 || len(snapshot.RiskReport.Repos) != 1 {
		t.Fatalf("expected one local repo summary and one repo risk entry, got %d and %d", len(snapshot.Inventory.RepoExposureSummaries), len(snapshot.RiskReport.Repos))
	}
	if got, want := snapshot.Inventory.RepoExposureSummaries[0].CombinedRiskScore, snapshot.RiskReport.Repos[0].Score; got != want {
		t.Fatalf("expected repo exposure score %.2f to match final repo risk %.2f", got, want)
	}
}

func TestScanMySetupMarksLocalGovernanceUnavailableWithoutApprovedTools(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--state", filepath.Join(t.TempDir(), "state.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryObj, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	localGov, ok := inventoryObj["local_governance"].(map[string]any)
	if !ok {
		t.Fatalf("expected local_governance summary, got %v", inventoryObj["local_governance"])
	}
	if localGov["reference_basis"] != "unavailable" {
		t.Fatalf("expected unavailable local governance reference, got %v", localGov)
	}
}

func TestScanMixedMySetupKeepsLocalGovernanceScopedToLocalMachine(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpHome, ".cursor"), 0o755); err != nil {
		t.Fatalf("mkdir cursor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".cursor", "mcp.json"), []byte(`{"mcpServers":{"demo":{"command":"npx","args":["-y","demo@1"]}}}`), 0o600); err != nil {
		t.Fatalf("write cursor config: %v", err)
	}

	scanRoot := t.TempDir()
	repoRoot := filepath.Join(scanRoot, "service")
	if err := os.MkdirAll(filepath.Join(repoRoot, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir repo claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, ".claude", "settings.json"), []byte(`{"env":{"FOO":"bar"}}`), 0o600); err != nil {
		t.Fatalf("write repo claude settings: %v", err)
	}

	approvedPath := filepath.Join(t.TempDir(), "approved-tools.yaml")
	if err := os.WriteFile(approvedPath, []byte(`
schema_version: v1
approved:
  tool_types:
    exact: ["codex", "mcp"]
`), 0o600); err != nil {
		t.Fatalf("write approved tools policy: %v", err)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--target", "my_setup:local-machine",
		"--target", "path:" + scanRoot,
		"--approved-tools", approvedPath,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryObj, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	localGov, ok := inventoryObj["local_governance"].(map[string]any)
	if !ok {
		t.Fatalf("expected local_governance summary, got %v", inventoryObj["local_governance"])
	}
	if localGov["sanctioned_tools"] != float64(2) || localGov["unsanctioned_tools"] != float64(1) {
		t.Fatalf("expected mixed scan local governance to count only local-machine tools, got %v", localGov)
	}

	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if snapshot.Inventory == nil || snapshot.Inventory.LocalGovernance == nil {
		t.Fatalf("expected local governance summary in snapshot inventory")
	}
	if snapshot.Inventory.LocalGovernance.SanctionedTools != 2 || snapshot.Inventory.LocalGovernance.UnsanctionedTools != 1 {
		t.Fatalf("unexpected snapshot local governance summary: %+v", snapshot.Inventory.LocalGovernance)
	}
}
