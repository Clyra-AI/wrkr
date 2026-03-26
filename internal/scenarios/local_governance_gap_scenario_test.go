//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalGovernanceGapScenario(t *testing.T) {
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

	payload := runScenarioCommandJSON(t, []string{"scan", "--my-setup", "--approved-tools", approvedPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})
	inventoryObj, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	localGov, ok := inventoryObj["local_governance"].(map[string]any)
	if !ok {
		t.Fatalf("expected local governance summary, got %v", inventoryObj["local_governance"])
	}
	if localGov["unsanctioned_tools"] != float64(1) {
		t.Fatalf("expected one unsanctioned tool, got %v", localGov)
	}
}
