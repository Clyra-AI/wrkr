package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--approved-tools", approvedPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"}, &out, &errOut)
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
