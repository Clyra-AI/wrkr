package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanPayload_IncludesAgentBindings(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "agents-repo")
	if err := os.MkdirAll(filepath.Join(repoPath, ".wrkr", "agents"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	payload := []byte(`{
  "agents": [
    {
      "name": "release_agent",
      "file": "agents/release.py",
      "tools": ["deploy.write", "search.read"],
      "data_sources": ["warehouse.events"],
      "auth_surfaces": ["oauth2", "token"],
      "deployment_artifacts": [".github/workflows/release.yml"],
      "auto_deploy": true,
      "human_gate": false
    }
  ]
}`)
	if err := os.WriteFile(filepath.Join(repoPath, ".wrkr", "agents", "langchain.json"), payload, 0o600); err != nil {
		t.Fatalf("write framework declaration: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var scan map[string]any
	if err := json.Unmarshal(out.Bytes(), &scan); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	inventoryObj, ok := scan["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("missing inventory payload: %v", scan)
	}
	agents, ok := inventoryObj["agents"].([]any)
	if !ok || len(agents) == 0 {
		t.Fatalf("expected non-empty agents payload: %v", inventoryObj["agents"])
	}
	first, ok := agents[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected agent payload shape: %T", agents[0])
	}
	if _, exists := first["bound_tools"]; !exists {
		t.Fatalf("expected bound_tools in agent payload: %v", first)
	}
	if _, exists := first["bound_data_sources"]; !exists {
		t.Fatalf("expected bound_data_sources in agent payload: %v", first)
	}
	if _, exists := first["bound_auth_surfaces"]; !exists {
		t.Fatalf("expected bound_auth_surfaces in agent payload: %v", first)
	}
	if status := first["deployment_status"]; status != "deployed" {
		t.Fatalf("expected deployment_status=deployed, got %v", status)
	}
}
