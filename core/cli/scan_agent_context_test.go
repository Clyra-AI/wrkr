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

func TestScanPayload_SourceOnlyFrameworkRepoIncludesAgentContext(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "source-agents")
	if err := os.MkdirAll(filepath.Join(repoPath, "agents"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	payload := []byte(`from crewai import Agent
import os

researcher = Agent(
    role="research_agent",
    tools=["search.read"],
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)
`)
	if err := os.WriteFile(filepath.Join(repoPath, "agents", "crew.py"), payload, 0o600); err != nil {
		t.Fatalf("write framework source: %v", err)
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
	if first["symbol"] != "research_agent" {
		t.Fatalf("expected symbol=research_agent, got %v", first["symbol"])
	}
	if first["security_visibility_status"] != "unknown_to_security" {
		t.Fatalf("expected security_visibility_status=unknown_to_security on initial source scan, got %v", first["security_visibility_status"])
	}
	if _, exists := first["bound_tools"]; !exists {
		t.Fatalf("expected bound_tools in source-derived agent payload: %v", first)
	}
	if _, exists := first["bound_auth_surfaces"]; !exists {
		t.Fatalf("expected bound_auth_surfaces in source-derived agent payload: %v", first)
	}
	visibilitySummary, ok := inventoryObj["security_visibility_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected security_visibility_summary in inventory payload: %v", inventoryObj)
	}
	if visibilitySummary["reference_basis"] != "initial_scan" {
		t.Fatalf("unexpected visibility summary basis: %v", visibilitySummary)
	}
}

func TestScanPayload_SourceOnlyMultiAgentFileProducesSeparatePrivilegeRows(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "source-agents")
	if err := os.MkdirAll(filepath.Join(repoPath, "agents"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	payload := []byte(`from crewai import Agent
import os

researcher = Agent(
    role="research_agent",
    tools=["search.read"],
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)

publisher = Agent(
    role="publisher_agent",
    tools=["deploy.write"],
    data_sources=["prod-db"],
    auth_surfaces=[os.getenv("GITHUB_TOKEN")],
)
`)
	if err := os.WriteFile(filepath.Join(repoPath, "agents", "crew.py"), payload, 0o600); err != nil {
		t.Fatalf("write framework source: %v", err)
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
	agentMap, ok := scan["agent_privilege_map"].([]any)
	if !ok || len(agentMap) < 2 {
		t.Fatalf("expected privilege rows in payload, got %v", scan["agent_privilege_map"])
	}
	filtered := make([]map[string]any, 0, len(agentMap))
	for _, raw := range agentMap {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("unexpected agent map entry type %T", raw)
		}
		if entry["framework"] == "crewai" {
			filtered = append(filtered, entry)
		}
	}
	if len(filtered) != 2 {
		t.Fatalf("expected exactly two crewai privilege rows, got %v", filtered)
	}
	first := filtered[0]
	second := filtered[1]
	if first["agent_instance_id"] == second["agent_instance_id"] {
		t.Fatalf("expected distinct agent_instance_id values, got %v and %v", first["agent_instance_id"], second["agent_instance_id"])
	}
	if first["write_capable"] == second["write_capable"] {
		t.Fatalf("expected different write_capable values for read vs write agent rows, got %v and %v", first["write_capable"], second["write_capable"])
	}
}
