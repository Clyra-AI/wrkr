package agentlangchain

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestLangChainDetector_PrecisionFixtures(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/langchain.json", `{
  "agents": [
    {
      "name": "triage_agent",
      "file": "agents/triage.py",
      "start_line": 12,
      "end_line": 24,
      "tools": ["search.read", "kb.write"],
      "data_sources": ["postgres.analytics"],
      "auth_surfaces": ["oauth2"],
      "deployment_artifacts": [".github/workflows/release.yml"],
      "data_class": "internal",
      "approval_status": "approved",
      "kill_switch": true,
      "human_gate": true
    }
  ]
}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "backend", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	f := findings[0]
	if f.FindingType != "agent_framework" {
		t.Fatalf("expected agent_framework, got %q", f.FindingType)
	}
	if f.ToolType != "langchain" {
		t.Fatalf("expected tool_type=langchain, got %q", f.ToolType)
	}
	if f.Location != "agents/triage.py" {
		t.Fatalf("unexpected location %q", f.Location)
	}
	if evidenceValue(f.Evidence, "symbol") != "triage_agent" {
		t.Fatalf("expected symbol evidence, got %q", evidenceValue(f.Evidence, "symbol"))
	}
	if evidenceValue(f.Evidence, "bound_tools") != "kb.write,search.read" {
		t.Fatalf("unexpected bound_tools evidence %q", evidenceValue(f.Evidence, "bound_tools"))
	}
}

func TestLangChainDetector_SourceOnlyRepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "agents/langchain_agent.py", `from langchain.agents import create_react_agent
import os

planner = create_react_agent(
    llm=llm,
    tools=["search.read", "deploy.write"],
    name="planner_agent",
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "backend", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one source finding, got %d", len(findings))
	}
	if findings[0].Location != "agents/langchain_agent.py" {
		t.Fatalf("unexpected location %q", findings[0].Location)
	}
	if evidenceValue(findings[0].Evidence, "symbol") != "planner_agent" {
		t.Fatalf("unexpected symbol %q", evidenceValue(findings[0].Evidence, "symbol"))
	}
	if evidenceValue(findings[0].Evidence, "auth_surfaces") != "OPENAI_API_KEY" {
		t.Fatalf("unexpected auth surfaces %q", evidenceValue(findings[0].Evidence, "auth_surfaces"))
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func evidenceValue(evidence []model.Evidence, key string) string {
	for _, item := range evidence {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}
