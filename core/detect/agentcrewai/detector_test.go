package agentcrewai

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestCrewAIDetector_DeterministicOrdering(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/crewai.yaml", `agents:
  - name: zeta_agent
    file: crews/zeta.py
    tools: [alpha.read]
    human_gate: true
  - name: alpha_agent
    file: crews/alpha.py
    tools: [zeta.write]
    auto_deploy: true
    human_gate: false
`)

	detector := New()
	scope := detect.Scope{Org: "acme", Repo: "ops", Root: root}

	first, err := detector.Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect first: %v", err)
	}
	second, err := detector.Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect second: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic output ordering\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first) != 2 {
		t.Fatalf("expected two findings, got %d", len(first))
	}
	if first[0].Location != "crews/alpha.py" || first[1].Location != "crews/zeta.py" {
		t.Fatalf("unexpected deterministic ordering: %+v", []string{first[0].Location, first[1].Location})
	}
	if first[0].Severity != model.SeverityHigh {
		t.Fatalf("expected auto_deploy without gate to be high severity, got %q", first[0].Severity)
	}
}

func TestCrewAIDetector_SourceOnlyRepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "crews/ops.py", `from crewai import Agent
import os

researcher = Agent(
    role="research_agent",
    tools=["search.read"],
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "ops", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one source finding, got %d", len(findings))
	}
	if findings[0].Location != "crews/ops.py" {
		t.Fatalf("unexpected location %q", findings[0].Location)
	}
	if evidenceValue(findings[0].Evidence, "symbol") != "research_agent" {
		t.Fatalf("unexpected symbol %q", evidenceValue(findings[0].Evidence, "symbol"))
	}
	if evidenceValue(findings[0].Evidence, "data_sources") != "warehouse.events" {
		t.Fatalf("unexpected data_sources %q", evidenceValue(findings[0].Evidence, "data_sources"))
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
