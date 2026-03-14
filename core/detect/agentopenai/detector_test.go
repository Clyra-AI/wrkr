package agentopenai

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestOpenAIAgentsDetector_ParseErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/openai-agents.json", `{"agents":[{"name":"release","file":"agents/release.py",]}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "release", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse error finding, got %d", len(findings))
	}
	if findings[0].FindingType != "parse_error" {
		t.Fatalf("expected parse_error, got %q", findings[0].FindingType)
	}
	if findings[0].ParseError == nil {
		t.Fatal("expected parse_error payload")
	}
	if findings[0].ParseError.Format != "json" {
		t.Fatalf("expected json parse error format, got %q", findings[0].ParseError.Format)
	}
	if findings[0].Detector != "agentopenai" {
		t.Fatalf("expected detector=agentopenai, got %q", findings[0].Detector)
	}
}

func TestOpenAIAgentsDetector_SourceOnlyRepo(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "agents/router.ts", `import { Agent } from "@openai/agents";

const triage = new Agent({
  name: "triage_agent",
  tools: ["ticket.write", "search.read"],
  dataSources: ["crm.records"],
  auth: [process.env.OPENAI_API_KEY],
});
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "release", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one source finding, got %d", len(findings))
	}
	if findings[0].Location != "agents/router.ts" {
		t.Fatalf("unexpected location %q", findings[0].Location)
	}
	if evidenceValue(findings[0].Evidence, "symbol") != "triage_agent" {
		t.Fatalf("unexpected symbol %q", evidenceValue(findings[0].Evidence, "symbol"))
	}
	if evidenceValue(findings[0].Evidence, "bound_tools") != "search.read,ticket.write" {
		t.Fatalf("unexpected bound_tools %q", evidenceValue(findings[0].Evidence, "bound_tools"))
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
