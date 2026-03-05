package agentopenai

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
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
