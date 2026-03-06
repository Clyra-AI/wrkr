package agentllamaindex

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestLlamaIndexDetector_PrecisionBaseline(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/llamaindex.yaml", `agents:
  - name: index_agent
    file: agents/index.py
    data_sources: [vector.rag]
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "search", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ToolType != "llamaindex" {
		t.Fatalf("expected llamaindex tool type, got %q", findings[0].ToolType)
	}
}

func TestLlamaIndexDetector_ExpandedFormatsDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/llamaindex.json", `{"agents":[{"name":"json_agent","file":"agents/json.py"}]}`)
	writeFile(t, root, ".wrkr/agents/llamaindex.toml", `[[agents]]
name = "toml_agent"
file = "agents/toml.py"
`)

	scope := detect.Scope{Org: "acme", Repo: "search", Root: root}
	first, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("expected two findings from json+toml declarations, got %d", len(first))
	}
	for _, finding := range first {
		if finding.ToolType != "llamaindex" {
			t.Fatalf("unexpected tool type %q", finding.ToolType)
		}
		if finding.FindingType != "agent_framework" {
			t.Fatalf("unexpected finding type %q", finding.FindingType)
		}
	}
	for i := 0; i < 10; i++ {
		next, err := New().Detect(context.Background(), scope, detect.Options{})
		if err != nil {
			t.Fatalf("detect run %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic output at run %d", i+1)
		}
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
