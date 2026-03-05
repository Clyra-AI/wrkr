package agentautogen

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestAutoGenDetector_PrecisionBaseline(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/autogen.json", `{
  "agents": [
    {
      "name": "ops_autogen",
      "file": "agents/autogen_ops.py",
      "tools": ["search.read"],
      "auth_surfaces": ["token"]
    }
  ]
}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "platform", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].ToolType != "autogen" {
		t.Fatalf("expected autogen tool type, got %q", findings[0].ToolType)
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
