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
