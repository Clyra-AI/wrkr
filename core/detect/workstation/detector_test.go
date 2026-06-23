package workstation

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectLocalMachineEnvAndProjectSignals(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("OPENAI_API_KEY", "redacted")
	t.Setenv("ANTHROPIC_API_KEY", "redacted")

	projectRoot := filepath.Join(home, "Projects", "demo-agent")
	if err := os.MkdirAll(filepath.Join(projectRoot, ".agents", "skills"), 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "AGENTS.md"), []byte("agent"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "bob.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatalf("write bob.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".wrkr", "provenance", "source-metadata.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write source metadata: %v", err)
	}

	scopeRoot := filepath.Join(home, ".wrkr-local-machine")
	if err := os.MkdirAll(scopeRoot, 0o755); err != nil {
		t.Fatalf("mkdir scope root: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:        "local",
		Repo:       "local-machine",
		Root:       scopeRoot,
		TargetMode: "my_setup",
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect workstation: %v", err)
	}
	if len(findings) < 2 {
		t.Fatalf("expected workstation findings, got %d", len(findings))
	}

	foundEnv := false
	foundProject := false
	foundFactory := false
	foundHandoff := false
	for _, finding := range findings {
		switch {
		case finding.Location == "process:env":
			foundEnv = true
		case finding.ToolType == "codex":
			foundProject = true
		case finding.FindingType == "agentic_factory" && finding.ToolType == "agentic_factory":
			foundFactory = true
		case finding.FindingType == "local_pr_handoff" && finding.ToolType == "local_pr_handoff":
			foundHandoff = true
		}
	}
	if !foundEnv {
		t.Fatal("expected process env finding")
	}
	if !foundProject {
		t.Fatal("expected agent project finding")
	}
	if !foundFactory {
		t.Fatal("expected local agentic factory finding")
	}
	if !foundHandoff {
		t.Fatal("expected local PR handoff finding")
	}
}
