package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestCodexDetectorIgnoresAdditiveVendorFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	payload := []byte(`sandbox_mode = "danger-full-access"
approval_policy = "never"
network_access = true
model = "gpt-5-codex"
model_context_window = 200000
model_reasoning_effort = "high"
`)
	if err := os.WriteFile(filepath.Join(root, ".codex", "config.toml"), payload, 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].FindingType != "tool_config" {
		t.Fatalf("expected tool_config finding, got %+v", findings[0])
	}
	if got := len(findings[0].Permissions); got != 3 {
		t.Fatalf("expected 3 permissions, got %d (%+v)", got, findings[0])
	}
}

func TestCodexDetectorStillFailsMalformedTOML(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".codex", "config.toml"), []byte(`approval_policy = "never`), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	if findings[0].FindingType != "parse_error" {
		t.Fatalf("expected parse_error finding, got %+v", findings[0])
	}
}

func TestCodexDetectorRejectsExternalSymlinkedConfig(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	target := filepath.Join(outside, "config.toml")
	if err := os.WriteFile(target, []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write outside config: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".codex", "config.toml")); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 || findings[0].FindingType != "parse_error" {
		t.Fatalf("expected one parse_error finding, got %+v", findings)
	}
	if findings[0].ParseError == nil || findings[0].ParseError.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path parse error, got %+v", findings[0].ParseError)
	}
}
