package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestSecretsDetectorRejectsExternalSymlinkedEnv(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, ".env")
	if err := os.WriteFile(target, []byte("OPENAI_API_KEY=redacted\n"), 0o600); err != nil {
		t.Fatalf("write outside env: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".env")); err != nil {
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
