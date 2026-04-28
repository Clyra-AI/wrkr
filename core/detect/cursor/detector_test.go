package cursor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectRejectsExternalSymlinkedCursorRule(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	writeCursorFile(t, outside, "deploy.mdc", strings.Join([]string{
		"---",
		"description: external",
		"alwaysApply: true",
		"---",
		"",
		"# Deploy",
	}, "\n"))
	mustSymlinkOrSkipCursor(t, filepath.Join(outside, "deploy.mdc"), filepath.Join(root, ".cursor", "rules", "deploy.mdc"))

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect cursor: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse error finding, got %#v", findings)
	}
	if findings[0].FindingType != "parse_error" || findings[0].ParseError == nil || findings[0].ParseError.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path parse error, got %#v", findings)
	}
}

func writeCursorFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func mustSymlinkOrSkipCursor(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink parent: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}
}
