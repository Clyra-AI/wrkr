package dependency

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectSkipsIgnoredUnreadableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}

	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/repo\n\ngo 1.25.7\nrequire github.com/openai/openai-go v0.1.0\n")

	ignoredDir := filepath.Join(root, "node_modules")
	if err := os.MkdirAll(filepath.Join(ignoredDir, "pkg"), 0o755); err != nil {
		t.Fatalf("mkdir ignored dir: %v", err)
	}
	writeFile(t, root, "node_modules/pkg/package.json", "{")

	if err := os.Chmod(ignoredDir, 0o000); err != nil {
		t.Fatalf("chmod ignored dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(ignoredDir, 0o755)
	})

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from go.mod")
	}
}

func TestProjectSignalUsesTokenBoundaries(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "README.md", "Storage management utilities.")

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "storage-service",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no project signal findings, got %d", len(findings))
	}
}

func TestProjectSignalMatchesExplicitToken(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "README.md", "This repository contains an agent runtime.")

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "platform-service",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one project signal finding, got %d", len(findings))
	}
	if findings[0].FindingType != "ai_project_signal" {
		t.Fatalf("expected ai_project_signal finding, got %s", findings[0].FindingType)
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
