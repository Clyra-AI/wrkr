package local

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAcquirePathRepos(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "zeta"), 0o755); err != nil {
		t.Fatalf("mkdir zeta: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "README.md"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	repos, err := Acquire(tmp)
	if err != nil {
		t.Fatalf("acquire local repos: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d", len(repos))
	}
	if repos[0].Repo != "alpha" || repos[1].Repo != "zeta" {
		t.Fatalf("unexpected order: %+v", repos)
	}
}
