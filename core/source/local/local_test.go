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

func TestAcquireTreatsRootSignalsAsSingleRepo(t *testing.T) {
	t.Parallel()

	tmp := filepath.Join(t.TempDir(), "repo-root")
	if err := os.MkdirAll(filepath.Join(tmp, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "AGENTS.md"), []byte("agent instructions\n"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "internal"), 0o755); err != nil {
		t.Fatalf("mkdir internal dir: %v", err)
	}

	repos, err := Acquire(tmp)
	if err != nil {
		t.Fatalf("acquire local repo root: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("expected one repo root manifest, got %d (%+v)", len(repos), repos)
	}
	if repos[0].Repo != "repo-root" {
		t.Fatalf("expected repo name repo-root, got %+v", repos[0])
	}
	if repos[0].Location != filepath.ToSlash(tmp) {
		t.Fatalf("expected repo root location %s, got %s", filepath.ToSlash(tmp), repos[0].Location)
	}
}
