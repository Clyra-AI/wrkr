package local

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

type recordingPathProgress struct {
	events []string
}

func (p *recordingPathProgress) PathDiscovery(root string, total int) {
	p.events = append(p.events, "discovery:"+filepath.ToSlash(root)+":"+strconv.Itoa(total))
}

func (p *recordingPathProgress) PathRepo(_ string, index, total int, repo string) {
	p.events = append(p.events, "repo:"+strconv.Itoa(index)+":"+strconv.Itoa(total)+":"+repo)
}

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

func TestAcquireDiscoversNestedOrgCloneRepos(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	for _, repo := range []string{"Activity-Insights/api", "Activity-Insights/web"} {
		if err := os.MkdirAll(filepath.Join(tmp, repo, ".codex"), 0o755); err != nil {
			t.Fatalf("mkdir repo %s: %v", repo, err)
		}
		if err := os.WriteFile(filepath.Join(tmp, repo, "AGENTS.md"), []byte("agent\n"), 0o600); err != nil {
			t.Fatalf("write repo signal: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module parent\n"), 0o600); err != nil {
		t.Fatalf("write parent signal: %v", err)
	}

	repos, err := Acquire(tmp)
	if err != nil {
		t.Fatalf("acquire nested org clone: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected nested repo roots, got %+v", repos)
	}
	if repos[0].Repo != "Activity-Insights/api" || repos[1].Repo != "Activity-Insights/web" {
		t.Fatalf("unexpected nested repo identities: %+v", repos)
	}
}

func TestAcquireKeepsGitRootAsSingleRepo(t *testing.T) {
	t.Parallel()

	tmp := filepath.Join(t.TempDir(), "monorepo")
	if err := os.MkdirAll(filepath.Join(tmp, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "examples", "agent", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir nested example: %v", err)
	}

	repos, err := Acquire(tmp)
	if err != nil {
		t.Fatalf("acquire git root: %v", err)
	}
	if len(repos) != 1 || repos[0].Repo != "monorepo" {
		t.Fatalf("expected git root to stay a single repo, got %+v", repos)
	}
}

func TestAcquireWithOptionsReportsPathProgress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir alpha: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "beta", ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir beta: %v", err)
	}
	progress := &recordingPathProgress{}

	repos, err := AcquireWithOptions(context.Background(), tmp, AcquireOptions{Progress: progress})
	if err != nil {
		t.Fatalf("acquire with progress: %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected two repos, got %+v", repos)
	}
	events := strings.Join(progress.events, "\n")
	for _, want := range []string{"discovery:", "repo:1:2:alpha", "repo:2:2:beta"} {
		if !strings.Contains(events, want) {
			t.Fatalf("expected progress %q, got:\n%s", want, events)
		}
	}
}

func TestAcquireIgnoresUnreadableRepoRootSignalProbe(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission fixture is not portable on windows")
	}

	tmp := t.TempDir()
	for _, name := range []string{"zeta", "alpha"} {
		if err := os.MkdirAll(filepath.Join(tmp, name), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}

	lockedSignalDir := filepath.Join(tmp, ".vscode")
	if err := os.MkdirAll(lockedSignalDir, 0o700); err != nil {
		t.Fatalf("mkdir locked signal dir: %v", err)
	}
	if err := os.Chmod(lockedSignalDir, 0o600); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(lockedSignalDir, 0o700)
	}()

	repos, err := Acquire(tmp)
	if err != nil {
		t.Fatalf("expected unreadable optional signal probe to be ignored, got %v", err)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %d (%+v)", len(repos), repos)
	}
	if repos[0].Repo != "alpha" || repos[1].Repo != "zeta" {
		t.Fatalf("unexpected order: %+v", repos)
	}
}
