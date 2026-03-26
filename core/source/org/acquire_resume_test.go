package org

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

type trackingMaterializer struct {
	t        *testing.T
	root     string
	delays   map[string]time.Duration
	failRepo string

	mu            sync.Mutex
	inFlight      int
	maxConcurrent int
	callCount     int
}

func (m *trackingMaterializer) MaterializeRepo(ctx context.Context, repo string, materializedRoot string) (source.RepoManifest, error) {
	m.mu.Lock()
	m.callCount++
	m.inFlight++
	if m.inFlight > m.maxConcurrent {
		m.maxConcurrent = m.inFlight
	}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.inFlight--
		m.mu.Unlock()
	}()

	if delay := m.delays[repo]; delay > 0 {
		select {
		case <-ctx.Done():
			return source.RepoManifest{}, ctx.Err()
		case <-time.After(delay):
		}
	}
	if repo == m.failRepo {
		return source.RepoManifest{}, errors.New("boom")
	}

	location := filepath.Join(materializedRoot, filepath.FromSlash(repo))
	if err := os.MkdirAll(location, 0o750); err != nil {
		m.t.Fatalf("mkdir materialized repo %s: %v", repo, err)
	}
	return source.RepoManifest{
		Repo:     repo,
		Location: filepath.ToSlash(location),
		Source:   "github_repo_materialized",
	}, nil
}

func TestAcquireMaterializedUsesBoundedConcurrencyAndDeterministicOrder(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	materializer := &trackingMaterializer{
		t:    t,
		root: materializedRoot,
		delays: map[string]time.Duration{
			"acme/a": 35 * time.Millisecond,
			"acme/b": 5 * time.Millisecond,
			"acme/c": 20 * time.Millisecond,
			"acme/d": 10 * time.Millisecond,
		},
	}

	repos, failures, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/d", "acme/b", "acme/a", "acme/c"}},
		materializer,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			WorkerCount:      2,
		},
	)
	if err != nil {
		t.Fatalf("acquire materialized: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("expected no failures, got %+v", failures)
	}
	if len(repos) != 4 {
		t.Fatalf("expected 4 repos, got %d", len(repos))
	}
	for i, want := range []string{"acme/a", "acme/b", "acme/c", "acme/d"} {
		if repos[i].Repo != want {
			t.Fatalf("expected repo %d to be %s, got %+v", i, want, repos)
		}
	}
	if materializer.maxConcurrent != 2 {
		t.Fatalf("expected bounded concurrency of 2, got %d", materializer.maxConcurrent)
	}
}

func TestAcquireMaterializedResumeReusesCompletedRepos(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	first := &trackingMaterializer{t: t, root: materializedRoot}
	if _, _, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a", "acme/b"}},
		first,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			WorkerCount:      1,
		},
	); err != nil {
		t.Fatalf("initial acquire materialized: %v", err)
	}

	second := &trackingMaterializer{t: t, root: materializedRoot}
	repos, failures, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a", "acme/b"}},
		second,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			Resume:           true,
			WorkerCount:      1,
		},
	)
	if err != nil {
		t.Fatalf("resume acquire materialized: %v", err)
	}
	if len(failures) != 0 {
		t.Fatalf("expected no failures, got %+v", failures)
	}
	if len(repos) != 2 {
		t.Fatalf("expected 2 repos, got %+v", repos)
	}
	if second.callCount != 0 {
		t.Fatalf("expected resume to reuse completed repos, got %d materializer calls", second.callCount)
	}
}

func TestAcquireMaterializedResumeMismatchFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	materializer := &trackingMaterializer{t: t, root: materializedRoot}
	if _, _, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a"}},
		materializer,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			WorkerCount:      1,
		},
	); err != nil {
		t.Fatalf("initial acquire materialized: %v", err)
	}

	_, _, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a", "acme/b"}},
		materializer,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			Resume:           true,
			WorkerCount:      1,
		},
	)
	if err == nil {
		t.Fatal("expected resume mismatch to fail")
	}
	if !IsCheckpointInputError(err) {
		t.Fatalf("expected checkpoint input error, got %v", err)
	}
}

func TestAcquireMaterializedResumeRejectsSymlinkedRepoRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	first := &trackingMaterializer{t: t, root: materializedRoot}
	if _, _, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a"}},
		first,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			WorkerCount:      1,
		},
	); err != nil {
		t.Fatalf("initial acquire materialized: %v", err)
	}

	location := filepath.Join(materializedRoot, "acme", "a")
	if err := os.RemoveAll(location); err != nil {
		t.Fatalf("remove materialized repo: %v", err)
	}
	outside := filepath.Join(tmp, "outside-repo")
	if err := os.MkdirAll(outside, 0o750); err != nil {
		t.Fatalf("mkdir outside repo: %v", err)
	}
	if err := os.Symlink(outside, location); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	second := &trackingMaterializer{t: t, root: materializedRoot}
	_, _, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a"}},
		second,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			Resume:           true,
			WorkerCount:      1,
		},
	)
	if err == nil {
		t.Fatal("expected symlinked resume repo root to fail")
	}
	if !IsCheckpointSafetyError(err) {
		t.Fatalf("expected checkpoint safety error, got %v", err)
	}
	if second.callCount != 0 {
		t.Fatalf("expected no materializer calls on rejected resume root, got %d", second.callCount)
	}
}

func TestAcquireMaterializedResumeRejectsSymlinkedCheckpointFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	first := &trackingMaterializer{t: t, root: materializedRoot}
	if _, _, err := AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a"}},
		first,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			WorkerCount:      1,
		},
	); err != nil {
		t.Fatalf("initial acquire materialized: %v", err)
	}

	checkpointFile, err := checkpointPath(statePath, "acme")
	if err != nil {
		t.Fatalf("checkpoint path: %v", err)
	}
	external := filepath.Join(tmp, "external-checkpoint.json")
	if err := os.WriteFile(external, []byte("{\"version\":\"v1\",\"org\":\"acme\",\"materialized_root\":\"materialized-sources\",\"repos\":[\"acme/a\"],\"completed_repos\":[\"acme/a\"]}\n"), 0o600); err != nil {
		t.Fatalf("write external checkpoint: %v", err)
	}
	if err := os.Remove(checkpointFile); err != nil {
		t.Fatalf("remove checkpoint file: %v", err)
	}
	if err := os.Symlink(external, checkpointFile); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	second := &trackingMaterializer{t: t, root: materializedRoot}
	_, _, err = AcquireMaterialized(
		context.Background(),
		"acme",
		fakeLister{repos: []string{"acme/a"}},
		second,
		AcquireMaterializedOptions{
			StatePath:        statePath,
			MaterializedRoot: materializedRoot,
			Resume:           true,
			WorkerCount:      1,
		},
	)
	if err == nil {
		t.Fatal("expected symlinked checkpoint file to fail")
	}
	if !IsCheckpointSafetyError(err) {
		t.Fatalf("expected checkpoint safety error, got %v", err)
	}
}

func TestCheckpointWriteRemainsAtomicOnInterruptedRename(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	path, err := checkpointPath(statePath, "acme")
	if err != nil {
		t.Fatalf("checkpoint path: %v", err)
	}
	manager := newCheckpointManager(path, "acme", []string{"acme/a"}, filepath.Join(tmp, "materialized-sources"))
	if err := manager.save(); err != nil {
		t.Fatalf("save initial checkpoint: %v", err)
	}

	restore := atomicwrite.SetBeforeRenameHookForTest(func(path string, _ string) error {
		if path == manager.path {
			return errors.New("interrupt before rename")
		}
		return nil
	})
	defer restore()

	if err := manager.markCompleted("acme/a"); err == nil {
		t.Fatal("expected interrupted checkpoint write to fail")
	}

	loaded, err := loadCheckpointManager(manager.path)
	if err != nil {
		t.Fatalf("load checkpoint after interrupted write: %v", err)
	}
	if len(loaded.state.CompletedRepos) != 0 {
		t.Fatalf("expected checkpoint file to remain on previous committed state, got %+v", loaded.state.CompletedRepos)
	}
}
