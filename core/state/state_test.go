package state

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestResolvePath(t *testing.T) {
	if got := ResolvePath("/tmp/custom.json"); got != "/tmp/custom.json" {
		t.Fatalf("unexpected explicit path: %q", got)
	}

	t.Setenv("WRKR_STATE_PATH", "/tmp/from-env.json")
	if got := ResolvePath(""); got != "/tmp/from-env.json" {
		t.Fatalf("unexpected env path: %q", got)
	}
}

func TestStateIntegrationRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")

	snapshot := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if loaded.Target.Value != "acme/backend" {
		t.Fatalf("unexpected target: %+v", loaded.Target)
	}

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first state: %v", err)
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot second time: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second state: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("state file must be byte-stable\nfirst: %s\nsecond: %s", first, second)
	}
}

func TestStateSaveIsAtomicUnderInterruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	initial := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial snapshot: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial snapshot bytes: %v", err)
	}

	var injected atomic.Bool
	restore := atomicwrite.SetBeforeRenameHookForTest(func(targetPath string, _ string) error {
		if filepath.Clean(targetPath) != filepath.Clean(path) {
			return nil
		}
		if injected.CompareAndSwap(false, true) {
			return errors.New("simulated interruption before rename")
		}
		return nil
	})
	defer restore()

	updated := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/updated"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/updated", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, updated); err == nil {
		t.Fatal("expected save interruption failure")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot after interruption: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected snapshot bytes to remain unchanged after interruption\nbefore: %s\nafter: %s", before, after)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected state file to remain parseable after interruption: %v", err)
	}
}
