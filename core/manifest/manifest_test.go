package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wrkr-manifest.yaml")
	in := Manifest{Identities: []IdentityRecord{{AgentID: "wrkr:mcp-abc:acme", ToolID: "mcp-abc", Status: "under_review", ApprovalState: "missing", Present: true}}}
	if err := Save(path, in); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if len(loaded.Identities) != 1 {
		t.Fatalf("expected one record, got %d", len(loaded.Identities))
	}
}

func TestResolvePathFromStatePath(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join("/tmp", "a", "last-scan.json")
	if got := ResolvePath(statePath); got != filepath.Join("/tmp", "a", "wrkr-manifest.yaml") {
		t.Fatalf("unexpected path: %s", got)
	}
}

func TestSaveCreatesDirectory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nested", "wrkr-manifest.yaml")
	if err := Save(path, Manifest{}); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("manifest not written: %v", err)
	}
}

func TestSaveIsAtomicUnderInterruption(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "wrkr-manifest.yaml")
	initial := Manifest{Identities: []IdentityRecord{{AgentID: "wrkr:mcp-old:acme", ToolID: "mcp-old", Present: true}}}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial manifest: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial manifest: %v", err)
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

	updated := Manifest{Identities: []IdentityRecord{{AgentID: "wrkr:mcp-new:acme", ToolID: "mcp-new", Present: true}}}
	if err := Save(path, updated); err == nil {
		t.Fatal("expected interrupted manifest save to fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest after interruption: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected manifest bytes to remain unchanged after interruption")
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected manifest to remain parseable after interruption: %v", err)
	}
}
