package manifest

import (
	"os"
	"path/filepath"
	"testing"
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
