package state

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/source"
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
