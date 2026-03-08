package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestLoadLifecycleManifestPrefersNewerStateSnapshot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	manifestPath := manifest.ResolvePath(statePath)

	staleManifest := manifest.Manifest{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:mcp-1:acme",
			ToolID:        "mcp-1",
			Status:        "active",
			ApprovalState: "valid",
			Present:       true,
		}},
	}
	if err := manifest.Save(manifestPath, staleManifest); err != nil {
		t.Fatalf("save stale manifest: %v", err)
	}

	snapshot := state.Snapshot{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:mcp-1:acme",
			ToolID:        "mcp-1",
			Status:        "under_review",
			ApprovalState: "missing",
			Present:       true,
		}},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state snapshot: %v", err)
	}

	oldTime := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(2 * time.Minute)
	if err := os.Chtimes(manifestPath, oldTime, oldTime); err != nil {
		t.Fatalf("set manifest mtime: %v", err)
	}
	if err := os.Chtimes(statePath, newTime, newTime); err != nil {
		t.Fatalf("set state mtime: %v", err)
	}

	loaded, err := loadLifecycleManifest(manifestPath, statePath, &snapshot)
	if err != nil {
		t.Fatalf("load lifecycle manifest: %v", err)
	}
	if len(loaded.Identities) != 1 {
		t.Fatalf("expected one identity, got %d", len(loaded.Identities))
	}
	if loaded.Identities[0].Status != "under_review" || loaded.Identities[0].ApprovalState != "missing" {
		t.Fatalf("expected newer state snapshot identities, got %+v", loaded.Identities[0])
	}
}

func TestLoadLifecycleManifestKeepsNewerManifestEdits(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	manifestPath := manifest.ResolvePath(statePath)

	snapshot := state.Snapshot{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:mcp-1:acme",
			ToolID:        "mcp-1",
			Status:        "under_review",
			ApprovalState: "missing",
			Present:       true,
		}},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state snapshot: %v", err)
	}

	newerManifest := manifest.Manifest{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:mcp-1:acme",
			ToolID:        "mcp-1",
			Status:        "revoked",
			ApprovalState: "revoked",
			Present:       true,
		}},
	}
	if err := manifest.Save(manifestPath, newerManifest); err != nil {
		t.Fatalf("save newer manifest: %v", err)
	}

	oldTime := time.Date(2026, 3, 7, 10, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(2 * time.Minute)
	if err := os.Chtimes(statePath, oldTime, oldTime); err != nil {
		t.Fatalf("set state mtime: %v", err)
	}
	if err := os.Chtimes(manifestPath, newTime, newTime); err != nil {
		t.Fatalf("set manifest mtime: %v", err)
	}

	loaded, err := loadLifecycleManifest(manifestPath, statePath, &snapshot)
	if err != nil {
		t.Fatalf("load lifecycle manifest: %v", err)
	}
	if len(loaded.Identities) != 1 {
		t.Fatalf("expected one identity, got %d", len(loaded.Identities))
	}
	if loaded.Identities[0].Status != "revoked" || loaded.Identities[0].ApprovalState != "revoked" {
		t.Fatalf("expected newer manifest identities, got %+v", loaded.Identities[0])
	}
}

func TestLoadLifecycleManifestUsesSnapshotWhenManifestMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	manifestPath := manifest.ResolvePath(statePath)

	snapshot := state.Snapshot{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:mcp-1:acme",
			ToolID:        "mcp-1",
			Status:        "under_review",
			ApprovalState: "missing",
			Present:       true,
		}},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state snapshot: %v", err)
	}

	loaded, err := loadLifecycleManifest(manifestPath, statePath, &snapshot)
	if err != nil {
		t.Fatalf("load lifecycle manifest: %v", err)
	}
	if len(loaded.Identities) != 1 || loaded.Identities[0].Status != "under_review" {
		t.Fatalf("expected snapshot-backed manifest, got %+v", loaded.Identities)
	}
}
