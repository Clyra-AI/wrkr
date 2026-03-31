package org

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/managedmarker"
)

func TestCheckpointPathCreatesSignedManagedRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	path, err := checkpointPath(statePath, "acme")
	if err != nil {
		t.Fatalf("checkpoint path: %v", err)
	}
	root := filepath.Dir(path)
	payload, err := os.ReadFile(filepath.Join(root, checkpointMarkerFile))
	if err != nil {
		t.Fatalf("read checkpoint marker: %v", err)
	}
	if err := managedmarker.ValidatePayload(statePath, root, checkpointMarkerKind, payload); err != nil {
		t.Fatalf("expected signed checkpoint marker, got: %v", err)
	}
}

func TestCheckpointPathRejectsLegacyMarkerContent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	root := filepath.Join(filepath.Dir(statePath), checkpointRootName)
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir checkpoint root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, checkpointMarkerFile), []byte(checkpointMarkerContent), 0o600); err != nil {
		t.Fatalf("write legacy checkpoint marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := checkpointPath(statePath, "acme")
	if err == nil {
		t.Fatal("expected legacy checkpoint marker to fail")
	}
	if !IsCheckpointSafetyError(err) {
		t.Fatalf("expected checkpoint safety error, got %v", err)
	}
}
