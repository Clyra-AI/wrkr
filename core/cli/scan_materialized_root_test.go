package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareMaterializedRootRejectsNonManagedNonEmptyDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	stalePath := filepath.Join(root, "stale.txt")
	if err := os.WriteFile(stalePath, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := prepareMaterializedRoot(statePath)
	if err == nil {
		t.Fatal("expected non-managed non-empty root to be rejected")
	}
	if !isMaterializedRootSafetyError(err) {
		t.Fatalf("expected materialized root safety error, got: %v", err)
	}
	if _, statErr := os.Stat(stalePath); statErr != nil {
		t.Fatalf("expected unmanaged stale file to remain, got: %v", statErr)
	}
}

func TestPrepareMaterializedRootRejectsMarkerSymlink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "marker-target.txt"), []byte(materializedRootMarkerContent), 0o600); err != nil {
		t.Fatalf("write marker target: %v", err)
	}
	if err := os.Symlink("marker-target.txt", filepath.Join(root, materializedRootMarkerFile)); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stale.txt"), []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := prepareMaterializedRoot(statePath)
	if err == nil {
		t.Fatal("expected marker symlink to be rejected")
	}
	if !isMaterializedRootSafetyError(err) {
		t.Fatalf("expected materialized root safety error, got: %v", err)
	}
}

func TestPrepareMaterializedRootResetsManagedRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, materializedRootMarkerFile), []byte(materializedRootMarkerContent), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	stalePath := filepath.Join(root, "stale.txt")
	if err := os.WriteFile(stalePath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	gotRoot, err := prepareMaterializedRoot(statePath)
	if err != nil {
		t.Fatalf("prepare managed root: %v", err)
	}
	if gotRoot != root {
		t.Fatalf("expected root %q, got %q", root, gotRoot)
	}
	if _, statErr := os.Stat(stalePath); !os.IsNotExist(statErr) {
		t.Fatalf("expected stale file to be removed, got: %v", statErr)
	}
	if markerPayload, readErr := os.ReadFile(filepath.Join(root, materializedRootMarkerFile)); readErr != nil {
		t.Fatalf("read marker: %v", readErr)
	} else if string(markerPayload) != materializedRootMarkerContent {
		t.Fatalf("unexpected marker content: %q", string(markerPayload))
	}
}

func TestScanRepoDoesNotDeleteUnmanagedMaterializedSources(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	stalePath := filepath.Join(root, "unmanaged.txt")
	if err := os.WriteFile(stalePath, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write unmanaged file: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", "https://example.invalid",
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != exitUnsafeBlocked {
		t.Fatalf("expected exit %d, got %d (%s)", exitUnsafeBlocked, code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout output on failure, got %q", out.String())
	}
	if _, statErr := os.Stat(stalePath); statErr != nil {
		t.Fatalf("expected unmanaged materialized file to remain, got: %v", statErr)
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got: %v", payload)
	}
	if errObj["code"] != "unsafe_operation_blocked" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(exitUnsafeBlocked) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}
