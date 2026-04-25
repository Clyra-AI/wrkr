package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/internal/managedmarker"
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
	payload, err := managedmarker.BuildPayload(statePath, root, materializedRootMarkerKind)
	if err != nil {
		t.Fatalf("build marker target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "marker-target.txt"), payload, 0o600); err != nil {
		t.Fatalf("write marker target: %v", err)
	}
	if err := os.Symlink("marker-target.txt", filepath.Join(root, materializedRootMarkerFile)); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stale.txt"), []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err = prepareMaterializedRoot(statePath)
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
	payload, err := managedmarker.BuildPayload(statePath, root, materializedRootMarkerKind)
	if err != nil {
		t.Fatalf("build marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, materializedRootMarkerFile), payload, 0o600); err != nil {
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
	} else if err := managedmarker.ValidatePayload(statePath, root, materializedRootMarkerKind, markerPayload); err != nil {
		t.Fatalf("expected signed managed marker, got: %v", err)
	}
}

func TestPrepareMaterializedRootRejectsLegacyMarkerContent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, materializedRootMarkerFile), []byte(materializedRootMarkerContent), 0o600); err != nil {
		t.Fatalf("write legacy marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := prepareMaterializedRoot(statePath)
	if err == nil {
		t.Fatal("expected legacy marker content to be rejected")
	}
	if !isMaterializedRootSafetyError(err) {
		t.Fatalf("expected materialized root safety error, got: %v", err)
	}
}

func TestCleanupManagedMaterializedRootRemovesManagedRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root, err := prepareMaterializedRoot(statePath)
	if err != nil {
		t.Fatalf("prepare materialized root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.txt"), []byte("private-source-sentinel"), 0o600); err != nil {
		t.Fatalf("write source sentinel: %v", err)
	}

	if err := cleanupManagedMaterializedRoot(statePath, root); err != nil {
		t.Fatalf("cleanup managed materialized root: %v", err)
	}
	if _, statErr := os.Stat(root); !os.IsNotExist(statErr) {
		t.Fatalf("expected managed materialized root to be removed, stat err=%v", statErr)
	}
}

func TestCleanupManagedMaterializedRootRejectsUnmanagedRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	root := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	sentinel := filepath.Join(root, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	err := cleanupManagedMaterializedRoot(statePath, root)
	if err == nil {
		t.Fatal("expected unmanaged root cleanup to be rejected")
	}
	if !isMaterializedRootSafetyError(err) {
		t.Fatalf("expected materialized root safety error, got: %v", err)
	}
	if _, statErr := os.Stat(sentinel); statErr != nil {
		t.Fatalf("expected unmanaged sentinel to remain, got: %v", statErr)
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

func TestScanInvalidSourceRetentionReturnsInvalidInput(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", t.TempDir(), "--source-retention", "forever", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on invalid input, got %q", out.String())
	}
}

func TestScanHostedDefaultRemovesMaterializedRootAndSerializesLogicalLocation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[{"path":"AGENTS.md","type":"blob","sha":"sha-agents"},{"path":"src/private.py","type":"blob","sha":"sha-source"}]}`)
		case "/repos/acme/backend/git/blobs/sha-agents":
			_, _ = fmt.Fprint(w, `{"content":"hosted instructions\n","encoding":"utf-8"}`)
		case "/repos/acme/backend/git/blobs/sha-source":
			t.Fatalf("default hosted scan should not fetch generic source blob %s", r.URL.Path)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "last-scan.json")
	materializedRoot := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("hosted scan failed: %d (%s)", code, errOut.String())
	}
	if strings.Contains(out.String(), "materialized-sources") || strings.Contains(errOut.String(), "materialized-sources") {
		t.Fatalf("expected hosted scan output to avoid materialized root paths\nstdout=%s\nstderr=%s", out.String(), errOut.String())
	}
	if _, statErr := os.Stat(materializedRoot); !os.IsNotExist(statErr) {
		t.Fatalf("expected default hosted scan to remove materialized root, stat err=%v", statErr)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	sourceManifest, ok := payload["source_manifest"].(map[string]any)
	if !ok {
		t.Fatalf("expected source manifest object, got %T", payload["source_manifest"])
	}
	repos, ok := sourceManifest["repos"].([]any)
	if !ok || len(repos) != 1 {
		t.Fatalf("expected one source repo, got %v", sourceManifest["repos"])
	}
	repo, ok := repos[0].(map[string]any)
	if !ok {
		t.Fatalf("expected repo object, got %T", repos[0])
	}
	if repo["location"] != "github://acme/backend" {
		t.Fatalf("expected logical hosted location, got %v", repo["location"])
	}
	if _, ok := repo["scan_root"]; ok {
		t.Fatalf("scan_root must not be serialized in source manifest: %v", repo)
	}
	privacy, ok := payload["source_privacy"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_privacy object, got %T", payload["source_privacy"])
	}
	if privacy["retention_mode"] != sourceprivacy.RetentionEphemeral {
		t.Fatalf("unexpected retention mode: %v", privacy["retention_mode"])
	}
	if privacy["cleanup_status"] != sourceprivacy.CleanupRemoved {
		t.Fatalf("unexpected cleanup status: %v", privacy["cleanup_status"])
	}
	if privacy["materialized_source_retained"] != false {
		t.Fatalf("expected materialized_source_retained=false, got %v", privacy["materialized_source_retained"])
	}
	if privacy["raw_source_in_artifacts"] != false {
		t.Fatalf("expected raw_source_in_artifacts=false, got %v", privacy["raw_source_in_artifacts"])
	}
	if privacy["serialized_locations"] != sourceprivacy.SerializedLocationsLogical {
		t.Fatalf("unexpected serialized locations: %v", privacy["serialized_locations"])
	}
}
