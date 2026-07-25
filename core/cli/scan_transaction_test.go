package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
)

func skipNonPortableChmodWriteFailureFixture(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based write failure fixture is not portable on windows")
	}
}

func TestScanLateReportWriteFailureRollsBackManagedArtifacts(t *testing.T) {
	t.Parallel()
	skipNonPortableChmodWriteFailureFixture(t)

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	var initialOut bytes.Buffer
	var initialErr bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &initialOut, &initialErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d stdout=%q stderr=%q", code, initialOut.String(), initialErr.String())
	}

	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)

	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	proofBefore := readOptionalTestFile(t, proofPath)
	attestationBefore := readOptionalTestFile(t, attestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	lockedDir := filepath.Join(tmp, "locked-report")
	if err := os.MkdirAll(lockedDir, 0o700); err != nil {
		t.Fatalf("mkdir locked dir: %v", err)
	}
	if err := os.Chmod(lockedDir, 0o500); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(lockedDir, 0o700)
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--report-md",
		"--report-md-path", filepath.Join(lockedDir, "scan.md"),
		"--json",
	}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)

	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofPath, proofBefore)
	assertOptionalTestFileEquals(t, attestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
}

func TestScanInterruptedAfterStateSaveRecoversManagedArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	var initialOut bytes.Buffer
	var initialErr bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &initialOut, &initialErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d stdout=%q stderr=%q", code, initialOut.String(), initialErr.String())
	}

	stateBefore := readOptionalTestFile(t, statePath)
	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)
	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	proofBefore := readOptionalTestFile(t, proofPath)
	attestationBefore := readOptionalTestFile(t, attestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	transaction, err := beginManagedArtifactTransaction(statePath, "scan", []managedArtifactFile{
		{label: "state", path: statePath},
		{label: "manifest", path: manifestPath},
		{label: "lifecycle chain", path: lifecyclePath},
		{label: "proof chain", path: proofPath},
		{label: "proof attestation", path: attestationPath},
		{label: "proof signing key", path: signingKeyPath},
	})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	transaction.completed = true // Simulate abrupt process interruption: leave journal behind and skip rollback.
	if err := os.WriteFile(statePath, []byte(`{"version":"v1","findings":[]}`+"\n"), 0o600); err != nil {
		t.Fatalf("write interrupted state: %v", err)
	}
	if err := transaction.releaseLease(); err != nil {
		t.Fatalf("release interrupted transaction lease: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--json"}, &out, &errOut); code != exitSuccess {
		t.Fatalf("score after recovery failed: %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	assertOptionalTestFileEquals(t, statePath, stateBefore)
	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofPath, proofBefore)
	assertOptionalTestFileEquals(t, attestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
	if _, err := os.Stat(managedArtifactTransactionPathForTest(t, statePath)); !os.IsNotExist(err) {
		t.Fatalf("expected recovered transaction journal to be removed, stat err=%v", err)
	}
}

func TestScanInterruptedAfterProofEmitFailsClosedOnManifestMismatch(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	agentID := scanIdentityAgentID(t, statePath)
	if strings.TrimSpace(agentID) == "" {
		t.Fatal("expected scan fixture to produce an agent id")
	}
	manifestPath := manifest.ResolvePath(statePath)
	loadedManifest, err := manifest.Load(manifestPath)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	loadedManifest.Identities = nil
	if err := manifest.Save(manifestPath, loadedManifest); err != nil {
		t.Fatalf("save mismatched manifest: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"regress", "run", "--baseline", statePath, "--state", statePath, "--json"}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected fail-closed runtime exit, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)
	if !strings.Contains(errOut.String(), "state and manifest identities differ") {
		t.Fatalf("expected consistency mismatch detail, got %q", errOut.String())
	}
}

func TestScoreRejectsTamperedProofWhenLifecycleChainMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	if strings.TrimSpace(scanIdentityAgentID(t, statePath)) == "" {
		t.Fatal("expected scan fixture to produce an agent id")
	}

	lifecyclePath := lifecycle.ChainPath(statePath)
	if err := os.Remove(lifecyclePath); err != nil {
		t.Fatalf("remove lifecycle chain: %v", err)
	}

	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	if err := os.Remove(attestationPath); err != nil {
		t.Fatalf("remove proof attestation: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"score", "--state", statePath, "--json"}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected fail-closed runtime exit, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)
	if !strings.Contains(errOut.String(), "managed artifact consistency proof attestation") {
		t.Fatalf("expected proof-attestation consistency detail, got %q", errOut.String())
	}
}

func TestScanRejectsTamperedProofChainBeforeTransactionCommit(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	if strings.TrimSpace(scanIdentityAgentID(t, statePath)) == "" {
		t.Fatal("expected scan fixture to produce an agent id")
	}

	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)

	stateBefore := readOptionalTestFile(t, statePath)
	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	attestationBefore := readOptionalTestFile(t, attestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	payload, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain map[string]any
	if err := json.Unmarshal(payload, &chain); err != nil {
		t.Fatalf("parse chain json: %v", err)
	}
	records, ok := chain["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected records in proof chain: %v", chain)
	}
	first, ok := records[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected record shape: %T", records[0])
	}
	integrity, ok := first["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("missing integrity block in first record: %v", first)
	}
	integrity["record_hash"] = "sha256:tampered"
	mutated, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered chain: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(proofPath, mutated, 0o600); err != nil {
		t.Fatalf("write tampered chain: %v", err)
	}
	proofBefore := readOptionalTestFile(t, proofPath)

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)
	if !strings.Contains(errOut.String(), "managed artifact consistency proof verification") {
		t.Fatalf("expected proof verification detail, got %q", errOut.String())
	}

	assertOptionalTestFileEquals(t, statePath, stateBefore)
	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofPath, proofBefore)
	assertOptionalTestFileEquals(t, attestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
	if _, err := os.Stat(managedArtifactTransactionPathForTest(t, statePath)); !os.IsNotExist(err) {
		t.Fatalf("expected recovered transaction journal to be removed, stat err=%v", err)
	}
}

func TestManagedArtifactTransactionMetadataIsPortable(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	reportPath := filepath.Join(tmp, "reports", "scan.md")
	transaction, err := beginManagedArtifactTransaction(statePath, "scan", []managedArtifactFile{
		{label: "state", path: statePath},
		{label: "report markdown", path: reportPath},
	})
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer func() {
		_ = transaction.Rollback(nil)
	}()

	journalPath := managedArtifactTransactionPathForTest(t, statePath)
	if filepath.Clean(filepath.Dir(journalPath)) == filepath.Clean(filepath.Dir(statePath)) {
		t.Fatalf("transaction journal must live outside the caller-controlled state directory: %s", journalPath)
	}
	payload := readOptionalTestFile(t, journalPath)
	if bytes.Contains(payload, []byte(tmp)) {
		t.Fatalf("transaction metadata must not contain checkout/temp absolute paths: %s", payload)
	}
	if !bytes.Contains(payload, []byte("../reports/scan.md")) {
		t.Fatalf("expected sidecar path to be stored relative to managed root, got %s", payload)
	}
	if !bytes.Contains(payload, []byte(`"state_path_sha256"`)) {
		t.Fatalf("expected transaction metadata to bind the caller state path, got %s", payload)
	}
}

func TestRepoLocalLegacyManagedArtifactJournalFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.WriteFile(statePath, []byte(`{"version":"v1"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	victimPath := filepath.Join(tmp, "victim.txt")
	original := []byte("safe\n")
	if err := os.WriteFile(victimPath, original, 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	journal := managedArtifactTransactionJournal{
		Version:         "v1",
		StatePathSHA256: "attacker-controlled",
		Operation:       "scan",
		Artifacts: []managedArtifactTransactionArtifact{{
			Label:   "outside target",
			Path:    "../victim.txt",
			Existed: true,
			Payload: []byte("overwritten\n"),
			Perm:    0o600,
		}},
	}
	payload, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		t.Fatalf("marshal malicious journal: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(legacyManagedArtifactTransactionPath(statePath), payload, 0o600); err != nil {
		t.Fatalf("write malicious journal: %v", err)
	}

	err = preflightManagedArtifactRead(statePath)
	if err == nil || !isUnsafeManagedArtifactPathError(err) {
		t.Fatalf("expected repo-local transaction journal to fail closed, got %v", err)
	}
	got, readErr := os.ReadFile(victimPath)
	if readErr != nil {
		t.Fatalf("read victim after rejected recovery: %v", readErr)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("repo-local journal changed outside target: got %q want %q", got, original)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--json"}, &out, &errOut); code != exitUnsafeBlocked {
		t.Fatalf("expected unsafe-operation exit for repo-local journal, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "unsafe_operation_blocked", exitUnsafeBlocked)
}

func TestPrivateManagedArtifactJournalStateBindingFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}
	journalPath := managedArtifactTransactionPathForTest(t, statePath)
	t.Cleanup(func() { _ = os.Remove(journalPath) })
	payload, err := json.Marshal(managedArtifactTransactionJournal{
		Version:         managedArtifactTransactionVersion,
		StatePathSHA256: strings.Repeat("0", 64),
		Operation:       "scan",
		Artifacts: []managedArtifactTransactionArtifact{{
			Label: "state",
			Path:  "state.json",
		}},
	})
	if err != nil {
		t.Fatalf("marshal mismatched journal: %v", err)
	}
	if err := os.WriteFile(journalPath, payload, 0o600); err != nil {
		t.Fatalf("write mismatched journal: %v", err)
	}

	err = recoverManagedArtifactTransaction(statePath)
	if err == nil || !isUnsafeManagedArtifactPathError(err) || !strings.Contains(err.Error(), "state binding mismatch") {
		t.Fatalf("expected state binding mismatch to fail closed, got %v", err)
	}
}

func TestPrivateManagedArtifactJournalSymlinkFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	journalPath := managedArtifactTransactionPathForTest(t, statePath)
	t.Cleanup(func() { _ = os.Remove(journalPath) })
	targetPath := filepath.Join(tmp, "attacker-journal.json")
	if err := os.WriteFile(targetPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write attacker journal: %v", err)
	}
	if err := os.Symlink(targetPath, journalPath); err != nil {
		t.Fatalf("symlink attacker journal: %v", err)
	}

	err := recoverManagedArtifactTransaction(statePath)
	if err == nil || !isUnsafeManagedArtifactPathError(err) || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("expected symlinked private journal to fail closed, got %v", err)
	}
}

func TestPrivateManagedArtifactJournalBroadPermissionsFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX owner-only permission contract does not apply on Windows")
	}
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	journalPath := managedArtifactTransactionPathForTest(t, statePath)
	t.Cleanup(func() { _ = os.Remove(journalPath) })
	if err := os.WriteFile(journalPath, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write broad-permission journal: %v", err)
	}
	if err := os.Chmod(journalPath, 0o644); err != nil {
		t.Fatalf("broaden journal permissions: %v", err)
	}

	err := recoverManagedArtifactTransaction(statePath)
	if err == nil || !isUnsafeManagedArtifactPathError(err) || !strings.Contains(err.Error(), "permissions are too broad") {
		t.Fatalf("expected broad private journal permissions to fail closed, got %v", err)
	}
}

func managedArtifactTransactionPathForTest(t *testing.T, statePath string) string {
	t.Helper()
	path, err := managedArtifactTransactionPath(statePath)
	if err != nil {
		t.Fatalf("resolve transaction path: %v", err)
	}
	return path
}

func TestScanLateSARIFWriteFailureRollsBackManagedArtifacts(t *testing.T) {
	t.Parallel()
	skipNonPortableChmodWriteFailureFixture(t)

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	var initialOut bytes.Buffer
	var initialErr bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &initialOut, &initialErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d stdout=%q stderr=%q", code, initialOut.String(), initialErr.String())
	}

	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)

	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	proofBefore := readOptionalTestFile(t, proofPath)
	attestationBefore := readOptionalTestFile(t, attestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	lockedDir := filepath.Join(tmp, "locked-sarif")
	if err := os.MkdirAll(lockedDir, 0o700); err != nil {
		t.Fatalf("mkdir locked dir: %v", err)
	}
	if err := os.Chmod(lockedDir, 0o500); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(lockedDir, 0o700)
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--sarif",
		"--sarif-path", filepath.Join(lockedDir, "wrkr.sarif"),
		"--json",
	}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)

	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofPath, proofBefore)
	assertOptionalTestFileEquals(t, attestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
}

func TestScanLateJSONPathWriteFailureRollsBackManagedArtifacts(t *testing.T) {
	t.Parallel()
	skipNonPortableChmodWriteFailureFixture(t)

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	var initialOut bytes.Buffer
	var initialErr bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &initialOut, &initialErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d stdout=%q stderr=%q", code, initialOut.String(), initialErr.String())
	}

	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)

	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	proofBefore := readOptionalTestFile(t, proofPath)
	attestationBefore := readOptionalTestFile(t, attestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	lockedDir := filepath.Join(tmp, "locked-json")
	if err := os.MkdirAll(lockedDir, 0o700); err != nil {
		t.Fatalf("mkdir locked dir: %v", err)
	}
	if err := os.Chmod(lockedDir, 0o500); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(lockedDir, 0o700)
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", filepath.Join(lockedDir, "scan.json"),
	}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)

	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofPath, proofBefore)
	assertOptionalTestFileEquals(t, attestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
}

func TestScanRejectedJSONPathAliasPreservesManagedArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	var initialOut bytes.Buffer
	var initialErr bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &initialOut, &initialErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d stdout=%q stderr=%q", code, initialOut.String(), initialErr.String())
	}

	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofPath := proofemit.ChainPath(statePath)
	attestationPath := proofemit.ChainAttestationPath(proofPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)

	stateBefore := readOptionalTestFile(t, statePath)
	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	proofBefore := readOptionalTestFile(t, proofPath)
	attestationBefore := readOptionalTestFile(t, attestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", statePath,
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected invalid input exit, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)

	assertOptionalTestFileEquals(t, statePath, stateBefore)
	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofPath, proofBefore)
	assertOptionalTestFileEquals(t, attestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
}
