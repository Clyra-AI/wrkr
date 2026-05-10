package cli

import (
	"bytes"
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
	if _, err := os.Stat(managedArtifactTransactionPath(statePath)); !os.IsNotExist(err) {
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

	payload := readOptionalTestFile(t, managedArtifactTransactionPath(statePath))
	if bytes.Contains(payload, []byte(tmp)) {
		t.Fatalf("transaction metadata must not contain checkout/temp absolute paths: %s", payload)
	}
	if !bytes.Contains(payload, []byte("../reports/scan.md")) {
		t.Fatalf("expected sidecar path to be stored relative to managed root, got %s", payload)
	}
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
