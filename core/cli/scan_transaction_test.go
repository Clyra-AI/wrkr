package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
