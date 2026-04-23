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

func TestScanJSONPathWritesByteIdenticalPayloadToStdoutAndFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	jsonPath := filepath.Join(tmp, "scan.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", jsonPath,
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "progress target=path ") {
		t.Fatalf("expected path progress on stderr, got %q", errOut.String())
	}

	filePayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json payload: %v", err)
	}
	if !bytes.Equal(out.Bytes(), filePayload) {
		t.Fatalf("expected stdout and file payloads to be byte-identical\nstdout=%q\nfile=%q", out.String(), string(filePayload))
	}

	var payload map[string]any
	if err := json.Unmarshal(filePayload, &payload); err != nil {
		t.Fatalf("parse json payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestScanJSONPathWritesArtifactWithoutJSONStdoutMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	jsonPath := filepath.Join(tmp, "scan.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json-path", jsonPath,
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != "wrkr scan complete" {
		t.Fatalf("expected normal stdout completion message, got %q", out.String())
	}

	filePayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(filePayload, &payload); err != nil {
		t.Fatalf("parse json payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestScanJSONPathHelpIncludesFlag(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--help"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "-json-path") {
		t.Fatalf("expected scan help to mention --json-path, got %q", errOut.String())
	}
}

func TestScanJSONPathRejectsDirectory(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", tmp,
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanJSONPathRejectsAliasWithStatePathBeforeWritingManagedArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

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
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)

	envelope := parseTrailingJSONEnvelope(t, errOut.Bytes())
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", envelope)
	}
	message, _ := errorPayload["message"].(string)
	for _, want := range []string{"--state", "--json-path"} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected error message %q to mention %s", message, want)
		}
	}

	for _, path := range []string{
		statePath,
		manifest.ResolvePath(statePath),
		lifecycle.ChainPath(statePath),
		proofemit.ChainPath(statePath),
		proofemit.ChainAttestationPath(proofemit.ChainPath(statePath)),
		proofemit.SigningKeyPath(statePath),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected %s to remain absent after rejected collision, got err=%v", path, err)
		}
	}
}

func TestScanJSONPathRejectsAliasViaSymlinkedParentPath(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	realDir := filepath.Join(tmp, "real")
	linkDir := filepath.Join(tmp, "link")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink unsupported in current environment: %v", err)
	}

	statePath := filepath.Join(realDir, "state.json")
	jsonPath := filepath.Join(linkDir, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", jsonPath,
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)

	envelope := parseTrailingJSONEnvelope(t, errOut.Bytes())
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", envelope)
	}
	message, _ := errorPayload["message"].(string)
	for _, want := range []string{"--state", "--json-path"} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected error message %q to mention %s", message, want)
		}
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("expected %s to remain absent after rejected collision, got err=%v", statePath, err)
	}
}

func TestScanRejectsSymlinkedStatePathBeforeWritingManagedArtifacts(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	workDir := filepath.Join(tmp, "work")
	realDir := filepath.Join(tmp, "real")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir work dir: %v", err)
	}
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real dir: %v", err)
	}
	realStatePath := filepath.Join(realDir, "state.json")
	stateLink := filepath.Join(workDir, "state-link.json")
	relativeTarget, err := filepath.Rel(filepath.Dir(stateLink), realStatePath)
	if err != nil {
		t.Fatalf("relative target: %v", err)
	}
	if err := os.Symlink(relativeTarget, stateLink); err != nil {
		t.Skipf("symlink unsupported in current environment: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", stateLink, "--json"}, &out, &errOut)
	if code != exitUnsafeBlocked {
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitUnsafeBlocked, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "unsafe_operation_blocked", exitUnsafeBlocked)

	for _, path := range []string{
		realStatePath,
		manifest.ResolvePath(stateLink),
		lifecycle.ChainPath(stateLink),
		proofemit.ChainPath(stateLink),
		proofemit.ChainAttestationPath(proofemit.ChainPath(stateLink)),
		proofemit.SigningKeyPath(stateLink),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expected no managed artifact at %s after rejected state symlink, got err=%v", path, err)
		}
	}
}

func TestScanJSONPathRejectsAliasWithReportPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "alpha", ".codex")
	statePath := filepath.Join(tmp, "state.json")
	sidecarPath := filepath.Join(tmp, "scan-artifact.json")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", sidecarPath,
		"--report-md",
		"--report-md-path", sidecarPath,
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)

	envelope := parseTrailingJSONEnvelope(t, errOut.Bytes())
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", envelope)
	}
	message, _ := errorPayload["message"].(string)
	for _, want := range []string{"--json-path", "--report-md-path"} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected error message %q to mention %s", message, want)
		}
	}
}

func TestScanJSONPathWriteFailureReturnsRuntimeFailure(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based write failure fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	lockedDir := filepath.Join(tmp, "locked")
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
		t.Fatalf("expected exit %d, got %d (%s)", exitRuntime, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)
}

func assertErrorEnvelopeCode(t *testing.T, payload []byte, expectedCode string, expectedExit int) {
	t.Helper()

	envelope := parseTrailingJSONEnvelope(t, payload)
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", envelope)
	}
	if errorPayload["code"] != expectedCode {
		t.Fatalf("expected error code %q, got %v", expectedCode, errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(expectedExit) {
		t.Fatalf("expected exit_code=%d, got %v", expectedExit, errorPayload["exit_code"])
	}
}

func parseTrailingJSONEnvelope(t *testing.T, payload []byte) map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	for idx := len(lines) - 1; idx >= 0; idx-- {
		line := strings.TrimSpace(lines[idx])
		if line == "" {
			continue
		}
		var envelope map[string]any
		if err := json.Unmarshal([]byte(line), &envelope); err == nil {
			return envelope
		}
	}
	t.Fatalf("parse error payload: no trailing json envelope in %q", string(payload))
	return nil
}
