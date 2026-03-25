package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	if errOut.Len() != 0 {
		t.Fatalf("expected no stderr output for path scan json sink, got %q", errOut.String())
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

	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("parse error payload: %v (%q)", err, string(payload))
	}
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
