package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type interactiveJSONBuffer struct {
	bytes.Buffer
}

func (b *interactiveJSONBuffer) JSONOutputCapabilities() jsonOutputCapabilities {
	return jsonOutputCapabilities{Interactive: true}
}

func TestScanJSONOnInteractiveStdoutUsesCompactSummary(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := createJSONStdoutRepoFixture(t, tmp)
	statePath := filepath.Join(tmp, "state.json")
	jsonPath := filepath.Join(tmp, "scan.json")

	stdout := &interactiveJSONBuffer{}
	var stderr bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-path", jsonPath,
		"--quiet",
	}, stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, stderr.String())
	}

	compact := parseJSONStdoutPayload(t, stdout.Bytes())
	if compact["json_stdout"] != "compact" {
		t.Fatalf("expected compact json stdout marker, got %v", compact)
	}
	if compact["command"] != "scan" {
		t.Fatalf("expected scan command marker, got %v", compact)
	}
	if compact["state_path"] != statePath {
		t.Fatalf("expected canonical state path %q, got %v", statePath, compact["state_path"])
	}
	if _, ok := compact["source_manifest"]; ok {
		t.Fatalf("expected compact scan stdout to omit full payload fields, got %v", compact)
	}
	artifactPaths, ok := compact["artifact_paths"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_paths, got %T", compact["artifact_paths"])
	}
	if artifactPaths["state"] != statePath || artifactPaths["json"] != jsonPath {
		t.Fatalf("unexpected compact scan artifact paths: %v", artifactPaths)
	}

	filePayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read scan json-path artifact: %v", err)
	}
	full := parseJSONStdoutPayload(t, filePayload)
	if _, ok := full["source_manifest"]; !ok {
		t.Fatalf("expected full scan payload in --json-path artifact, got %v", full)
	}
}

func TestScanJSONStdoutFullRestoresFullInteractivePayload(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := createJSONStdoutRepoFixture(t, tmp)
	statePath := filepath.Join(tmp, "state.json")
	jsonPath := filepath.Join(tmp, "scan.json")

	stdout := &interactiveJSONBuffer{}
	var stderr bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--json-stdout", "full",
		"--json-path", jsonPath,
		"--quiet",
	}, stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, stderr.String())
	}

	filePayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read scan json-path artifact: %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), filePayload) {
		t.Fatalf("expected --json-stdout=full to preserve full interactive payload bytes\nstdout=%q\nfile=%q", stdout.String(), string(filePayload))
	}
}

func TestReportJSONOnInteractiveStdoutUsesCompactSummary(t *testing.T) {
	t.Parallel()

	_, statePath := prepareJSONStdoutState(t)
	stdout := &interactiveJSONBuffer{}
	var stderr bytes.Buffer
	code := Run([]string{"report", "--state", statePath, "--json"}, stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("report failed: code=%d stderr=%s", code, stderr.String())
	}

	compact := parseJSONStdoutPayload(t, stdout.Bytes())
	if compact["json_stdout"] != "compact" || compact["command"] != "report" {
		t.Fatalf("expected compact report summary, got %v", compact)
	}
	if compact["state_path"] != statePath {
		t.Fatalf("expected report compact summary to name state path %q, got %v", statePath, compact["state_path"])
	}
	if _, ok := compact["summary"]; ok {
		t.Fatalf("expected compact report stdout to omit full summary payload, got %v", compact)
	}
}

func TestEvidenceJSONOnInteractiveStdoutUsesCompactSummary(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	_, statePath := prepareJSONStdoutState(t)
	outputDir := filepath.Join(tmp, "wrkr-evidence")
	stdout := &interactiveJSONBuffer{}
	var stderr bytes.Buffer
	code := Run([]string{
		"evidence",
		"--state", statePath,
		"--frameworks", "soc2",
		"--output", outputDir,
		"--json",
	}, stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("evidence failed: code=%d stderr=%s", code, stderr.String())
	}

	compact := parseJSONStdoutPayload(t, stdout.Bytes())
	if compact["json_stdout"] != "compact" || compact["command"] != "evidence" {
		t.Fatalf("expected compact evidence summary, got %v", compact)
	}
	if compact["output_dir"] != outputDir {
		t.Fatalf("expected output dir %q, got %v", outputDir, compact["output_dir"])
	}
	if _, ok := compact["control_evidence"]; ok {
		t.Fatalf("expected compact evidence stdout to omit full preview payloads, got %v", compact)
	}
}

func TestAssessJSONOnInteractiveStdoutUsesCompactSummary(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := createJSONStdoutRepoFixture(t, tmp)
	outputDir := filepath.Join(tmp, "assessment")
	stdout := &interactiveJSONBuffer{}
	var stderr bytes.Buffer
	code := Run([]string{
		"assess",
		"--path", reposPath,
		"--output-dir", outputDir,
		"--json",
	}, stdout, &stderr)
	if code != exitSuccess {
		t.Fatalf("assess failed: code=%d stderr=%s", code, stderr.String())
	}

	compact := parseJSONStdoutPayload(t, stdout.Bytes())
	if compact["json_stdout"] != "compact" || compact["command"] != "assess" {
		t.Fatalf("expected compact assess summary, got %v", compact)
	}
	if compact["output_dir"] != outputDir {
		t.Fatalf("expected assessment output dir %q, got %v", outputDir, compact["output_dir"])
	}
	if _, ok := compact["stages"].(map[string]any); !ok {
		t.Fatalf("expected compact assess summary to include stage handoff, got %v", compact["stages"])
	}
}

func TestJSONStdoutRejectsInvalidMode(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--json", "--json-stdout", "sideways"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected invalid input exit, got %d stderr=%s", code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func createJSONStdoutRepoFixture(t *testing.T, root string) string {
	t.Helper()

	reposPath := filepath.Join(root, "repos")
	repoPath := filepath.Join(reposPath, "alpha")
	if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir repo git dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo codex dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	return reposPath
}

func prepareJSONStdoutState(t *testing.T) (string, string) {
	t.Helper()

	tmp := t.TempDir()
	reposPath := createJSONStdoutRepoFixture(t, tmp)
	statePath := filepath.Join(tmp, "state.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json", "--quiet"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("prepare scan state failed: code=%d stderr=%s", code, errOut.String())
	}
	return reposPath, statePath
}

func parseJSONStdoutPayload(t *testing.T, payload []byte) map[string]any {
	t.Helper()

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse json stdout payload: %v (%q)", err, string(payload))
	}
	return decoded
}
