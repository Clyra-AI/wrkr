package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestAssessRequiresTarget(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"assess", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestAssessWritesOutputDirectoryManifest(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	repo := writeAssessFixtureRepo(t, tmp)
	outputDir := filepath.Join(tmp, "assessment")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"assess",
		"--path", repo,
		"--output-dir", outputDir,
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse assess payload: %v", err)
	}
	manifestPath, _ := payload["manifest_path"].(string)
	if manifestPath == "" {
		t.Fatalf("expected manifest_path, got %v", payload)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected manifest file: %v", err)
	}

	artifacts, ok := payload["artifacts"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifacts object, got %T", payload["artifacts"])
	}
	for _, key := range []string{"state_path", "report_markdown_path", "report_evidence_json_path", "backlog_csv_path", "evidence_output_dir", "export_pack_path"} {
		value, _ := artifacts[key].(string)
		if value == "" {
			t.Fatalf("expected artifact %s, got %v", key, artifacts)
		}
		if _, err := os.Stat(filepath.Join(outputDir, filepath.FromSlash(value))); err != nil {
			t.Fatalf("expected artifact %s to exist: %v", key, err)
		}
	}
}

func TestAssessRuntimeInputWritesArtifact(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	repo := writeAssessFixtureRepo(t, tmp)
	sessionInput := filepath.Join(tmp, "runtime-session.json")
	payload := []byte(`{
  "provider": "codex",
  "session_id": "sess-1",
  "repo": "local/repo",
  "workflow": ".github/workflows/release.yml",
  "changed_files": ["cmd/release.go"],
  "actions": ["deploy"],
  "completed_at": "2026-05-27T14:59:00Z"
}`)
	if err := os.WriteFile(sessionInput, payload, 0o600); err != nil {
		t.Fatalf("write runtime session: %v", err)
	}
	outputDir := filepath.Join(tmp, "assessment")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"assess",
		"--path", repo,
		"--runtime-input", sessionInput,
		"--output-dir", outputDir,
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payloadOut map[string]any
	if err := json.Unmarshal(out.Bytes(), &payloadOut); err != nil {
		t.Fatalf("parse assess payload: %v", err)
	}
	artifacts, ok := payloadOut["artifacts"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifacts object, got %T", payloadOut["artifacts"])
	}
	if artifacts["runtime_artifact_kind"] != "runtime_sessions" {
		t.Fatalf("expected runtime_sessions artifact kind, got %v", artifacts["runtime_artifact_kind"])
	}
	runtimePath, _ := artifacts["runtime_artifact_path"].(string)
	if runtimePath == "" {
		t.Fatalf("expected runtime artifact path, got %v", artifacts)
	}
	if _, err := os.Stat(filepath.Join(outputDir, filepath.FromSlash(runtimePath))); err != nil {
		t.Fatalf("expected runtime artifact file: %v", err)
	}
}

func TestAssessBaselineDriftReturnsExitAndWritesManifest(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	repo := writeAssessFixtureRepo(t, tmp)
	baselinePath := filepath.Join(tmp, "baseline.json")
	baseline := regress.BuildBaseline(state.Snapshot{Version: "v1"}, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	if err := regress.SaveBaseline(baselinePath, baseline); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	outputDir := filepath.Join(tmp, "assessment")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"assess",
		"--path", repo,
		"--baseline", baselinePath,
		"--output-dir", outputDir,
		"--json",
	}, &out, &errOut)
	if code != exitRegressionDrift {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitRegressionDrift, code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse assess payload: %v", err)
	}
	if payload["status"] != "drift_detected" {
		t.Fatalf("expected drift_detected status, got %v", payload)
	}
	manifestPath, _ := payload["manifest_path"].(string)
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected manifest even when drift detected: %v", err)
	}
	stages, ok := payload["stages"].(map[string]any)
	if !ok {
		t.Fatalf("expected stages object, got %T", payload["stages"])
	}
	regressStage, ok := stages["regress"].(map[string]any)
	if !ok || regressStage["status"] != "drift_detected" {
		t.Fatalf("expected regress stage drift_detected, got %v", stages["regress"])
	}
}

func writeAssessFixtureRepo(t *testing.T, root string) string {
	t.Helper()

	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".github", "workflows"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "AGENTS.md"), []byte("# Wrkr fixture\n"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}
	workflow := []byte(`name: release
on:
  push:
    branches: [main]
permissions:
  contents: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - run: codex exec --model gpt-5 "deploy release"
`)
	if err := os.WriteFile(filepath.Join(repo, ".github", "workflows", "release.yml"), workflow, 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	return repo
}
