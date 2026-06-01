package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestWave7ScanJSONIncludesDefaultDeploymentMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected scan to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	if payload["deployment_mode"] != "local_only" {
		t.Fatalf("expected top-level deployment_mode local_only, got %v", payload["deployment_mode"])
	}
	sourcePrivacy, ok := payload["source_privacy"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_privacy object, got %T", payload["source_privacy"])
	}
	if sourcePrivacy["deployment_mode"] != "local_only" {
		t.Fatalf("expected source_privacy deployment_mode local_only, got %v", sourcePrivacy["deployment_mode"])
	}
}

func TestWave7ScanRejectsInvalidDeploymentMode(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", t.TempDir(),
		"--deployment-mode", "unsupported_mode",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestWave7ReportAndEvidenceJSONIncludeDeploymentMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{
		"scan",
		"--path", scanPath,
		"--state", statePath,
		"--deployment-mode", "customer_controlled_storage",
		"--json",
	}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--json",
	}, &reportOut, &reportErr)
	if code != 0 {
		t.Fatalf("expected report to succeed, got %d stderr=%s", code, reportErr.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if reportPayload["deployment_mode"] != "customer_controlled_storage" {
		t.Fatalf("expected report deployment_mode, got %v", reportPayload["deployment_mode"])
	}
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary payload, got %T", reportPayload["summary"])
	}
	if summary["deployment_mode"] != "customer_controlled_storage" {
		t.Fatalf("expected summary deployment_mode, got %v", summary["deployment_mode"])
	}

	var evidenceOut bytes.Buffer
	var evidenceErr bytes.Buffer
	code = Run([]string{
		"evidence",
		"--state", statePath,
		"--frameworks", "soc2",
		"--output", filepath.Join(tmp, "wrkr-evidence"),
		"--json",
	}, &evidenceOut, &evidenceErr)
	if code != 0 {
		t.Fatalf("expected evidence to succeed, got %d stderr=%s", code, evidenceErr.String())
	}

	var evidencePayload map[string]any
	if err := json.Unmarshal(evidenceOut.Bytes(), &evidencePayload); err != nil {
		t.Fatalf("parse evidence payload: %v", err)
	}
	if evidencePayload["deployment_mode"] != "customer_controlled_storage" {
		t.Fatalf("expected evidence deployment_mode, got %v", evidencePayload["deployment_mode"])
	}
	sourcePrivacy, ok := evidencePayload["source_privacy"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_privacy object, got %T", evidencePayload["source_privacy"])
	}
	if sourcePrivacy["deployment_mode"] != "customer_controlled_storage" {
		t.Fatalf("expected evidence source_privacy deployment_mode, got %v", sourcePrivacy["deployment_mode"])
	}
}

func TestWave7RedactedReportPreservesDeploymentMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{
		"scan",
		"--path", scanPath,
		"--state", statePath,
		"--deployment-mode", "managed_platform",
		"--json",
	}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected redacted report to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary payload, got %T", payload["summary"])
	}
	if summary["deployment_mode"] != "managed_platform" {
		t.Fatalf("expected redacted summary deployment_mode, got %v", summary["deployment_mode"])
	}
	sourcePrivacy, ok := summary["source_privacy"].(map[string]any)
	if !ok {
		t.Fatalf("expected redacted source_privacy object, got %T", summary["source_privacy"])
	}
	if sourcePrivacy["deployment_mode"] != "managed_platform" {
		t.Fatalf("expected redacted source_privacy deployment_mode, got %v", sourcePrivacy["deployment_mode"])
	}
}
