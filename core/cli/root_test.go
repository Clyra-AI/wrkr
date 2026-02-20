package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunJSON(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), `"status":"ok"`) {
		t.Fatalf("expected json status output, got %q", out.String())
	}
}

func TestRunInvalidFlagReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--nope"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
}

func TestRunInvalidFlagWithJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--json", "--nope"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on parse error, got %q", out.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestInitNonInteractiveWritesConfig(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d with stderr %q", code, errOut.String())
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
}

func TestScanMutuallyExclusiveTargetsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/backend", "--org", "acme", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
}

func TestScanUsesConfiguredDefaultTarget(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	statePath := filepath.Join(tmp, "last-scan.json")

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	initCode := Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &initOut, &initErr)
	if initCode != 0 {
		t.Fatalf("init failed: exit %d stderr %s", initCode, initErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--config", configPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: exit %d stderr %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	target := payload["target"].(map[string]any)
	if target["mode"] != "repo" || target["value"] != "acme/backend" {
		t.Fatalf("unexpected target: %v", target)
	}
}

func TestScanDiffOnlyReturnsDelta(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir pathA: %v", err)
	}

	var out1 bytes.Buffer
	var err1 bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out1, &err1)
	if code != 0 {
		t.Fatalf("first scan failed: %d %s", code, err1.String())
	}
	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta: %v", err)
	}

	var out2 bytes.Buffer
	var err2 bytes.Buffer
	code = Run([]string{"scan", "--path", reposPath, "--state", statePath, "--diff", "--json"}, &out2, &err2)
	if code != 0 {
		t.Fatalf("diff scan failed: %d %s", code, err2.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out2.Bytes(), &payload); err != nil {
		t.Fatalf("parse diff output: %v", err)
	}
	diffPayload, ok := payload["diff"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff object, got %v", payload)
	}
	added, _ := diffPayload["added"].([]any)
	if len(added) == 0 {
		t.Fatalf("expected added findings, got none payload=%v", payload)
	}
	foundNewRepo := false
	for _, item := range added {
		finding, castOK := item.(map[string]any)
		if !castOK {
			continue
		}
		if finding["tool_type"] == "source_repo" && finding["repo"] == "beta" {
			foundNewRepo = true
			break
		}
	}
	if !foundNewRepo {
		t.Fatalf("expected diff to include beta source discovery, payload=%v", payload)
	}
	removed, _ := diffPayload["removed"].([]any)
	if len(removed) != 0 {
		t.Fatalf("expected no removed findings, got %d", len(removed))
	}
}

func TestScanEnrichRequiresNetworkSource(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/backend", "--enrich", "--json"}, &out, &errOut)
	if code != 7 {
		t.Fatalf("expected exit 7, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", payload)
	}
	if errorPayload["code"] != "dependency_missing" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
}
