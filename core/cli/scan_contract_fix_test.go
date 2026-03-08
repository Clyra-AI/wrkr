package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanStateFailureDoesNotWriteAuxiliaryArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	if err := os.Symlink("/System/state.json", statePath); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected exit %d, got %d (%s)", exitRuntime, code, errOut.String())
	}
	assertErrorCode(t, errOut.Bytes(), "runtime_failure")

	for _, name := range []string{"wrkr-manifest.yaml", "identity-chain.json", "proof-chain.json", "proof-signing-key.json"} {
		if _, err := os.Stat(filepath.Join(tmp, name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be absent after state failure, got %v", name, err)
		}
	}
}

func TestScanPolicyWeightOverrideFailureReturnsPolicySchemaViolation(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	policyPath := filepath.Join(tmp, "wrkr-policy.yaml")
	policy := []byte("rules: []\nscore_weights:\n  policy_pass_rate: 101\n")
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--policy", policyPath, "--json"}, &out, &errOut)
	if code != exitPolicyViolation {
		t.Fatalf("expected exit %d, got %d (%s)", exitPolicyViolation, code, errOut.String())
	}
	assertPolicyError(t, errOut.Bytes(), "policy_schema_violation", exitPolicyViolation)
}

func assertPolicyError(t *testing.T, payload []byte, expectedCode string, expectedExit int) {
	t.Helper()

	var envelope map[string]any
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("parse error payload: %v (%q)", err, string(payload))
	}
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", envelope)
	}
	if errorPayload["code"] != expectedCode {
		t.Fatalf("expected error code %q, got %v", expectedCode, errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(expectedExit) {
		t.Fatalf("expected exit_code=%d, got %v", expectedExit, errorPayload["exit_code"])
	}
}
