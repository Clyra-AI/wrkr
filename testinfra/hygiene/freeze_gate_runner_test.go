package hygiene

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFreezeGateRunnerExecutesTestsAndBindsRuntimeReceipt(t *testing.T) {
	t.Parallel()

	fixtureRoot, receiptPath := initializeFreezeGateFixture(t)
	outputPath := filepath.Join(fixtureRoot, "runtime-receipt.json")
	stdout, stderr, err := runFreezeGate(t, fixtureRoot,
		"--receipt", receiptPath,
		"--output", outputPath,
		"--require-clean",
	)
	if err != nil {
		t.Fatalf("expected freeze gate to pass, err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}

	raw := mustReadFile(t, outputPath)
	var receipt map[string]any
	if err := json.Unmarshal([]byte(raw), &receipt); err != nil {
		t.Fatalf("parse runtime receipt: %v", err)
	}
	if receipt["status"] != "pass" || receipt["worktree_dirty"] != false {
		t.Fatalf("runtime receipt must prove a clean passing run: %v", receipt)
	}
	head := strings.TrimSpace(runGitForFreezeGate(t, fixtureRoot, "rev-parse", "HEAD"))
	if receipt["commit_sha"] != head {
		t.Fatalf("runtime receipt commit mismatch: got %v want %s", receipt["commit_sha"], head)
	}
	sourceReceiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read source receipt: %v", err)
	}
	sourceReceiptSum := sha256.Sum256(sourceReceiptBytes)
	if got, want := receipt["source_receipt_sha256"], hex.EncodeToString(sourceReceiptSum[:]); got != want {
		t.Fatalf("runtime receipt source binding mismatch: got %v want %s", got, want)
	}
	results, ok := receipt["command_results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("runtime receipt must include one command result: %v", receipt["command_results"])
	}
	result, ok := results[0].(map[string]any)
	if !ok || result["exit_code"] != float64(0) || strings.TrimSpace(freezeStringValue(result["output_sha256"])) == "" {
		t.Fatalf("runtime command result must prove execution: %v", results[0])
	}
}

func TestFreezeGateRunnerRejectsSourceChangedAfterReceipt(t *testing.T) {
	t.Parallel()

	fixtureRoot, receiptPath := initializeFreezeGateFixture(t)
	mustWriteFile(t, filepath.Join(fixtureRoot, "guarded.txt"), "changed after receipt\n")
	stdout, stderr, err := runFreezeGate(t, fixtureRoot,
		"--receipt", receiptPath,
		"--metadata-only",
	)
	if err == nil {
		t.Fatalf("expected stale source-bound receipt to fail, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stderr, "receipt content digest is stale") {
		t.Fatalf("expected deterministic stale digest error, got %q", stderr)
	}
}

func initializeFreezeGateFixture(t *testing.T) (string, string) {
	t.Helper()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "go.mod"), "module example.com/freezegate\n\ngo 1.26.5\n")
	mustWriteFile(t, filepath.Join(root, "gate_test.go"), "package freezegate\n\nimport \"testing\"\n\nfunc TestGate(t *testing.T) {}\n")
	guardedContent := []byte("guarded source\n")
	if err := os.WriteFile(filepath.Join(root, "guarded.txt"), guardedContent, 0o644); err != nil {
		t.Fatalf("write guarded source: %v", err)
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte("guarded.txt"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(guardedContent)
	_, _ = digest.Write([]byte{0})
	receipt := map[string]any{
		"validation_contract_version": 2,
		"validated_content_sha256":    hex.EncodeToString(digest.Sum(nil)),
		"validation_scope_paths":      []string{"guarded.txt"},
		"status":                      "green",
		"artifact_size_deltas": []map[string]any{{
			"artifact":           "fixture",
			"fixture":            "freeze-gate-test",
			"measured_bytes":     1,
			"baseline_bytes":     0,
			"budget_bytes":       2,
			"delta_bytes":        1,
			"measurement_source": "TestGate",
		}},
		"validations": []map[string]any{{
			"name":          "fixture",
			"status":        "pass",
			"commands":      []string{"go test ./... -count=1"},
			"fixture_names": []string{"freeze-gate-test"},
		}},
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatalf("marshal freeze-gate receipt: %v", err)
	}
	receiptPath := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(receiptPath, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write freeze-gate receipt: %v", err)
	}

	runGitForFreezeGate(t, root, "init", "-q")
	runGitForFreezeGate(t, root, "config", "user.name", "Freeze Gate Test")
	runGitForFreezeGate(t, root, "config", "user.email", "freeze-gate@example.test")
	runGitForFreezeGate(t, root, "add", "go.mod", "gate_test.go", "guarded.txt", "receipt.json")
	runGitForFreezeGate(t, root, "commit", "-q", "-m", "fixture")
	return root, receiptPath
}

func runFreezeGate(t *testing.T, fixtureRoot string, args ...string) (string, string, error) {
	t.Helper()

	script := filepath.Join(mustFindRepoRoot(t), "scripts", "run_freeze_gate.py")
	command := append([]string{script, "--repo-root", fixtureRoot}, args...)
	cmd := exec.Command("python3", command...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func runGitForFreezeGate(t *testing.T, root string, args ...string) string {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v (%s)", args, err, output)
	}
	return string(output)
}

func freezeStringValue(value any) string {
	text, _ := value.(string)
	return text
}
