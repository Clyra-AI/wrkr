package contracts

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompositionPublicSurfaceRequiresSprint0FreezeGateReceipt(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	receipt := mustReadJSON(t, filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "freeze-gate", "story-0.1-receipt.json"))
	if receipt["validation_contract_version"] != float64(2) {
		t.Fatalf("composition public-surface receipt must use validation contract v2, got %v", receipt["validation_contract_version"])
	}
	digest, _ := receipt["validated_content_sha256"].(string)
	decodedDigest, err := hex.DecodeString(digest)
	if err != nil || len(decodedDigest) != 32 {
		t.Fatalf("composition public-surface receipt must carry a sha256 content binding, got %q", digest)
	}
	scopes, ok := receipt["validation_scope_paths"].([]any)
	if !ok || len(scopes) == 0 {
		t.Fatalf("composition public-surface receipt missing validation scopes: %v", receipt["validation_scope_paths"])
	}
	if receipt["status"] != "green" {
		t.Fatalf("composition public-surface receipt must be green, got %v", receipt["status"])
	}
	if receipt["plan_path"] != "product/plans/adhoc/PLAN_ADHOC_2026-07-13_143619_composed-action-path-contracts.md" {
		t.Fatalf("composition public-surface receipt points at unexpected plan: %v", receipt["plan_path"])
	}

	validations, ok := receipt["validations"].([]any)
	if !ok || len(validations) == 0 {
		t.Fatalf("composition public-surface receipt missing validations: %v", receipt)
	}
	required := map[string]bool{
		"output_size_budget":  false,
		"redaction":           false,
		"recursive_redaction": false,
		"clone_strip":         false,
		"readability":         false,
		"finding_noise":       false,
	}
	for _, raw := range validations {
		row, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("validation row is not an object: %v", raw)
		}
		name, _ := row["name"].(string)
		if _, wanted := required[name]; !wanted {
			continue
		}
		if row["status"] != "pass" {
			t.Fatalf("validation %s must pass, got %v", name, row["status"])
		}
		if commands, ok := row["commands"].([]any); !ok || len(commands) == 0 {
			t.Fatalf("validation %s must name commands, got %v", name, row["commands"])
		}
		if fixtures, ok := row["fixture_names"].([]any); !ok || len(fixtures) == 0 {
			t.Fatalf("validation %s must name fixtures, got %v", name, row["fixture_names"])
		}
		required[name] = true
	}
	for name, seen := range required {
		if !seen {
			t.Fatalf("composition public-surface receipt missing validation %s", name)
		}
	}

	sizeRows, ok := receipt["artifact_size_deltas"].([]any)
	if !ok || len(sizeRows) == 0 {
		t.Fatalf("composition public-surface receipt missing measured size rows: %v", receipt["artifact_size_deltas"])
	}
	for idx, raw := range sizeRows {
		row, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("artifact_size_deltas[%d] is not an object: %v", idx, raw)
		}
		measured, measuredOK := row["measured_bytes"].(float64)
		baseline, baselineOK := row["baseline_bytes"].(float64)
		budget, budgetOK := row["budget_bytes"].(float64)
		delta, deltaOK := row["delta_bytes"].(float64)
		if !measuredOK || !baselineOK || !budgetOK || !deltaOK {
			t.Fatalf("artifact_size_deltas[%d] missing numeric measurement fields: %v", idx, row)
		}
		if measured <= 0 || baseline < 0 || budget <= 0 || measured > budget {
			t.Fatalf("artifact_size_deltas[%d] has invalid measured/baseline/budget values: %v", idx, row)
		}
		if measured-baseline != delta {
			t.Fatalf("artifact_size_deltas[%d] delta must equal measured-baseline: %v", idx, row)
		}
		if strings.TrimSpace(stringValue(row["measurement_source"])) == "" {
			t.Fatalf("artifact_size_deltas[%d] missing measurement source: %v", idx, row)
		}
	}
}

func TestCompositionPublicSchemaFieldsReferenceFreezeGateReceipt(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	receipt := "testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json"
	docs := []string{
		mustReadFile(t, filepath.Join(repoRoot, "docs", "commands", "report.md")),
		mustReadFile(t, filepath.Join(repoRoot, "docs", "commands", "scan.md")),
	}
	for _, content := range docs {
		for _, required := range []string{
			"Sprint 0 output-safety freeze",
			receipt,
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("composition docs must mention %q", required)
			}
		}
	}
}

func TestCompositionFreezeGateRuntimeReceiptIsRequiredByCI(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	makefile := mustReadFile(t, filepath.Join(repoRoot, "Makefile"))
	for _, required := range []string{
		"test-freeze-gate:",
		"scripts/run_freeze_gate.py",
		".tmp/freeze-gate-runtime-receipt.json",
	} {
		if !strings.Contains(makefile, required) {
			t.Fatalf("Makefile must require freeze-gate runtime evidence %q", required)
		}
	}
	for _, workflow := range []string{"pr.yml", "main.yml", "release.yml"} {
		content := mustReadFile(t, filepath.Join(repoRoot, ".github", "workflows", workflow))
		for _, required := range []string{
			"make test-freeze-gate FREEZE_GATE_REQUIRE_CLEAN=--require-clean",
			"freeze-gate-runtime-receipt.json",
			"if-no-files-found: error",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("%s must preserve current-head freeze-gate evidence %q", workflow, required)
			}
		}
	}
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
