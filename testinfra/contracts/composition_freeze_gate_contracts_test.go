package contracts

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCompositionPublicSurfaceRequiresSprint0FreezeGateReceipt(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	receipt := mustReadJSON(t, filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "freeze-gate", "story-0.1-receipt.json"))
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
