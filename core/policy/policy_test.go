package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesIncludesBuiltinPack(t *testing.T) {
	t.Parallel()

	rules, err := LoadRules("", "")
	if err != nil {
		t.Fatalf("load builtin rules: %v", err)
	}
	if len(rules) != 15 {
		t.Fatalf("expected 15 builtin rules, got %d", len(rules))
	}
}

func TestLoadRulesMergesCustomPolicy(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	custom := filepath.Join(tmp, "wrkr-policy.yaml")
	payload := []byte("rules:\n  - id: WRKR-015\n    title: Override\n    severity: low\n    remediation: custom\n    kind: skill_sprawl_exec_ratio\n    version: 1\n")
	if err := os.WriteFile(custom, payload, 0o600); err != nil {
		t.Fatalf("write custom policy: %v", err)
	}

	rules, err := LoadRules(custom, "")
	if err != nil {
		t.Fatalf("load merged rules: %v", err)
	}
	found := false
	for _, rule := range rules {
		if rule.ID == "WRKR-015" {
			found = true
			if rule.Title != "Override" {
				t.Fatalf("expected override title, got %s", rule.Title)
			}
		}
	}
	if !found {
		t.Fatal("expected WRKR-015 in merged rules")
	}
}
