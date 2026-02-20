package profile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltinProfilesLoad(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"baseline", "standard", "strict"} {
		loaded, err := Builtin(name)
		if err != nil {
			t.Fatalf("load %s: %v", name, err)
		}
		if loaded.Name != name {
			t.Fatalf("unexpected profile name: %s", loaded.Name)
		}
		if len(loaded.RuleThreshold) == 0 {
			t.Fatalf("expected thresholds for %s", name)
		}
	}
}

func TestWithOverrides(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "wrkr-policy.yaml")
	payload := []byte("profiles:\n  standard:\n    min_compliance: 85\n    rule_thresholds:\n      WRKR-015: 1\n")
	if err := os.WriteFile(policyPath, payload, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	base, err := Builtin("standard")
	if err != nil {
		t.Fatalf("load builtin: %v", err)
	}
	overridden, err := WithOverrides(base, policyPath, "")
	if err != nil {
		t.Fatalf("apply overrides: %v", err)
	}
	if overridden.MinCompliance != 85 {
		t.Fatalf("unexpected min compliance %v", overridden.MinCompliance)
	}
	if overridden.RuleThreshold["WRKR-015"] != 1 {
		t.Fatalf("unexpected threshold %+v", overridden.RuleThreshold)
	}
}
