//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestPolicyComplianceMappingScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	requiredChecks := map[string]string{
		"WRKR-A001": "fail",
		"WRKR-A002": "fail",
		"WRKR-A004": "pass",
	}
	seenChecks := map[string]string{}
	seenViolations := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ruleID, _ := finding["rule_id"].(string)
		if finding["finding_type"] == "policy_check" && ruleID != "" {
			seenChecks[ruleID], _ = finding["check_result"].(string)
		}
		if finding["finding_type"] == "policy_violation" && ruleID != "" {
			seenViolations[ruleID] = true
		}
	}
	for ruleID, want := range requiredChecks {
		if got := seenChecks[ruleID]; got != want {
			t.Fatalf("unexpected policy_check result for %s: got %q want %q (all=%v)", ruleID, got, want, seenChecks)
		}
		if want == "fail" && !seenViolations[ruleID] {
			t.Fatalf("expected policy_violation for %s, got %v", ruleID, seenViolations)
		}
	}

	summary, ok := payload["compliance_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected compliance_summary payload, got %T", payload["compliance_summary"])
	}
	frameworks, ok := summary["frameworks"].([]any)
	if !ok || len(frameworks) == 0 {
		t.Fatalf("expected framework rollups, got %v", summary["frameworks"])
	}
	mapped := false
	for _, item := range frameworks {
		framework, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if count, ok := framework["mapped_finding_count"].(float64); ok && count > 0 {
			mapped = true
			break
		}
	}
	if !mapped {
		t.Fatalf("expected compliance summary to preserve mapped agent-rule coverage, got %v", frameworks)
	}
}
