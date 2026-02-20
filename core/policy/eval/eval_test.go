package eval

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy"
)

func TestEvaluateEmitsChecksAndViolations(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{
		{ID: "WRKR-001", Title: "tool config", Severity: "high", Kind: "require_tool_config", Version: 1},
		{ID: "WRKR-002", Title: "no secret", Severity: "high", Kind: "block_secret_presence", Version: 1},
	}
	findings := []model.Finding{{FindingType: "tool_config", Severity: model.SeverityLow, ToolType: "claude", Location: ".claude", Org: "local"}}
	out := Evaluate("repo", "org", findings, rules)

	checks := 0
	violations := 0
	for _, finding := range out {
		switch finding.FindingType {
		case "policy_check":
			checks++
		case "policy_violation":
			violations++
		}
	}
	if checks != 2 {
		t.Fatalf("expected 2 policy checks, got %d", checks)
	}
	if violations != 0 {
		t.Fatalf("expected no policy violations, got %d", violations)
	}
}

func TestRuleWRKR015FailsWhenExecRatioAboveThreshold(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{ID: "WRKR-015", Title: "sprawl", Severity: "medium", Kind: "skill_sprawl_exec_ratio", Version: 1}}
	findings := []model.Finding{{
		FindingType: "skill_metrics",
		Severity:    model.SeverityMedium,
		ToolType:    "skill",
		Location:    ".agents/skills",
		Org:         "local",
		Evidence: []model.Evidence{{
			Key:   "skill_privilege_concentration.exec_ratio",
			Value: "0.80",
		}},
	}}
	out := Evaluate("repo", "org", findings, rules)

	foundViolation := false
	for _, finding := range out {
		if finding.FindingType == "policy_violation" && finding.RuleID == "WRKR-015" {
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Fatal("expected WRKR-015 policy violation")
	}
}
