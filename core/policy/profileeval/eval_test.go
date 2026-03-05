package profileeval

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy/profile"
)

func TestEvaluateComplianceAndDelta(t *testing.T) {
	t.Parallel()
	p := profile.Profile{Name: "standard", MinCompliance: 80, RuleThreshold: map[string]int{"WRKR-013": 0, "WRKR-014": 0}}
	findings := []model.Finding{
		{FindingType: "policy_check", RuleID: "WRKR-013", CheckResult: model.CheckResultPass},
		{FindingType: "policy_check", RuleID: "WRKR-014", CheckResult: model.CheckResultFail},
	}
	previous := &Result{CompliancePercent: 100}
	result := Evaluate(p, findings, previous)
	if result.CompliancePercent != 50 {
		t.Fatalf("expected compliance 50, got %.2f", result.CompliancePercent)
	}
	if result.DeltaPercent != -50 {
		t.Fatalf("expected delta -50, got %.2f", result.DeltaPercent)
	}
	if len(result.Fails) != 1 || result.Fails[0] != "WRKR-014" {
		t.Fatalf("unexpected failing rules: %+v", result.Fails)
	}
}

func TestProfileEval_NormalizesRuleAliasesDeterministically(t *testing.T) {
	t.Parallel()

	p := profile.Profile{
		Name:          "standard",
		MinCompliance: 80,
		RuleThreshold: map[string]int{"WRKR-A014": 0},
	}
	findings := []model.Finding{
		{FindingType: "policy_check", RuleID: "wrkr-014", CheckResult: model.CheckResultFail},
	}
	result := Evaluate(p, findings, nil)
	if len(result.Fails) != 1 || result.Fails[0] != "WRKR-A014" {
		t.Fatalf("expected alias-normalized failure list, got %+v", result.Fails)
	}
	if len(result.Rationale) != 1 || result.Rationale[0] != "WRKR-A014 fail_count=1 threshold=0" {
		t.Fatalf("expected deterministic alias rationale, got %+v", result.Rationale)
	}
}

func TestProfileEval_AgentRuleAliasCompatibility(t *testing.T) {
	t.Parallel()

	p := profile.Profile{
		Name:          "standard",
		MinCompliance: 80,
		RuleThreshold: map[string]int{"WRKR-A010": 0},
	}
	findings := []model.Finding{
		{FindingType: "policy_check", RuleID: "WRKR-010", CheckResult: model.CheckResultFail},
	}

	result := Evaluate(p, findings, nil)
	if len(result.Fails) != 1 || result.Fails[0] != "WRKR-A010" {
		t.Fatalf("expected WRKR-A010 alias-normalized failure, got %+v", result.Fails)
	}
	if len(result.Rationale) != 1 || result.Rationale[0] != "WRKR-A010 fail_count=1 threshold=0" {
		t.Fatalf("unexpected rationale: %+v", result.Rationale)
	}
}
