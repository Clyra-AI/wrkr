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
