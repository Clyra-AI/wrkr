package score

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
)

func TestComputeDeterministicScoreAndGrade(t *testing.T) {
	t.Parallel()
	result := Compute(Input{
		Findings:        []model.Finding{{FindingType: "policy_check", CheckResult: model.CheckResultPass, Severity: model.SeverityLow}},
		Identities:      []manifest.IdentityRecord{{Present: true, ApprovalState: "valid"}},
		ProfileResult:   profileeval.Result{CompliancePercent: 90},
		TransitionCount: 0,
		Weights:         scoremodel.DefaultWeights(),
	})
	if result.Score <= 0 {
		t.Fatalf("expected positive score, got %.2f", result.Score)
	}
	if result.Grade == "F" {
		t.Fatalf("unexpected grade for healthy profile: %s", result.Grade)
	}
}

func TestLoadWeightsValidation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	policyPath := filepath.Join(tmp, "wrkr-policy.yaml")
	payload := []byte("score_weights:\n  policy_pass_rate: 40\n  approval_coverage: 20\n  severity_distribution: 20\n  profile_compliance: 10\n  drift_rate: 10\n")
	if err := os.WriteFile(policyPath, payload, 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	weights, err := LoadWeights(policyPath, "")
	if err != nil {
		t.Fatalf("load weights: %v", err)
	}
	if err := weights.Validate(); err != nil {
		t.Fatalf("validate weights: %v", err)
	}
}
