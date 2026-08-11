package score

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
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
	if result.PolicySignalBasis != "grouped_policy_outcomes" {
		t.Fatalf("expected grouped policy basis, got %+v", result)
	}
}

func TestComputeGroupsPolicyFanoutBeforeScoring(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "tool_detected", ToolType: "codex", Location: ".codex/config.toml", Severity: model.SeverityLow, Org: "acme"},
		{FindingType: "policy_check", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_violation", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_check", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-b"},
		{FindingType: "policy_violation", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-b"},
	}

	result := Compute(Input{
		Findings:       findings,
		PolicyOutcomes: outputsignal.BuildPolicyOutcomes(findings),
		Identities:     []manifest.IdentityRecord{{Present: true, ApprovalState: "valid"}},
		ProfileResult:  profileeval.Result{CompliancePercent: 90},
		Weights:        scoremodel.DefaultWeights(),
	})

	if result.Breakdown.PolicyPassRate != 0 {
		t.Fatalf("expected grouped failing policy outcome to yield 0 pass rate, got %+v", result.Breakdown)
	}
	if result.Breakdown.SeverityDistribution != 60 {
		t.Fatalf("expected grouped severity distribution of 60.00, got %+v", result.Breakdown)
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

func TestSummarizeOperationalExposureSeparatesHighImpactPaths(t *testing.T) {
	t.Parallel()

	summary := SummarizeOperationalExposure([]risk.ActionPath{
		{
			WriteCapable:     true,
			CredentialAccess: true,
			ProductionWrite:  true,
			DeploymentStatus: "deployed",
		},
		{
			WriteCapable: true,
		},
	})
	if summary.Grade != "critical" {
		t.Fatalf("expected critical operational exposure, got %+v", summary)
	}
	if summary.Driver != "production_and_credentials" {
		t.Fatalf("expected production_and_credentials driver, got %+v", summary)
	}
}

func TestSummarizeOperationalExposureDoesNotCallDeploymentSurfaceProductionBacked(t *testing.T) {
	t.Parallel()

	summary := SummarizeOperationalExposure([]risk.ActionPath{{
		CredentialAccess: true,
		DeploymentStatus: "deployed",
	}})
	if summary.Grade != "critical" || summary.Driver != "delivery_surface_and_credentials" {
		t.Fatalf("expected credential-bearing delivery surface to remain critical, got %+v", summary)
	}
	if !slices.Contains(summary.Rationale, "production_target_backed_paths=0") || !slices.Contains(summary.Rationale, "deployment_surface_paths=1") {
		t.Fatalf("expected explicit production and inferred delivery counts to stay separate, got %+v", summary.Rationale)
	}
}

func TestSummarizeOperationalExposureGradesEachEvidenceBasis(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   risk.ActionPath
		grade  string
		driver string
	}{
		{name: "credential", path: risk.ActionPath{CredentialAccess: true}, grade: "high", driver: "credential_or_production"},
		{name: "production target", path: risk.ActionPath{ProductionWrite: true}, grade: "high", driver: "credential_or_production"},
		{name: "deployment surface", path: risk.ActionPath{DeploymentStatus: "deployed"}, grade: "high", driver: "delivery_surface"},
		{name: "write capable", path: risk.ActionPath{WriteCapable: true}, grade: "medium", driver: "write_capable"},
		{name: "review only", path: risk.ActionPath{}, grade: "low", driver: "review_only"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			summary := SummarizeOperationalExposure([]risk.ActionPath{test.path})
			if summary.Grade != test.grade || summary.Driver != test.driver {
				t.Fatalf("expected grade=%s driver=%s, got %+v", test.grade, test.driver, summary)
			}
		})
	}
}

func TestSummarizeGovernanceReadinessSeparatesCoverageAndControlGaps(t *testing.T) {
	t.Parallel()

	summary := SummarizeGovernanceReadiness([]risk.ActionPath{
		{
			ApprovalGap:          true,
			OwnershipStatus:      "unresolved",
			OwnershipState:       "missing",
			PolicyCoverageStatus: "none",
		},
	}, 1, true)
	if summary.Grade != "low" {
		t.Fatalf("expected low governance readiness, got %+v", summary)
	}
	if summary.Driver != "governance_gaps_present" {
		t.Fatalf("expected governance gap driver, got %+v", summary)
	}
}
