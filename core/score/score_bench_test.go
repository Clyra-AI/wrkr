package score

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
)

func BenchmarkScoreComputeDeterministic(b *testing.B) {
	findings := []model.Finding{
		{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultPass, Severity: model.SeverityLow, ToolType: "policy", Location: "WRKR-001", Repo: "backend", Org: "acme"},
		{FindingType: "policy_check", RuleID: "WRKR-002", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-002", Repo: "backend", Org: "acme"},
		{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".agents/skills/deploy/SKILL.md", Repo: "backend", Org: "acme"},
	}
	identities := []manifest.IdentityRecord{
		{AgentID: "wrkr:cursor:acme", ToolID: "cursor:.cursor/rules/default.mdc", Org: "acme", Present: true, ApprovalState: "valid"},
		{AgentID: "wrkr:codex:acme", ToolID: "codex:AGENTS.md", Org: "acme", Present: true, ApprovalState: "missing"},
	}
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 75}
	weights := scoremodel.DefaultWeights()

	input := Input{
		Findings:        findings,
		Identities:      identities,
		ProfileResult:   profile,
		TransitionCount: 1,
		Weights:         weights,
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Compute(input)
	}
}
