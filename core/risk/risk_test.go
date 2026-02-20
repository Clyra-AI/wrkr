package risk

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestScoreOrdersHeadlessHigherThanInteractive(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{FindingType: "ci_autonomy", Severity: model.SeverityHigh, ToolType: "ci_agent", Location: ".github/workflows/a.yml", Repo: "repo", Org: "acme", Autonomy: "interactive", Permissions: []string{"secret.read"}},
		{FindingType: "ci_autonomy", Severity: model.SeverityHigh, ToolType: "ci_agent", Location: ".github/workflows/b.yml", Repo: "repo", Org: "acme", Autonomy: "headless_auto", Permissions: []string{"secret.read"}},
	}
	report := Score(findings, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC))
	if len(report.Ranked) != 2 {
		t.Fatalf("expected 2 ranked findings, got %d", len(report.Ranked))
	}
	if report.Ranked[0].AutonomyLevel != "headless_auto" {
		t.Fatalf("expected headless_auto to rank first, got %s", report.Ranked[0].AutonomyLevel)
	}
}

func TestSkillConflictCorrelation(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{FindingType: "policy_violation", RuleID: "WRKR-014", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-014", Repo: "repo", Org: "acme"},
		{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".claude/skills/deploy/SKILL.md", Repo: "repo", Org: "acme"},
	}
	report := Score(findings, 5, time.Time{})
	if len(report.Ranked) != 1 {
		t.Fatalf("expected deduped canonical conflict count 1, got %d", len(report.Ranked))
	}
}

func TestCompiledActionAmplification(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{{
		FindingType: "compiled_action",
		Severity:    model.SeverityMedium,
		ToolType:    "compiled_action",
		Location:    "agent-plans/release.agent-script.json",
		Repo:        "repo",
		Org:         "acme",
		Evidence:    []model.Evidence{{Key: "tool_sequence", Value: "gait.eval.script,mcp"}},
	}}
	report := Score(findings, 5, time.Time{})
	if report.Ranked[0].Score <= 5 {
		t.Fatalf("expected amplified score, got %.2f", report.Ranked[0].Score)
	}
}
