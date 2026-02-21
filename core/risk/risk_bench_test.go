package risk

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/model"
)

func BenchmarkRiskScoreDeterministic(b *testing.B) {
	findings := []model.Finding{
		{FindingType: "policy_violation", RuleID: "WRKR-014", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-014", Repo: "frontend", Org: "acme", Autonomy: "headless_auto"},
		{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "frontend", Org: "acme", Permissions: []string{"proc.exec"}},
		{FindingType: "skill_metrics", Severity: model.SeverityMedium, ToolType: "skill", Location: ".agents/skills", Repo: "frontend", Org: "acme", Permissions: []string{"proc.exec", "filesystem.write"}, Evidence: []model.Evidence{
			{Key: "skill_privilege_concentration.exec_write_ratio", Value: "0.66"},
			{Key: "skill_sprawl.total", Value: "3"},
			{Key: "skill_sprawl.exec", Value: "2"},
			{Key: "skill_sprawl.write", Value: "1"},
		}},
	}
	now := time.Date(2026, 2, 21, 0, 0, 0, 0, time.UTC)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Score(findings, 5, now)
	}
}
