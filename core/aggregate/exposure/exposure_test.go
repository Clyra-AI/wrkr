package exposure

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildIncludesSkillAggregationFields(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{{
		FindingType: "skill_metrics",
		ToolType:    "skill",
		Location:    ".agents/skills",
		Repo:        "payments",
		Org:         "acme",
		Permissions: []string{"proc.exec", "filesystem.write"},
		Evidence: []model.Evidence{
			{Key: "skill_sprawl.total", Value: "4"},
			{Key: "skill_sprawl.exec", Value: "2"},
			{Key: "skill_sprawl.write", Value: "1"},
			{Key: "skill_sprawl.read", Value: "1"},
			{Key: "skill_sprawl.none", Value: "0"},
		},
	}}
	repoRisk := map[string]float64{"acme::payments": 8.4}
	out := Build(findings, repoRisk)
	if len(out) != 1 {
		t.Fatalf("expected one summary, got %d", len(out))
	}
	if len(out[0].SkillPrivilegeCeiling) == 0 {
		t.Fatal("expected skill_privilege_ceiling to be populated")
	}
	if out[0].SkillPrivilegeConcentration.ExecWriteRatio <= 0 {
		t.Fatal("expected non-zero skill_privilege_concentration.exec_write_ratio")
	}
}
