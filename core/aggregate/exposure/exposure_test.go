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

func TestBuildIncludesGatewayCoverageFactors(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "mcp_gateway_posture",
			ToolType:    "mcp",
			Location:    ".mcp.json",
			Repo:        "payments",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "coverage", Value: "unprotected"}},
		},
		{
			FindingType: "a2a_agent_card",
			ToolType:    "a2a_agent",
			Location:    ".well-known/agent.json",
			Repo:        "payments",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "coverage", Value: "protected"}},
		},
	}
	out := Build(findings, map[string]float64{"acme::payments": 6.2})
	if len(out) != 1 {
		t.Fatalf("expected one summary, got %d", len(out))
	}

	factors := out[0].ExposureFactors
	hasProtected := false
	hasUnprotected := false
	for _, factor := range factors {
		if factor == "gateway_protected=1" {
			hasProtected = true
		}
		if factor == "gateway_unprotected=1" {
			hasUnprotected = true
		}
	}
	if !hasProtected || !hasUnprotected {
		t.Fatalf("expected gateway coverage factors in exposure_factors, got %v", factors)
	}
}
