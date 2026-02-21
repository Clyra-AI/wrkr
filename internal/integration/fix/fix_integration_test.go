package fixintegration

import (
	"encoding/json"
	"testing"

	"github.com/Clyra-AI/wrkr/core/fix"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestIntegrationBuildPlanProducesTopThreeDeterministicRemediations(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		{Score: 9.8, Finding: model.Finding{FindingType: "policy_violation", RuleID: "WRKR-004", ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"}, Reasons: []string{"autonomy_multiplier=1.3"}},
		{Score: 9.4, Finding: model.Finding{FindingType: "skill_policy_conflict", ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "backend", Org: "acme"}, Reasons: []string{"skill_policy_conflict_high_severity"}},
		{Score: 8.7, Finding: model.Finding{FindingType: "ai_dependency", ToolType: "dependency", Location: "go.mod", Repo: "backend", Org: "acme"}, Reasons: []string{"trust_deficit=2.1"}},
		{Score: 8.1, Finding: model.Finding{FindingType: "mcp_server", ToolType: "mcp", Location: ".codex/config.toml", Repo: "backend", Org: "acme"}, Reasons: []string{"blast_radius=4.5"}},
	}

	planA, err := fix.BuildPlan(ranked, 3)
	if err != nil {
		t.Fatalf("build plan A: %v", err)
	}
	planB, err := fix.BuildPlan(ranked, 3)
	if err != nil {
		t.Fatalf("build plan B: %v", err)
	}
	if len(planA.Remediations) != 3 {
		t.Fatalf("expected 3 remediations, got %d", len(planA.Remediations))
	}
	for _, item := range planA.Remediations {
		if item.PatchPreview == "" {
			t.Fatalf("expected patch preview for %+v", item)
		}
		if item.CommitMessage == "" {
			t.Fatalf("expected commit message for %+v", item)
		}
	}

	blobA, _ := json.Marshal(planA)
	blobB, _ := json.Marshal(planB)
	if string(blobA) != string(blobB) {
		t.Fatalf("expected deterministic plan output\nA=%s\nB=%s", blobA, blobB)
	}
}

func TestIntegrationUnsupportedFindingsReturnReasonCodes(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		{Score: 9.9, Finding: model.Finding{FindingType: "unknown", ToolType: "misc", Location: "README.md", Repo: "backend", Org: "acme"}},
	}
	plan, err := fix.BuildPlan(ranked, 1)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Remediations) != 0 {
		t.Fatalf("expected no remediations, got %d", len(plan.Remediations))
	}
	if len(plan.Skipped) != 1 {
		t.Fatalf("expected one skipped finding, got %d", len(plan.Skipped))
	}
	if plan.Skipped[0].ReasonCode != fix.ReasonUnsupportedFindingType {
		t.Fatalf("expected unsupported reason code, got %+v", plan.Skipped[0])
	}
}
