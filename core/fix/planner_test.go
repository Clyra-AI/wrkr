package fix

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildPlanTopThreeDeterministic(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		scored(9.9, model.Finding{FindingType: "policy_violation", RuleID: "WRKR-004", ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "acme/backend", Org: "acme"}, "autonomy_multiplier=1.30"),
		scored(9.3, model.Finding{FindingType: "skill_policy_conflict", ToolType: "skill", Location: ".agents/skills/deploy/SKILL.md", Repo: "acme/backend", Org: "acme"}, "skill_policy_conflict_high_severity"),
		scored(8.7, model.Finding{FindingType: "mcp_server", ToolType: "mcp", Location: ".codex/config.toml", Repo: "acme/backend", Org: "acme"}, "trust_deficit=2.50"),
		scored(7.1, model.Finding{FindingType: "ai_dependency", ToolType: "dependency", Location: "package.json", Repo: "acme/backend", Org: "acme"}, "privilege_level=2.10"),
	}

	first, err := BuildPlan(ranked, 3)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	second, err := BuildPlan(ranked, 3)
	if err != nil {
		t.Fatalf("build plan second pass: %v", err)
	}

	if len(first.Remediations) != 3 {
		t.Fatalf("expected three remediations, got %d", len(first.Remediations))
	}
	if first.Fingerprint == "" {
		t.Fatal("expected non-empty deterministic fingerprint")
	}

	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("expected deterministic output\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
}

func TestBuildPlanUnsupportedReasonCodes(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		scored(9.0, model.Finding{FindingType: "unknown_type", ToolType: "mystery", Location: "README.md", Repo: "r", Org: "o"}),
		scored(8.5, model.Finding{FindingType: "ai_dependency", ToolType: "dependency", Location: "", Repo: "r", Org: "o"}),
	}

	plan, err := BuildPlan(ranked, 2)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Remediations) != 0 {
		t.Fatalf("expected no remediations, got %d", len(plan.Remediations))
	}
	if len(plan.Skipped) != 2 {
		t.Fatalf("expected two skipped records, got %d", len(plan.Skipped))
	}

	codes := []string{plan.Skipped[0].ReasonCode, plan.Skipped[1].ReasonCode}
	joined := strings.Join(codes, ",")
	if !strings.Contains(joined, ReasonUnsupportedFindingType) {
		t.Fatalf("expected unsupported reason code in %v", codes)
	}
	if !strings.Contains(joined, ReasonMissingLocation) {
		t.Fatalf("expected missing-location reason code in %v", codes)
	}
}

func TestBuildPlanPolicyRuleTemplateSelection(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		scored(9.4, model.Finding{FindingType: "policy_violation", RuleID: "wrkr-006", ToolType: "dependency", Location: "go.mod", Repo: "r", Org: "o"}),
	}

	plan, err := BuildPlan(ranked, 1)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Remediations) != 1 {
		t.Fatalf("expected one remediation, got %d", len(plan.Remediations))
	}
	if plan.Remediations[0].TemplateID != "WRKR-006" {
		t.Fatalf("expected WRKR-006 template, got %q", plan.Remediations[0].TemplateID)
	}
	if !strings.Contains(plan.Remediations[0].PatchPreview, "wrkr template: WRKR-006") {
		t.Fatalf("expected template marker in patch preview, got %q", plan.Remediations[0].PatchPreview)
	}
}

func scored(score float64, finding model.Finding, reasons ...string) risk.ScoredFinding {
	return risk.ScoredFinding{
		Score:   score,
		Reasons: append([]string(nil), reasons...),
		Finding: finding,
	}
}
