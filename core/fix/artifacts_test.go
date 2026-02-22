package fix

import (
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildPRArtifactsDeterministic(t *testing.T) {
	t.Parallel()

	plan := Plan{
		RequestedTop: 3,
		Fingerprint:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Remediations: []Remediation{
			{
				ID:            "1111111111111111111111111111111111111111111111111111111111111111",
				TemplateID:    "WRKR-004",
				Category:      "ci_gate_addition",
				RuleID:        "WRKR-004",
				CommitMessage: "fix(ci-gate) deploy.yml (WRKR-004)",
				Rationale:     "risk_score=9.90; reasons=autonomy_multiplier=1.30",
				PatchPreview:  "--- a/.github/workflows/deploy.yml\n+++ b/.github/workflows/deploy.yml\n@@ wrkr-fix @@\n+# wrkr template: WRKR-004\n",
				Finding:       findingFixture(".github/workflows/deploy.yml"),
			},
		},
	}

	first, err := BuildPRArtifacts(plan)
	if err != nil {
		t.Fatalf("build artifacts: %v", err)
	}
	second, err := BuildPRArtifacts(plan)
	if err != nil {
		t.Fatalf("build artifacts second pass: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("artifact count drifted: %d vs %d", len(first), len(second))
	}
	if len(first) != 2 {
		t.Fatalf("expected plan + remediation artifact, got %d", len(first))
	}

	wantRoot := filepath.Join(".wrkr/remediations", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	if first[0].Path != filepath.Join(wantRoot, "plan.json") {
		t.Fatalf("unexpected plan path %q", first[0].Path)
	}
	if first[1].Path != filepath.Join(wantRoot, "01-wrkr-004-111111111111.patch") {
		t.Fatalf("unexpected remediation patch path %q", first[1].Path)
	}
	if string(first[0].Content) != string(second[0].Content) || string(first[1].Content) != string(second[1].Content) {
		t.Fatal("expected deterministic artifact content across runs")
	}
}

func findingFixture(location string) model.Finding {
	return model.Finding{
		FindingType: "policy_violation",
		RuleID:      "WRKR-004",
		Severity:    model.SeverityHigh,
		ToolType:    "ci",
		Location:    location,
		Repo:        "acme/backend",
		Org:         "acme",
	}
}
