package compliance

import (
	"reflect"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildRollupSummaryDeterministic(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "policy_violation", RuleID: "WRKR-A001", Severity: model.SeverityHigh, ToolType: "codex", Location: ".codex/config.toml", Repo: "repo", Org: "acme"},
		{FindingType: "policy_violation", RuleID: "WRKR-A010", Severity: model.SeverityHigh, ToolType: "mcp", Location: ".mcp.json", Repo: "repo", Org: "acme"},
		{FindingType: "policy_violation", RuleID: "WRKR-A010", Severity: model.SeverityHigh, ToolType: "mcp", Location: ".mcp.json", Repo: "repo", Org: "acme"},
	}

	chain := proof.NewChain("wrkr-proof")
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          "risk_assessment",
		Event: map[string]any{
			"assessment_type": "finding_risk",
			"finding": map[string]any{
				"rule_id": "WRKR-A010",
			},
		},
		Relationship: &proof.Relationship{
			PolicyRef: &proof.PolicyRef{
				PolicyID:       "wrkr-policy",
				MatchedRuleIDs: []string{"WRKR-A001", "WRKR-A010"},
			},
		},
		Controls: proof.Controls{PermissionsEnforced: true},
	})
	if err != nil {
		t.Fatalf("new record: %v", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		t.Fatalf("append record: %v", err)
	}

	first, err := BuildRollupSummary(findings, chain)
	if err != nil {
		t.Fatalf("build rollup summary: %v", err)
	}
	second, err := BuildRollupSummary(findings, chain)
	if err != nil {
		t.Fatalf("build rollup summary second run: %v", err)
	}

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("rollup summary must be deterministic\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first.Frameworks) != 3 {
		t.Fatalf("expected 3 framework rollups, got %d", len(first.Frameworks))
	}
	if first.Frameworks[0].FrameworkID != "eu-ai-act" || first.Frameworks[1].FrameworkID != "pci-dss" || first.Frameworks[2].FrameworkID != "soc2" {
		t.Fatalf("unexpected framework order: %+v", first.Frameworks)
	}

	var soc2 FrameworkRollup
	for _, framework := range first.Frameworks {
		if framework.FrameworkID == "soc2" {
			soc2 = framework
			break
		}
	}
	if soc2.MappedFindingCount != 2 {
		t.Fatalf("expected 2 distinct mapped findings for soc2, got %d", soc2.MappedFindingCount)
	}
	counts := map[string]int{}
	for _, control := range soc2.Controls {
		counts[control.ControlID] = control.FindingCount
	}
	if counts["cc6"] != 1 || counts["cc7"] != 1 || counts["cc8"] != 2 {
		t.Fatalf("unexpected soc2 control finding counts: %+v", counts)
	}
}

func TestExplainRollupSummaryUsesStableHumanText(t *testing.T) {
	t.Parallel()

	lines := ExplainRollupSummary(RollupSummary{
		Frameworks: []FrameworkRollup{
			{
				FrameworkID: "soc2",
				Title:       "SOC2",
				Controls: []ControlRollup{
					{ControlID: "cc6", Title: "Logical Access", FindingCount: 2},
					{ControlID: "cc7", Title: "Operations", FindingCount: 0},
				},
			},
		},
	}, 5)

	expected := []string{"2 findings map to SOC2 CC6 (Logical Access)"}
	if !reflect.DeepEqual(lines, expected) {
		t.Fatalf("unexpected explain lines\nwant=%v\ngot=%v", expected, lines)
	}
}
