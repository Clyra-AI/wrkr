package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestAgentActionBOMPrimaryViewLineBudget(t *testing.T) {
	t.Parallel()

	items := make([]AgentActionBOMItem, 0, 400)
	for idx := 0; idx < 400; idx++ {
		items = append(items, AgentActionBOMItem{
			PathID:                   fmt.Sprintf("apc-%03d", idx),
			Org:                      "acme",
			Repo:                     fmt.Sprintf("enterprise-%03d", idx),
			ToolType:                 "compiled_action",
			Location:                 fmt.Sprintf(".github/workflows/release-%03d.yml", idx),
			ControlState:             "block_recommended",
			RiskZone:                 "high",
			ReviewBurden:             "high",
			ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
			DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
			RecommendedControl:       risk.RecommendedControlApprovalRequired,
			Remediation:              "Attach owner-approved evidence, verify the release path, and rescan.",
			ProofCoverage:            "missing",
		})
	}

	summary := Summary{
		GeneratedAt:  "2026-06-12T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID:         "bom-sprint0",
			SchemaVersion: AgentActionBOMSchemaVersion,
			Summary: AgentActionBOMSummary{
				TotalItems:        len(items),
				ControlFirstItems: len(items),
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                   "apc-000",
					SelectionReason:          AgentActionBOMPrimarySelectionDefaultTopPath,
					AutonomyTier:             risk.AutonomyTier4ProdPrivilegedCustomerImpact,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					PathMap: AgentActionBOMPrimaryPathMap{
						Tool:       "codex",
						RepoPR:     "enterprise-000 / pr/108",
						Workflow:   ".github/workflows/release-000.yml",
						Credential: "github_actions_prod_deployer",
						Action:     "deploy",
						Target:     "production_impacting",
					},
					DecisionTraceRefs: []string{"decision_trace:trace-000"},
					AppendixRefs:      []string{"bom_items", "graph_refs", "proof_refs"},
				},
			},
			Items: items,
		},
	}

	markdown := RenderMarkdown(summary)
	lines := strings.Split(strings.TrimRight(markdown, "\n"), "\n")
	if len(lines) > defaultMarkdownLineCap {
		t.Fatalf("expected markdown under the %d-line budget, got %d", defaultMarkdownLineCap, len(lines))
	}
	if !strings.Contains(markdown, "## Primary Workflow BOM") || !strings.Contains(markdown, "## Workflow BOM Appendix") {
		t.Fatalf("expected primary-view and appendix sections in markdown, got %q", markdown)
	}
}

func TestApplyMarkdownBudgetKeepsTruncationInsideLineCap(t *testing.T) {
	t.Parallel()

	var builder strings.Builder
	for idx := 0; idx < defaultMarkdownLineCap+10; idx++ {
		builder.WriteString(fmt.Sprintf("line-%04d\n", idx))
	}

	markdown, suppressed := ApplyMarkdownBudget(builder.String())
	if suppressed <= 0 {
		t.Fatalf("expected markdown budget to suppress overflow lines, got %d", suppressed)
	}
	lines := strings.Split(strings.TrimRight(markdown, "\n"), "\n")
	if len(lines) > defaultMarkdownLineCap {
		t.Fatalf("expected markdown including truncation note at or under %d lines, got %d", defaultMarkdownLineCap, len(lines))
	}
	if !strings.Contains(markdown, "output truncated to stay within the markdown line budget") {
		t.Fatalf("expected truncation note in capped markdown, got %q", markdown)
	}
}

func TestPolicyOutcomeSuppressedCounts(t *testing.T) {
	t.Parallel()

	findings := make([]model.Finding, 0, 5)
	for idx := 0; idx < 5; idx++ {
		findings = append(findings, model.Finding{
			FindingType: "policy_violation",
			RuleID:      "WRKR-016",
			CheckResult: "fail",
			Severity:    "high",
			Org:         "acme",
			Repo:        fmt.Sprintf("enterprise-%03d", idx),
		})
	}

	outcomes := BuildPolicyOutcomes(findings)
	if len(outcomes) != 1 {
		t.Fatalf("expected one grouped policy outcome, got %+v", outcomes)
	}
	if outcomes[0].OccurrenceCount != 5 {
		t.Fatalf("expected occurrence count 5, got %+v", outcomes[0])
	}
	if outcomes[0].AffectedRepoCount != 5 {
		t.Fatalf("expected affected repo count 5, got %+v", outcomes[0])
	}
	if len(outcomes[0].TopRepoRefs) != 3 {
		t.Fatalf("expected bounded repo refs, got %+v", outcomes[0])
	}
	if outcomes[0].SuppressedCount != 2 {
		t.Fatalf("expected suppressed repo examples, got %+v", outcomes[0])
	}
}
