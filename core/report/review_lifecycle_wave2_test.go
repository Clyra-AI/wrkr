package report

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestRenderMarkdownShowsResolvedReviewCounts(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-06-25T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-wave2",
			Summary: AgentActionBOMSummary{
				TotalItems:         2,
				CoverageConfidence: "high",
			},
			Items: []AgentActionBOMItem{
				{
					PathID:                   "apc-open",
					Repo:                     "acme/release",
					Location:                 ".github/workflows/release.yml",
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					ActionPathType:           risk.ActionPathTypeCICDWorkflow,
					ControlPriority:          risk.ControlPriorityControlFirst,
					RiskTier:                 risk.RiskTierCritical,
					ControlState:             risk.ControlStateBlockRecommend,
					TargetClass:              risk.TargetClassProductionImpacting,
					DelegationReadinessState: risk.DelegationReadinessBlocked,
					Queue:                    "control_first",
					FindingVisibility:        "primary",
				},
				{
					PathID:               "apc-resolved",
					Repo:                 "acme/release",
					Location:             ".github/workflows/release-old.yml",
					ConfidenceLane:       risk.ConfidenceLaneConfirmedActionPath,
					ActionPathType:       risk.ActionPathTypeCICDWorkflow,
					ReviewLifecycleState: risk.ReviewLifecycleStateDeclaredControlled,
					ResolvedVisibility:   risk.ReviewResolvedVisibilityAppendix,
					Queue:                "inventory_hygiene",
					FindingVisibility:    "appendix",
				},
			},
		},
	})

	if !strings.Contains(markdown, "Resolved review decisions") {
		t.Fatalf("expected markdown to call out resolved appendix counts, got %q", markdown)
	}
}
