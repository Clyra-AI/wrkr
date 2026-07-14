package report

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildSummaryPreservesSavedComposedPathsWhenActionPathsAreCapped(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:            "apc-only",
					Org:               "acme",
					Repo:              "checkout",
					ToolType:          "ci_agent",
					Location:          ".github/workflows/release.yml",
					RecommendedAction: "review",
				}},
				ComposedActionPaths: []risk.ComposedActionPath{{
					CompositionID: "cap-saved",
					PatternID:     risk.CompositionPatternCodeToDeploy,
					Stages: []risk.CompositionStage{
						{StageID: "stage-1", Role: risk.CompositionStageRoleSource},
						{StageID: "stage-2", Role: risk.CompositionStageRolePrivilegedSink},
					},
				}},
			},
		},
		Template:     TemplateAgentActionBOM,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.ComposedActionPaths) != 1 || summary.ComposedActionPaths[0].CompositionID != "cap-saved" {
		t.Fatalf("expected saved composed path to survive report build, got %+v", summary.ComposedActionPaths)
	}
}

func TestBuildSummaryPublicRedactionRemapsActionPathContractRefs(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                     "apc-1",
					Org:                        "acme",
					Repo:                       "checkout",
					ToolType:                   "ci_agent",
					Location:                   ".github/workflows/release.yml",
					ProposedActionContractRefs: []string{"pac-original"},
				}},
				ComposedActionPaths: []risk.ComposedActionPath{{
					CompositionID: "cap-1",
					PatternID:     risk.CompositionPatternCodeToDeploy,
					Stages: []risk.CompositionStage{
						{StageID: "stage-1", Role: risk.CompositionStageRoleSource},
						{StageID: "stage-2", Role: risk.CompositionStageRolePrivilegedSink},
					},
					ProposedActionContract: &risk.ProposedActionContract{
						ContractID:             "pac-original",
						ContractFamilyID:       "pacf-original",
						ContractContentDigest:  "sha256:orig",
						ContractVersion:        risk.ProposedActionContractVersion,
						ContractKind:           risk.ProposedActionContractKind,
						CompositionRef:         "cap-1",
						MaximumDelegationDepth: 1,
						ReportOnly:             true,
						ReadinessState:         risk.ActionContractReadinessReadyForReportOnly,
						ResolutionKey:          "acme/checkout|release",
						TargetConstraints: []risk.ProposedActionTargetConstraint{
							{Key: "target_identity", Value: "acme/checkout"},
						},
					},
					ProposedActionContractRefs: []string{"pac-original"},
				}},
			},
		},
		Template:     TemplateAgentActionBOM,
		ShareProfile: ShareProfilePublic,
		GeneratedAt:  time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.ComposedActionPaths) != 1 || summary.ComposedActionPaths[0].ProposedActionContract == nil {
		t.Fatalf("expected sanitized composed contract, got %+v", summary.ComposedActionPaths)
	}
	contractID := summary.ComposedActionPaths[0].ProposedActionContract.ContractID
	if contractID == "pac-original" {
		t.Fatalf("expected sanitized contract id to change, got %+v", summary.ComposedActionPaths[0].ProposedActionContract)
	}
	if len(summary.ActionPaths) != 1 || len(summary.ActionPaths[0].ProposedActionContractRefs) != 1 || summary.ActionPaths[0].ProposedActionContractRefs[0] != contractID {
		t.Fatalf("expected action-path contract refs to remap to sanitized id, got action_paths=%+v composed=%+v", summary.ActionPaths, summary.ComposedActionPaths)
	}
}
