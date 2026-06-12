package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildSummaryIncludesWorkflowHighlights(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-release",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					ApprovalGap:              true,
					ActionPathType:           risk.ActionPathTypeCICDWorkflow,
					TargetClass:              risk.TargetClassReleaseAdjacent,
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					RecommendedAction:        "control",
					AttackPathScore:          8.9,
					RiskScore:                8.9,
				}},
			},
		},
		Template:     TemplateCISO,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.WorkflowHighlights == nil || len(summary.WorkflowHighlights.Highlights) != 1 {
		t.Fatalf("expected one workflow highlight, got %+v", summary.WorkflowHighlights)
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "## Workflow Chain Highlights") {
		t.Fatalf("expected workflow highlights section, got %q", markdown)
	}
	if !strings.Contains(markdown, "path=apc-release") {
		t.Fatalf("expected highlighted path in markdown, got %q", markdown)
	}
}

func TestRenderMarkdownIncludesFocusView(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-release",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					ApprovalGap:              true,
					ActionPathType:           risk.ActionPathTypeCICDWorkflow,
					TargetClass:              risk.TargetClassReleaseAdjacent,
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					RecommendedAction:        "control",
					AttackPathScore:          8.9,
					RiskScore:                8.9,
				}},
			},
		},
		Template:     TemplateAgentActionBOM,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if err := ApplyFocusPreset(&summary, string(FocusPresetRelease)); err != nil {
		t.Fatalf("apply focus preset: %v", err)
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "## Focus View") {
		t.Fatalf("expected focus view section, got %q", markdown)
	}
	if !strings.Contains(markdown, "- Preset: release") {
		t.Fatalf("expected release preset in markdown, got %q", markdown)
	}
}
