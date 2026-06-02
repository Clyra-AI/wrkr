package report

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildAgentActionBOMSelectsPrimaryViewFromTopEligiblePath(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-05-27T12:00:00Z",
		ActionPaths: []risk.ActionPath{
			{
				PathID:                   "apc-top",
				Org:                      "acme",
				Repo:                     "acme/release",
				ToolType:                 "compiled_action",
				Location:                 ".github/workflows/release.yml",
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				AutonomyTier:             risk.AutonomyTier3SensitiveCodeOrInfra,
				DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
				RecommendedControl:       risk.RecommendedControlApprovalRequired,
				TargetClass:              risk.TargetClassProductionImpacting,
				ActionClasses:            []string{"deploy"},
				ApprovalGap:              true,
				CredentialAccess:         true,
				ControlPriority:          risk.ControlPriorityControlFirst,
				EvidenceCompleteness: &risk.EvidenceCompleteness{
					TotalScore: 42,
					Label:      risk.EvidenceCompletenessPartial,
				},
			},
		},
	})
	if bom == nil {
		t.Fatal("expected agent action bom")
		return
	}
	bomValue := *bom
	if bomValue.Summary.PrimaryView == nil {
		t.Fatalf("expected primary view, got %+v", bomValue.Summary)
	}
	primaryView := *bomValue.Summary.PrimaryView
	if primaryView.PathID != "apc-top" {
		t.Fatalf("expected primary view path apc-top, got %+v", primaryView)
	}
	if primaryView.SelectionReason != AgentActionBOMPrimarySelectionDefaultTopPath {
		t.Fatalf("expected default top path selection, got %+v", primaryView)
	}
	if primaryView.PathMap.Workflow != ".github/workflows/release.yml" {
		t.Fatalf("expected workflow path map, got %+v", primaryView.PathMap)
	}
	if bom.Summary.PrimaryView.AutonomyTier == "" || bom.Summary.PrimaryView.RecommendedControl == "" || bom.Summary.PrimaryView.DelegationReadinessState == "" {
		t.Fatalf("expected projected control metadata on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if bom.Summary.PrimaryView.EvidenceCompletenessLabel != risk.EvidenceCompletenessPartial {
		t.Fatalf("expected completeness label on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if len(bom.Summary.PrimaryView.AppendixRefs) == 0 {
		t.Fatalf("expected appendix refs on primary view, got %+v", bom.Summary.PrimaryView)
	}
}

func TestBuildAgentActionBOMSkipsContextOnlyPrimarySelection(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-05-27T12:00:00Z",
		ActionPaths: []risk.ActionPath{
			{
				PathID:           "apc-context-only",
				Org:              "acme",
				Repo:             "acme/release",
				ToolType:         "compiled_action",
				Location:         "notes.md",
				ConfidenceLane:   risk.ConfidenceLaneContextOnly,
				ActionPathType:   risk.ActionPathTypePlainSourceCode,
				ApprovalGap:      false,
				CredentialAccess: false,
			},
			{
				PathID:                   "apc-eligible",
				Org:                      "acme",
				Repo:                     "acme/release",
				ToolType:                 "compiled_action",
				Location:                 ".github/workflows/release.yml",
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				RecommendedControl:       risk.RecommendedControlOwnerReview,
				ApprovalGap:              true,
				CredentialAccess:         true,
			},
		},
	})
	if bom == nil || bom.Summary.PrimaryView == nil {
		t.Fatalf("expected primary view, got %+v", bom)
	}
	if bom.Summary.PrimaryView.PathID != "apc-eligible" {
		t.Fatalf("expected primary view to skip context-only path, got %+v", bom.Summary.PrimaryView)
	}
}

func TestRenderMarkdownAgentActionBOMLeadsWithPrimaryWorkflowPath(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-05-27T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID:         "bom-primary",
			SchemaVersion: AgentActionBOMSchemaVersion,
			Summary: AgentActionBOMSummary{
				TotalItems:        1,
				ControlFirstItems: 1,
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                   "apc-primary",
					SelectionReason:          AgentActionBOMPrimarySelectionDefaultTopPath,
					AutonomyTier:             risk.AutonomyTier4ProdPrivilegedCustomerImpact,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					PathMap: AgentActionBOMPrimaryPathMap{
						Tool:       "codex",
						RepoPR:     "acme/release / pr/108",
						Workflow:   ".github/workflows/release.yml",
						Credential: "github_actions_prod_deployer",
						Action:     "deploy",
						Target:     "production_impacting",
					},
					AppendixRefs: []string{"bom_items", "graph_refs", "proof_refs"},
				},
			},
			Items: []AgentActionBOMItem{{
				PathID:                   "apc-primary",
				Org:                      "acme",
				Repo:                     "acme/release",
				ToolType:                 "compiled_action",
				Location:                 ".github/workflows/release.yml",
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
				RecommendedControl:       risk.RecommendedControlApprovalRequired,
				ApprovalGap:              true,
				CredentialAccess:         true,
			}},
		},
	}

	markdown := RenderMarkdown(summary)
	primaryIdx := strings.Index(markdown, "## Primary Workflow BOM")
	appendixIdx := strings.Index(markdown, "## Workflow BOM Appendix")
	if primaryIdx < 0 {
		t.Fatalf("expected primary workflow section, got %q", markdown)
	}
	if appendixIdx < 0 {
		t.Fatalf("expected workflow appendix section, got %q", markdown)
	}
	if primaryIdx > appendixIdx {
		t.Fatalf("expected primary workflow BOM to lead before appendix, got %q", markdown)
	}
	if !strings.Contains(markdown, "codex -> acme/release / pr/108 -> .github/workflows/release.yml -> github_actions_prod_deployer -> deploy -> production_impacting") {
		t.Fatalf("expected workflow path map in markdown, got %q", markdown)
	}
}
