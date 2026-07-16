package report

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
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
				ToolType:                 "codex",
				Location:                 ".codex/config.toml",
				ConfidenceLane:           risk.ConfidenceLaneLikelyActionPath,
				ActionPathType:           risk.ActionPathTypeAgentInstruction,
				AutonomyTier:             risk.AutonomyTier3SensitiveCodeOrInfra,
				DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
				RecommendedControl:       risk.RecommendedControlApprovalRequired,
				TargetClass:              risk.TargetClassProductionImpacting,
				ActionClasses:            []string{"deploy"},
				ApprovalGap:              true,
				CredentialAccess:         true,
				ControlPriority:          risk.ControlPriorityControlFirst,
				AgenticDeliverySystemChange: &risk.AgenticDeliverySystemChange{
					SurfaceType:        risk.AgenticDeliverySurfaceToolConfig,
					ChangedArtifact:    ".codex/config.toml",
					AuthorityImpact:    risk.AgenticAuthorityImpactRelease,
					ReviewState:        risk.AgenticReviewStateMissing,
					CredentialReach:    "github_pat repository standing",
					ReachableTools:     []string{"deploy.write"},
					RecommendedControl: risk.RecommendedControlApprovalRequired,
				},
				DecisionTraceRefs: []string{"decision_trace:trace-123"},
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
	if primaryView.PathMap.Workflow != ".codex/config.toml" {
		t.Fatalf("expected workflow path map, got %+v", primaryView.PathMap)
	}
	if bom.Summary.PrimaryView.AutonomyTier == "" || bom.Summary.PrimaryView.RecommendedControl == "" || bom.Summary.PrimaryView.DelegationReadinessState == "" {
		t.Fatalf("expected projected control metadata on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if bom.Summary.PrimaryView.EvidenceCompletenessLabel != risk.EvidenceCompletenessPartial {
		t.Fatalf("expected completeness label on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if bom.Summary.PrimaryView.AgenticDeliverySystemChange == nil {
		t.Fatalf("expected delivery-system change on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if len(bom.Summary.PrimaryView.DecisionTraceRefs) != 1 {
		t.Fatalf("expected decision trace refs on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if len(bom.Summary.PrimaryView.AppendixRefs) == 0 {
		t.Fatalf("expected appendix refs on primary view, got %+v", bom.Summary.PrimaryView)
	}
	if bom.Summary.PrimaryView.CoverageStatus != scanquality.AbsenceStatusNotScanned {
		t.Fatalf("expected default not_scanned coverage status without scan-quality input, got %+v", bom.Summary.PrimaryView)
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

func TestBuildAgentActionBOMSkipsPlainSourcePrimarySelection(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-05-27T12:00:00Z",
		ActionPaths: []risk.ActionPath{
			{
				PathID:                   "apc-swagger",
				Org:                      "acme",
				Repo:                     "acme/api",
				ToolType:                 "openapi",
				Location:                 "src/proto/payments/v1/payments.swagger.json",
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType:           risk.ActionPathTypePlainSourceCode,
				DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
				RecommendedControl:       risk.RecommendedControlApprovalRequired,
				TargetClass:              risk.TargetClassCustomerDataAdjacent,
				ActionClasses:            []string{"read", "write"},
				ApprovalGap:              true,
				CredentialAccess:         true,
			},
			{
				PathID:                   "apc-workflow",
				Org:                      "acme",
				Repo:                     "acme/api",
				ToolType:                 "ci_agent",
				Location:                 ".github/workflows/release.yml",
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
				RecommendedControl:       risk.RecommendedControlApprovalRequired,
				TargetClass:              risk.TargetClassReleaseAdjacent,
				ActionClasses:            []string{"deploy"},
				ApprovalGap:              true,
				CredentialAccess:         true,
			},
		},
	})
	if bom == nil || bom.Summary.PrimaryView == nil {
		t.Fatalf("expected primary view, got %+v", bom)
	}
	if bom.Summary.PrimaryView.PathID != "apc-workflow" {
		t.Fatalf("expected primary view to skip source-only API spec path, got %+v", bom.Summary.PrimaryView)
	}
}

func TestApplySummaryCapsSelectsPrimaryViewFromUncappedWorkflowSource(t *testing.T) {
	t.Parallel()

	items := make([]AgentActionBOMItem, 0, defaultMaxAgentActionBOM+1)
	for idx := 0; idx < defaultMaxAgentActionBOM; idx++ {
		items = append(items, AgentActionBOMItem{
			PathID:                  fmt.Sprintf("apc-context-%03d", idx),
			Repo:                    "acme/api",
			ToolType:                "openapi",
			Location:                fmt.Sprintf("src/proto/%03d/openapi.yaml", idx),
			ActionPathEligible:      true,
			ActionBindingState:      risk.ActionBindingStateBound,
			ActionPathType:          risk.ActionPathTypePlainSourceCode,
			ConfidenceLane:          risk.ConfidenceLaneConfirmedActionPath,
			RecommendedControl:      risk.RecommendedControlOwnerReview,
			TargetClass:             risk.TargetClassCustomerDataAdjacent,
			ApprovalEvidenceState:   risk.EvidenceStateUnknown,
			CredentialEvidenceState: risk.EvidenceStateUnknown,
		})
	}
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		StandingAccess:         true,
	}
	workflow := AgentActionBOMItem{
		PathID:                   "apc-workflow",
		Repo:                     "acme/release",
		ToolType:                 "ci_agent",
		Location:                 ".github/workflows/release.yml",
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
		TargetClass:              risk.TargetClassReleaseAdjacent,
		ActionClasses:            []string{"deploy", "write"},
		CredentialAccess:         true,
		CredentialAuthorityRef:   agginventory.CanonicalCredentialAuthorityRef(authority),
		CredentialAuthority:      authority,
	}
	allItems := append(append([]AgentActionBOMItem(nil), items...), workflow)
	summary := Summary{
		AgentActionBOM: &AgentActionBOM{
			Items:            append([]AgentActionBOMItem(nil), allItems...),
			focusSourceItems: allItems,
		},
	}

	ApplySummaryCaps(&summary)

	if summary.AgentActionBOM == nil || summary.AgentActionBOM.Summary.PrimaryView == nil {
		t.Fatalf("expected capped summary to select a primary workflow, got %+v", summary.AgentActionBOM)
	}
	if summary.AgentActionBOM.Summary.PrimaryView.PathID != "apc-workflow" {
		t.Fatalf("expected primary view from uncapped workflow source, got %+v", summary.AgentActionBOM.Summary.PrimaryView)
	}
	found := false
	for _, item := range summary.AgentActionBOM.Items {
		if item.PathID != "apc-workflow" {
			continue
		}
		found = true
		if item.CredentialAuthorityRef == "" {
			t.Fatalf("expected visible primary workflow to keep credential authority ref, got %+v", item)
		}
		if item.CredentialAuthority != nil {
			t.Fatalf("expected visible primary workflow to strip embedded credential authority, got %+v", item.CredentialAuthority)
		}
	}
	if !found {
		t.Fatalf("expected primary workflow to be made visible after caps, got %+v", summary.AgentActionBOM.Items)
	}
}

func TestApplySummaryCapsDropsRefsToSuppressedComposedContracts(t *testing.T) {
	t.Parallel()

	composed := make([]risk.ComposedActionPath, 0, defaultMaxComposedActionPaths+1)
	for idx := 0; idx < defaultMaxComposedActionPaths+1; idx++ {
		ref := fmt.Sprintf("pac-%03d", idx)
		composed = append(composed, risk.ComposedActionPath{
			CompositionID:              fmt.Sprintf("cap-%03d", idx),
			ProposedActionContractRefs: []string{ref},
		})
	}
	summary := Summary{
		ActionPaths: []risk.ActionPath{{
			PathID:                     "apc-1",
			ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
		}},
		ComposedActionPaths: composed,
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				PathID:                     "apc-1",
				ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
			}},
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                     "apc-1",
					ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
				},
			},
		},
	}

	ApplySummaryCaps(&summary)

	want := []string{"pac-000"}
	if !reflect.DeepEqual(summary.ActionPaths[0].ProposedActionContractRefs, want) {
		t.Fatalf("expected action path refs to drop suppressed contracts, got %+v", summary.ActionPaths[0].ProposedActionContractRefs)
	}
	if !reflect.DeepEqual(summary.AgentActionBOM.Items[0].ProposedActionContractRefs, want) {
		t.Fatalf("expected BOM item refs to drop suppressed contracts, got %+v", summary.AgentActionBOM.Items[0].ProposedActionContractRefs)
	}
	if !reflect.DeepEqual(summary.AgentActionBOM.Summary.PrimaryView.ProposedActionContractRefs, want) {
		t.Fatalf("expected primary view refs to drop suppressed contracts, got %+v", summary.AgentActionBOM.Summary.PrimaryView.ProposedActionContractRefs)
	}
}

func TestApplySummaryCapsDropsSuppressedCompositionIDs(t *testing.T) {
	t.Parallel()

	composed := make([]risk.ComposedActionPath, 0, defaultMaxComposedActionPaths+1)
	for idx := 0; idx < defaultMaxComposedActionPaths+1; idx++ {
		composed = append(composed, risk.ComposedActionPath{
			CompositionID:              fmt.Sprintf("cap-%03d", idx),
			ProposedActionContractRefs: []string{fmt.Sprintf("pac-%03d", idx)},
		})
	}
	summary := Summary{
		ActionPaths: []risk.ActionPath{{
			PathID:                     "apc-1",
			CompositionIDs:             []string{"cap-000", fmt.Sprintf("cap-%03d", defaultMaxComposedActionPaths)},
			ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
		}},
		ComposedActionPaths: composed,
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				PathID:                     "apc-1",
				CompositionIDs:             []string{"cap-000", fmt.Sprintf("cap-%03d", defaultMaxComposedActionPaths)},
				ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
			}},
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                     "apc-1",
					CompositionIDs:             []string{"cap-000", fmt.Sprintf("cap-%03d", defaultMaxComposedActionPaths)},
					ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
				},
			},
		},
	}

	ApplySummaryCaps(&summary)

	wantIDs := []string{"cap-000"}
	if !reflect.DeepEqual(summary.ActionPaths[0].CompositionIDs, wantIDs) {
		t.Fatalf("expected action path composition ids to drop suppressed compositions, got %+v", summary.ActionPaths[0].CompositionIDs)
	}
	if !reflect.DeepEqual(summary.AgentActionBOM.Items[0].CompositionIDs, wantIDs) {
		t.Fatalf("expected BOM item composition ids to drop suppressed compositions, got %+v", summary.AgentActionBOM.Items[0].CompositionIDs)
	}
	if !reflect.DeepEqual(summary.AgentActionBOM.Summary.PrimaryView.CompositionIDs, wantIDs) {
		t.Fatalf("expected primary view composition ids to drop suppressed compositions, got %+v", summary.AgentActionBOM.Summary.PrimaryView.CompositionIDs)
	}
}

func TestApplySummaryCapsDropsSuppressedAssessmentRefs(t *testing.T) {
	t.Parallel()

	composed := make([]risk.ComposedActionPath, 0, defaultMaxComposedActionPaths+1)
	for idx := 0; idx < defaultMaxComposedActionPaths+1; idx++ {
		composed = append(composed, risk.ComposedActionPath{
			CompositionID:              fmt.Sprintf("cap-%03d", idx),
			ProposedActionContractRefs: []string{fmt.Sprintf("pac-%03d", idx)},
		})
	}
	summary := Summary{
		ComposedActionPaths: composed,
		AssessmentSummary: &AssessmentSummary{
			TopPathToControlFirst: &risk.ActionPath{
				PathID:                     "apc-top",
				CompositionIDs:             []string{"cap-000", fmt.Sprintf("cap-%03d", defaultMaxComposedActionPaths)},
				ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
			},
			TopExecutionIdentityBacked: &risk.ActionPath{
				PathID:                     "apc-exec",
				CompositionIDs:             []string{"cap-000", fmt.Sprintf("cap-%03d", defaultMaxComposedActionPaths)},
				ProposedActionContractRefs: []string{"pac-000", fmt.Sprintf("pac-%03d", defaultMaxComposedActionPaths)},
			},
		},
	}

	ApplySummaryCaps(&summary)

	wantIDs := []string{"cap-000"}
	wantRefs := []string{"pac-000"}
	if !reflect.DeepEqual(summary.AssessmentSummary.TopPathToControlFirst.CompositionIDs, wantIDs) {
		t.Fatalf("expected assessment top path composition ids to drop suppressed compositions, got %+v", summary.AssessmentSummary.TopPathToControlFirst.CompositionIDs)
	}
	if !reflect.DeepEqual(summary.AssessmentSummary.TopPathToControlFirst.ProposedActionContractRefs, wantRefs) {
		t.Fatalf("expected assessment top path contract refs to drop suppressed contracts, got %+v", summary.AssessmentSummary.TopPathToControlFirst.ProposedActionContractRefs)
	}
	if !reflect.DeepEqual(summary.AssessmentSummary.TopExecutionIdentityBacked.CompositionIDs, wantIDs) {
		t.Fatalf("expected assessment execution-backed composition ids to drop suppressed compositions, got %+v", summary.AssessmentSummary.TopExecutionIdentityBacked.CompositionIDs)
	}
	if !reflect.DeepEqual(summary.AssessmentSummary.TopExecutionIdentityBacked.ProposedActionContractRefs, wantRefs) {
		t.Fatalf("expected assessment execution-backed contract refs to drop suppressed contracts, got %+v", summary.AssessmentSummary.TopExecutionIdentityBacked.ProposedActionContractRefs)
	}
}

func TestApplySummaryCapsDropsComposedPathsThatReferenceSuppressedActionPaths(t *testing.T) {
	t.Parallel()

	actionPaths := make([]risk.ActionPath, 0, defaultMaxActionPaths+1)
	for idx := 0; idx < defaultMaxActionPaths+1; idx++ {
		actionPaths = append(actionPaths, risk.ActionPath{
			PathID: fmt.Sprintf("apc-%03d", idx),
		})
	}
	actionPaths[0].CompositionIDs = []string{"cap-keep", "cap-drop"}
	actionPaths[0].ProposedActionContractRefs = []string{"pac-keep", "pac-drop"}

	summary := Summary{
		ActionPaths: actionPaths,
		ComposedActionPaths: []risk.ComposedActionPath{
			{
				CompositionID:              "cap-keep",
				PathIDs:                    []string{"apc-000"},
				ProposedActionContractRefs: []string{"pac-keep"},
				Stages: []risk.CompositionStage{
					{StageID: "stage-keep", PathID: "apc-000"},
				},
			},
			{
				CompositionID:              "cap-drop",
				PathIDs:                    []string{fmt.Sprintf("apc-%03d", defaultMaxActionPaths)},
				ProposedActionContractRefs: []string{"pac-drop"},
				Stages: []risk.CompositionStage{
					{StageID: "stage-drop", PathID: fmt.Sprintf("apc-%03d", defaultMaxActionPaths)},
				},
			},
		},
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				PathID:                     "apc-000",
				CompositionIDs:             []string{"cap-keep", "cap-drop"},
				ProposedActionContractRefs: []string{"pac-keep", "pac-drop"},
			}},
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                     "apc-000",
					CompositionIDs:             []string{"cap-keep", "cap-drop"},
					ProposedActionContractRefs: []string{"pac-keep", "pac-drop"},
				},
			},
		},
		AssessmentSummary: &AssessmentSummary{
			TopPathToControlFirst: &risk.ActionPath{
				PathID:                     "apc-000",
				CompositionIDs:             []string{"cap-keep", "cap-drop"},
				ProposedActionContractRefs: []string{"pac-keep", "pac-drop"},
			},
		},
	}

	ApplySummaryCaps(&summary)

	if len(summary.ActionPaths) != defaultMaxActionPaths {
		t.Fatalf("expected action paths to cap at %d, got %d", defaultMaxActionPaths, len(summary.ActionPaths))
	}
	if len(summary.ComposedActionPaths) != 1 || summary.ComposedActionPaths[0].CompositionID != "cap-keep" {
		t.Fatalf("expected composed paths to drop refs to capped action paths, got %+v", summary.ComposedActionPaths)
	}

	wantIDs := []string{"cap-keep"}
	wantRefs := []string{"pac-keep"}
	if !reflect.DeepEqual(summary.ActionPaths[0].CompositionIDs, wantIDs) {
		t.Fatalf("expected action path composition ids to drop capped references, got %+v", summary.ActionPaths[0].CompositionIDs)
	}
	if !reflect.DeepEqual(summary.ActionPaths[0].ProposedActionContractRefs, wantRefs) {
		t.Fatalf("expected action path contract refs to drop capped references, got %+v", summary.ActionPaths[0].ProposedActionContractRefs)
	}
	if !reflect.DeepEqual(summary.AgentActionBOM.Items[0].CompositionIDs, wantIDs) {
		t.Fatalf("expected BOM item composition ids to drop capped references, got %+v", summary.AgentActionBOM.Items[0].CompositionIDs)
	}
	if !reflect.DeepEqual(summary.AgentActionBOM.Summary.PrimaryView.CompositionIDs, wantIDs) {
		t.Fatalf("expected primary view composition ids to drop capped references, got %+v", summary.AgentActionBOM.Summary.PrimaryView.CompositionIDs)
	}
	if !reflect.DeepEqual(summary.AssessmentSummary.TopPathToControlFirst.CompositionIDs, wantIDs) {
		t.Fatalf("expected assessment composition ids to drop capped references, got %+v", summary.AssessmentSummary.TopPathToControlFirst.CompositionIDs)
	}
	if summary.SuppressedCounts == nil || summary.SuppressedCounts.ActionPaths != 1 || summary.SuppressedCounts.ComposedActionPaths != 1 {
		t.Fatalf("expected suppressed counts to record both action-path and composed-path caps, got %+v", summary.SuppressedCounts)
	}
}

func TestBuildWorkflowHighlightsSkipsPlainSourceContext(t *testing.T) {
	t.Parallel()

	highlights := BuildWorkflowHighlights(Summary{
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{
				{
					PathID:                   "apc-swagger",
					Repo:                     "acme/api",
					ToolType:                 "openapi",
					Location:                 "src/proto/payments/v1/payments.swagger.json",
					ActionPathEligible:       true,
					ActionBindingState:       risk.ActionBindingStateBound,
					ActionPathType:           risk.ActionPathTypePlainSourceCode,
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					CredentialAccess:         true,
				},
				{
					PathID:                   "apc-workflow",
					Repo:                     "acme/api",
					ToolType:                 "ci_agent",
					Location:                 ".github/workflows/release.yml",
					ActionPathEligible:       true,
					ActionBindingState:       risk.ActionBindingStateBound,
					ActionPathType:           risk.ActionPathTypeCICDWorkflow,
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					CredentialAccess:         true,
				},
			},
		},
	})
	if highlights == nil || len(highlights.Highlights) != 1 {
		t.Fatalf("expected one promotable workflow highlight, got %+v", highlights)
	}
	if highlights.Highlights[0].PathID != "apc-workflow" {
		t.Fatalf("expected workflow highlight to skip source-only API spec path, got %+v", highlights.Highlights)
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
					RiskTier:                 "critical",
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					CoverageStatus:           scanquality.CoverageConfidenceComplete,
					RecommendedNextActions: []string{
						"Attach approval evidence for this exact workflow path",
						"Attach path-specific proof before promotion",
					},
					PathMap: AgentActionBOMPrimaryPathMap{
						Tool:       "codex",
						RepoPR:     "acme/release / pr/108",
						Workflow:   ".github/workflows/release.yml",
						Credential: "github_actions_prod_deployer",
						Action:     "deploy",
						Target:     "production_impacting",
					},
					AgenticDeliverySystemChange: &risk.AgenticDeliverySystemChange{
						SurfaceType:     risk.AgenticDeliverySurfaceToolConfig,
						ChangedArtifact: ".codex/config.toml",
						AuthorityImpact: risk.AgenticAuthorityImpactRelease,
						ReviewState:     risk.AgenticReviewStateMissing,
					},
					DecisionTraceRefs: []string{"decision_trace:trace-321"},
					AppendixRefs:      []string{"bom_items", "graph_refs", "proof_refs"},
				},
			},
			ScanQuality: &scanquality.Report{
				ScanQualityVersion: scanquality.ReportVersion,
				Mode:               "governance",
				Detectors: []scanquality.DetectorHealth{
					{Org: "acme", Repo: "acme/release", Detector: "mcp", Status: "complete", AttemptedFiles: 1, ParsedFiles: 1},
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
		WorkflowHighlights: &WorkflowHighlights{
			TotalItems: 2,
			Highlights: []WorkflowHighlight{
				{
					PathID:              "apc-primary",
					Repo:                "acme/release",
					Workflow:            ".github/workflows/release.yml",
					TargetClass:         risk.TargetClassProductionImpacting,
					DelegationReadiness: risk.DelegationReadinessApprovalRequired,
					Recommendation:      "Attach approval evidence for this exact workflow path",
				},
				{
					PathID:              "apc-secondary",
					Repo:                "acme/release",
					Workflow:            ".github/workflows/release.yml",
					TargetClass:         risk.TargetClassProductionImpacting,
					DelegationReadiness: risk.DelegationReadinessApprovalRequired,
					Recommendation:      "Attach approval evidence for this exact workflow path",
				},
			},
		},
	}

	markdown := RenderMarkdown(summary)
	inspectFirstIdx := strings.Index(markdown, "## What To Look At First")
	primaryIdx := strings.Index(markdown, "## Primary Workflow BOM")
	topPathsIdx := strings.Index(markdown, "## Top Action Paths")
	contextIdx := strings.Index(markdown, "## Report Context Appendix")
	appendixIdx := strings.Index(markdown, "## Workflow BOM Appendix")
	if inspectFirstIdx < 0 {
		t.Fatalf("expected inspect-first lead section, got %q", markdown)
	}
	if primaryIdx < 0 {
		t.Fatalf("expected primary workflow section, got %q", markdown)
	}
	if topPathsIdx < 0 {
		t.Fatalf("expected top action paths section, got %q", markdown)
	}
	if contextIdx < 0 {
		t.Fatalf("expected report context appendix section, got %q", markdown)
	}
	if appendixIdx < 0 {
		t.Fatalf("expected workflow appendix section, got %q", markdown)
	}
	if inspectFirstIdx > primaryIdx {
		t.Fatalf("expected inspect-first cards to lead before primary workflow BOM, got %q", markdown)
	}
	if primaryIdx > appendixIdx {
		t.Fatalf("expected primary workflow BOM to lead before appendix, got %q", markdown)
	}
	if !strings.Contains(markdown, "Workflow: codex in acme/release / pr/108 via .github/workflows/release.yml.") {
		t.Fatalf("expected human-readable workflow line in markdown, got %q", markdown)
	}
	if !strings.Contains(markdown, "Visible controls:") {
		t.Fatalf("expected visible controls lead line in markdown, got %q", markdown)
	}
	if !strings.Contains(markdown, "Coverage status: complete.") {
		t.Fatalf("expected coverage status in primary workflow section, got %q", markdown)
	}
	if !strings.Contains(markdown, "Next actions: Attach approval evidence for this exact workflow path | Attach path-specific proof before promotion.") {
		t.Fatalf("expected concise next actions in markdown, got %q", markdown)
	}
	if !strings.Contains(markdown, "Inspect first: codex in acme/release / pr/108 via .github/workflows/release.yml.") {
		t.Fatalf("expected buyer diagnostic card lead, got %q", markdown)
	}
	lead := markdown[:contextIdx]
	if strings.Contains(lead, "Decision traces:") || strings.Contains(lead, "Appendix refs:") {
		t.Fatalf("expected hash-heavy refs to stay out of the lead view, got %q", lead)
	}
}

func TestAgentActionBOMStartsWithInspectFirstCards(t *testing.T) {
	t.Parallel()

	items := []AgentActionBOMItem{}
	highlights := []WorkflowHighlight{}
	for idx := 0; idx < 6; idx++ {
		pathID := "apc-card-" + string(rune('0'+idx))
		repo := "acme/repo-" + string(rune('0'+idx))
		workflow := ".github/workflows/workflow-" + string(rune('0'+idx)) + ".yml"
		items = append(items, AgentActionBOMItem{
			PathID:                   pathID,
			Org:                      "acme",
			Repo:                     repo,
			ToolType:                 "compiled_action",
			Location:                 workflow,
			ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
			ActionPathType:           risk.ActionPathTypeCICDWorkflow,
			DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
			RecommendedControl:       risk.RecommendedControlApprovalRequired,
			TargetClass:              risk.TargetClassProductionImpacting,
			ApprovalGap:              true,
			CredentialAccess:         true,
			ControlResolutionState:   risk.ControlResolutionStateNoVisibleControl,
			ApprovalEvidenceState:    risk.EvidenceStateUnknown,
			ProofEvidenceState:       risk.EvidenceStateUnknown,
			RuntimeEvidenceState:     risk.EvidenceStateUnknown,
		})
		highlights = append(highlights, WorkflowHighlight{
			PathID:              pathID,
			PathType:            "workflow path",
			Repo:                repo,
			Workflow:            workflow,
			TargetClass:         risk.TargetClassProductionImpacting,
			DelegationReadiness: risk.DelegationReadinessApprovalRequired,
			Authority:           "credential access declared",
			EvidenceSummary:     "control=no visible control",
			ApprovalPath:        "approval evidence unknown",
			ProofStatus:         "proof evidence unknown",
			RuntimeStatus:       "runtime evidence unknown",
			Recommendation:      "Attach approval evidence for this exact workflow path",
		})
	}

	summary := Summary{
		GeneratedAt:  "2026-06-17T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{
			BOMID:         "bom-cards",
			SchemaVersion: AgentActionBOMSchemaVersion,
			Summary: AgentActionBOMSummary{
				TotalItems:        len(items),
				ControlFirstItems: len(items),
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                   "apc-card-0",
					SelectionReason:          AgentActionBOMPrimarySelectionDefaultTopPath,
					BoundaryLabel:            BoundaryLabelReportOnly,
					AutonomyTier:             risk.AutonomyTier4ProdPrivilegedCustomerImpact,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					RiskTier:                 "critical",
					PathMap: AgentActionBOMPrimaryPathMap{
						Tool:       "codex",
						RepoPR:     "acme/repo-0 / pr/108",
						Workflow:   ".github/workflows/workflow-0.yml",
						Credential: "prod-deployer",
						Action:     "deploy",
						Target:     "production_impacting",
					},
					ControlResolutionState: risk.ControlResolutionStateNoVisibleControl,
					ApprovalEvidenceState:  risk.EvidenceStateUnknown,
					ProofEvidenceState:     risk.EvidenceStateUnknown,
					RuntimeEvidenceState:   risk.EvidenceStateUnknown,
					UnresolvedEvidence:     []string{"approval", "proof"},
					RecommendedNextActions: []string{
						"Attach approval evidence for this exact workflow path",
						"Attach path-specific proof before promotion",
					},
				},
			},
			Items: items,
		},
		WorkflowHighlights: &WorkflowHighlights{
			TotalItems: len(highlights),
			Highlights: highlights,
		},
	}

	markdown := RenderMarkdown(summary)
	inspectFirstIdx := strings.Index(markdown, "## What To Look At First")
	primaryIdx := strings.Index(markdown, "## Primary Workflow BOM")
	topPathsIdx := strings.Index(markdown, "## Top Action Paths")
	contextIdx := strings.Index(markdown, "## Report Context Appendix")
	if inspectFirstIdx < 0 || primaryIdx < 0 || topPathsIdx < 0 || contextIdx < 0 {
		t.Fatalf("expected inspect-first, primary, top-path, and appendix sections, got %q", markdown)
	}
	leadCards := markdown[inspectFirstIdx:primaryIdx]
	if strings.Contains(leadCards, "BOM id:") {
		t.Fatalf("expected machine-heavy BOM metadata to stay out of the lead cards, got %q", leadCards)
	}
	if strings.Contains(leadCards, "apc-card-") {
		t.Fatalf("expected opaque path ids to stay out of the lead cards, got %q", leadCards)
	}
	if count := strings.Count(leadCards, "- Inspect "); count != 5 {
		t.Fatalf("expected five inspect-first cards when enough eligible paths exist, got %d in %q", count, leadCards)
	}
	topPaths := markdown[topPathsIdx:contextIdx]
	if count := strings.Count(topPaths, "\n- "); count != 5 {
		t.Fatalf("expected five compact top action paths before appendices, got %d in %q", count, topPaths)
	}
}

func TestDefaultAgentActionBOMOnePageBudget(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-06-12T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-budget",
			Summary: AgentActionBOMSummary{
				TotalItems:         12,
				ControlFirstItems:  8,
				CoverageConfidence: scanquality.CoverageConfidenceReduced,
				DelegationReadiness: risk.DelegationReadinessCounts{
					Blocked:        2,
					ReviewRequired: 5,
				},
				PrimaryView: &AgentActionBOMPrimaryView{
					SelectionReason:          AgentActionBOMPrimarySelectionDefaultTopPath,
					BoundaryLabel:            BoundaryLabelReportOnly,
					AutonomyTier:             risk.AutonomyTier4ProdPrivilegedCustomerImpact,
					DelegationReadinessState: risk.DelegationReadinessApprovalRequired,
					RecommendedControl:       risk.RecommendedControlApprovalRequired,
					RiskTier:                 "critical",
					PathMap: AgentActionBOMPrimaryPathMap{
						Tool:       "codex",
						RepoPR:     "repo-529260 / pr-3d238ea7",
						Workflow:   "loc-87db21a9",
						Credential: "cred-1",
						Action:     "deploy",
						Target:     "production_impacting",
					},
					ProofEvidenceState:        risk.EvidenceStateUnknown,
					ApprovalEvidenceState:     risk.EvidenceStateUnknown,
					OwnerEvidenceState:        risk.EvidenceStateInferred,
					RuntimeEvidenceState:      risk.EvidenceStateUnknown,
					TargetEvidenceState:       risk.EvidenceStateInferred,
					CredentialEvidenceState:   risk.EvidenceStateVerified,
					EvidenceCompletenessLabel: risk.EvidenceCompletenessPartial,
					EvidenceCompletenessScore: 63,
					UnresolvedEvidence:        []string{"approval", "proof"},
					CoverageStatus:            scanquality.CoverageConfidenceReduced,
					CoverageImpact:            "Some detector coverage was reduced or parse-limited, so negative claims remain scoped to scanned inputs.",
					RecommendedNextActions: []string{
						"Attach approval evidence for this exact workflow path",
						"Attach path-specific proof before promotion",
					},
				},
			},
		},
		WorkflowHighlights: &WorkflowHighlights{
			TotalItems: 6,
			Highlights: []WorkflowHighlight{
				{Repo: "repo-1", Workflow: "wf-1", TargetClass: risk.TargetClassProductionImpacting, DelegationReadiness: risk.DelegationReadinessApprovalRequired, Recommendation: "Attach approval evidence for this exact workflow path"},
				{Repo: "repo-1", Workflow: "wf-1", TargetClass: risk.TargetClassProductionImpacting, DelegationReadiness: risk.DelegationReadinessApprovalRequired, Recommendation: "Attach approval evidence for this exact workflow path"},
				{Repo: "repo-2", Workflow: "wf-2", TargetClass: risk.TargetClassReleaseAdjacent, DelegationReadiness: risk.DelegationReadinessReviewRequired, Recommendation: "Review this workflow path"},
				{Repo: "repo-3", Workflow: "wf-3", TargetClass: risk.TargetClassProductionImpacting, DelegationReadiness: risk.DelegationReadinessBlocked, Recommendation: "Replace standing credential with repo-scoped JIT or brokered authority"},
			},
		},
	}

	markdown := RenderMarkdown(summary)
	contextIdx := strings.Index(markdown, "## Report Context Appendix")
	if contextIdx < 0 {
		t.Fatalf("expected report context appendix, got %q", markdown)
	}
	lead := markdown[:contextIdx]
	lines := strings.Split(strings.TrimRight(lead, "\n"), "\n")
	if len(lines) > defaultBOMLeadLineCap {
		t.Fatalf("expected lead view under %d lines, got %d\n%s", defaultBOMLeadLineCap, len(lines), lead)
	}
	if strings.Count(lead, "\n## ") > defaultBOMLeadSectionCap {
		t.Fatalf("expected no more than %d lead sections, got %q", defaultBOMLeadSectionCap, lead)
	}
}

func TestBuildAgentActionBOMPrimaryViewCarriesQualifiedCoverageStatus(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-06-12T12:00:00Z",
		ScanQuality: &scanquality.Report{
			ScanQualityVersion: scanquality.ReportVersion,
			Mode:               "governance",
			Detectors: []scanquality.DetectorHealth{
				{Org: "acme", Repo: "acme/web", Detector: "webmcp", Status: "reduced", AttemptedFiles: 1, ParsedFiles: 0, ParseFailures: 1, CoverageReasons: []string{"parse_failures"}},
			},
			AbsenceClaims: []scanquality.AbsenceClaim{{
				Org:     "acme",
				Repo:    "acme/web",
				Surface: scanquality.SurfaceMCPServer,
				Status:  scanquality.AbsenceStatusCandidateParseFailed,
				Reasons: []string{"detector:webmcp=reduced", "webmcp:parse_failures"},
				Impact:  "At least one MCP candidate surface failed to parse, so absence is not authoritative.",
			}},
		},
		ActionPaths: []risk.ActionPath{{
			PathID:                   "apc-webmcp",
			Org:                      "acme",
			Repo:                     "acme/web",
			ToolType:                 "webmcp",
			Location:                 "ui/register.mjs",
			ConfidenceLane:           risk.ConfidenceLaneLikelyActionPath,
			ActionPathType:           risk.ActionPathTypeAIAssistedWorkflow,
			DelegationReadinessState: risk.DelegationReadinessReviewRequired,
			RecommendedControl:       risk.RecommendedControlOwnerReview,
			ActionClasses:            []string{"read"},
			TargetClass:              risk.TargetClassDeveloperProductivity,
		}},
	})
	if bom == nil || bom.Summary.PrimaryView == nil {
		t.Fatalf("expected primary view, got %+v", bom)
	}
	if bom.Summary.PrimaryView.CoverageStatus != scanquality.CoverageConfidenceReduced {
		t.Fatalf("expected reduced primary-view coverage status, got %+v", bom.Summary.PrimaryView)
	}
	if !strings.Contains(bom.Summary.PrimaryView.CoverageImpact, "failed to parse") {
		t.Fatalf("expected qualified coverage impact, got %+v", bom.Summary.PrimaryView)
	}
}

func TestPrimaryViewBlockedStandingCredentialNextActionsLeadWithReplacement(t *testing.T) {
	t.Parallel()

	actions := primaryViewRecommendedNextActions(AgentActionBOMItem{
		PathID:                   "apc-blocked",
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
		StandingPrivilege:        true,
		ClosureActions: []risk.ClosureAction{
			{ActionType: risk.ClosureActionAcceptRiskWithExpiry, Title: "Accept risk with expiry"},
			{ActionType: risk.ClosureActionAttachPolicyOrProof, Title: "Attach policy or proof reference"},
			{ActionType: risk.ClosureActionReduceStandingCredential, Title: "Reduce standing credential scope"},
		},
	})

	if len(actions) == 0 {
		t.Fatal("expected next actions")
	}
	if !strings.Contains(strings.ToLower(actions[0]), "replace standing credential") {
		t.Fatalf("expected blocked standing credential to lead with replacement, got %+v", actions)
	}
	for idx, action := range actions {
		if strings.Contains(strings.ToLower(action), "accept risk") && idx == 0 {
			t.Fatalf("accept-risk must not be first for blocked standing credentials: %+v", actions)
		}
	}
}

func TestRenderMarkdownSeparatesRepeatedWorkflowAuthoritiesWithDifferentActions(t *testing.T) {
	t.Parallel()

	items := []AgentActionBOMItem{
		{
			PathID:                   "apc-1",
			Repo:                     "repo-a",
			Location:                 "loc-release",
			ActionPathType:           risk.ActionPathTypeCICDWorkflow,
			TargetClass:              risk.TargetClassProductionImpacting,
			DelegationReadinessState: risk.DelegationReadinessBlocked,
			RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
			StandingPrivilege:        true,
			ControlState:             "block_recommended",
			ApprovalEvidenceState:    risk.EvidenceStateUnknown,
			ProofEvidenceState:       risk.EvidenceStateUnknown,
			RuntimeEvidenceState:     risk.EvidenceStateUnknown,
		},
		{
			PathID:                   "apc-2",
			Repo:                     "repo-a",
			Location:                 "loc-release",
			ActionPathType:           risk.ActionPathTypeCICDWorkflow,
			TargetClass:              risk.TargetClassProductionImpacting,
			DelegationReadinessState: risk.DelegationReadinessBlocked,
			RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
			StandingPrivilege:        true,
			ControlState:             "block_recommended",
			ApprovalEvidenceState:    risk.EvidenceStateUnknown,
			ProofEvidenceState:       risk.EvidenceStateUnknown,
			RuntimeEvidenceState:     risk.EvidenceStateUnknown,
		},
	}
	summary := Summary{
		GeneratedAt:  "2026-06-26T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-grouped",
			Summary: AgentActionBOMSummary{
				TotalItems:                   2,
				ControlFirstItems:            2,
				ApprovalEvidenceUnknownItems: 2,
				ProofEvidenceUnknownItems:    2,
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                   "apc-1",
					PathMap:                  AgentActionBOMPrimaryPathMap{Tool: "workflow", RepoPR: "repo-a", Workflow: "loc-release", Credential: "github_pat | standing", Action: "credential_access,deploy,read", Target: risk.TargetClassProductionImpacting},
					BoundaryLabel:            BoundaryLabelReportOnly,
					DelegationReadinessState: risk.DelegationReadinessBlocked,
					RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
					RiskTier:                 risk.RiskTierCritical,
					ApprovalEvidenceState:    risk.EvidenceStateUnknown,
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					RuntimeEvidenceState:     risk.EvidenceStateUnknown,
					UnresolvedEvidence:       []string{"approval", "proof"},
					RecommendedNextActions:   []string{"replace standing credential authority on this CI/CD workflow path with brokered or repo-scoped JIT access"},
				},
			},
			Items: items,
		},
		WorkflowHighlights: &WorkflowHighlights{
			TotalItems: 2,
			Highlights: []WorkflowHighlight{
				{PathID: "apc-1", Repo: "repo-a", Workflow: "loc-release", PathType: risk.ActionPathTypeCICDWorkflow, TargetClass: risk.TargetClassProductionImpacting, DelegationReadiness: risk.DelegationReadinessBlocked, Authority: "github_pat | workflow | standing", Recommendation: "replace standing credential authority on this CI/CD workflow path with brokered or repo-scoped JIT access"},
				{PathID: "apc-2", Repo: "repo-a", Workflow: "loc-release", PathType: risk.ActionPathTypeCICDWorkflow, TargetClass: risk.TargetClassProductionImpacting, DelegationReadiness: risk.DelegationReadinessBlocked, Authority: "github_pat | workflow | standing", Recommendation: "attach scoped approval evidence for this CI/CD workflow path"},
			},
		},
	}

	markdown := RenderMarkdown(summary)
	contextIdx := strings.Index(markdown, "## Report Context Appendix")
	if contextIdx < 0 {
		t.Fatalf("expected context appendix, got %q", markdown)
	}
	lead := markdown[:contextIdx]
	if !strings.Contains(lead, "Inspect next") {
		t.Fatalf("expected distinct remediation action to stay visible in inspect cards:\n%s", lead)
	}
	if strings.Contains(lead, "plus 1 related authority collapsed") {
		t.Fatalf("expected different remediation actions not to collapse as related authorities:\n%s", lead)
	}
	topPathsIdx := strings.Index(lead, "## Top Action Paths")
	if topPathsIdx < 0 {
		t.Fatalf("expected top action paths section, got:\n%s", lead)
	}
	if count := strings.Count(lead[topPathsIdx:], "\n- "); count != 2 {
		t.Fatalf("expected separate top action paths for different remediation actions, got %d:\n%s", count, lead[topPathsIdx:])
	}
	if !strings.Contains(lead[topPathsIdx:], "replace standing credential authority") || !strings.Contains(lead[topPathsIdx:], "attach scoped approval evidence") {
		t.Fatalf("expected both remediation actions in top action paths, got:\n%s", lead[topPathsIdx:])
	}
	if !strings.Contains(markdown[contextIdx:], "repo=repo-a location=loc-release") {
		t.Fatalf("expected appendix detail to remain available, got:\n%s", markdown)
	}
}
