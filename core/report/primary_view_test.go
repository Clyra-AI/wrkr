package report

import (
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

func TestApplyAgentActionBOMFocusSelectsSuppressedSourceItem(t *testing.T) {
	t.Parallel()

	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		StandingAccess:         true,
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingSaaSToken,
		Provider:     "github",
		TargetSystem: "source_control",
		LikelyScope:  "repo_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Confidence:   "high",
	}
	visible := []AgentActionBOMItem{
		{
			PathID:         "apc-visible-1",
			Org:            "acme",
			Repo:           "acme/release",
			ToolType:       "codex",
			Location:       ".github/workflows/release.yml",
			ConfidenceLane: risk.ConfidenceLaneConfirmedActionPath,
			ActionPathType: risk.ActionPathTypeCICDWorkflow,
		},
		{
			PathID:         "apc-visible-2",
			Org:            "acme",
			Repo:           "acme/release",
			ToolType:       "codex",
			Location:       ".github/workflows/deploy.yml",
			ConfidenceLane: risk.ConfidenceLaneLikelyActionPath,
			ActionPathType: risk.ActionPathTypeCICDWorkflow,
		},
	}
	suppressed := AgentActionBOMItem{
		PathID:                   "apc-suppressed-focus",
		Org:                      "acme",
		Repo:                     "acme/release",
		ToolType:                 "codex",
		Location:                 ".github/workflows/publish.yml",
		ConfidenceLane:           risk.ConfidenceLaneSemanticReviewCandidate,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		DelegationReadinessState: risk.DelegationReadinessProofRequired,
		RecommendedControl:       risk.RecommendedControlProofRequired,
		MutableEndpointSemantics: semantics,
		CredentialAuthority:      authority,
		AuthorityBindings:        []*agginventory.AuthorityBinding{binding},
	}
	summary := Summary{
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{},
			Items:   append([]AgentActionBOMItem(nil), visible...),
			focusSourceItems: append(append([]AgentActionBOMItem(nil), visible...),
				suppressed,
			),
		},
	}

	if err := ApplyAgentActionBOMFocus(&summary, "apc-suppressed-focus"); err != nil {
		t.Fatalf("expected suppressed focus path to remain selectable: %v", err)
	}
	if summary.AgentActionBOM.Summary.PrimaryView == nil || summary.AgentActionBOM.Summary.PrimaryView.PathID != "apc-suppressed-focus" {
		t.Fatalf("expected primary view for suppressed focus path, got %+v", summary.AgentActionBOM.Summary.PrimaryView)
	}
	if !agentActionBOMItemsContainPath(summary.AgentActionBOM.Items, "apc-suppressed-focus") {
		t.Fatalf("expected focused source item to be visible in capped BOM items, got %+v", summary.AgentActionBOM.Items)
	}
	focusedItem, ok := agentActionBOMItemByPath(summary.AgentActionBOM.Items, "apc-suppressed-focus")
	if !ok {
		t.Fatalf("expected focused source item to be visible in capped BOM items, got %+v", summary.AgentActionBOM.Items)
	}
	if focusedItem.CredentialAuthorityRef == "" || len(focusedItem.AuthorityBindingRefs) == 0 || len(focusedItem.MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected focused display item to carry canonical refs, got %+v", focusedItem)
	}
	if focusedItem.CredentialAuthority != nil || len(focusedItem.AuthorityBindings) > 0 || len(focusedItem.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected focused display item to omit embedded canonical payload clones, got %+v", focusedItem)
	}
	sourceItem, ok := agentActionBOMItemByPath(summary.AgentActionBOM.focusSourceItems, "apc-suppressed-focus")
	if !ok {
		t.Fatalf("expected rich focused source item to remain available, got %+v", summary.AgentActionBOM.focusSourceItems)
	}
	if sourceItem.CredentialAuthority == nil || len(sourceItem.AuthorityBindings) == 0 || len(sourceItem.MutableEndpointSemantics) == 0 {
		t.Fatalf("expected rich focused source item to remain unstripped for primary view context, got %+v", sourceItem)
	}
}

func agentActionBOMItemsContainPath(items []AgentActionBOMItem, pathID string) bool {
	_, ok := agentActionBOMItemByPath(items, pathID)
	return ok
}

func agentActionBOMItemByPath(items []AgentActionBOMItem, pathID string) (AgentActionBOMItem, bool) {
	for _, item := range items {
		if strings.TrimSpace(item.PathID) == pathID {
			return item, true
		}
	}
	return AgentActionBOMItem{}, false
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
