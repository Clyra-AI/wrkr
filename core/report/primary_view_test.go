package report

import (
	"strings"
	"testing"

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
	primaryIdx := strings.Index(markdown, "## Primary Workflow BOM")
	topPathsIdx := strings.Index(markdown, "## Top Action Paths")
	contextIdx := strings.Index(markdown, "## Report Context Appendix")
	appendixIdx := strings.Index(markdown, "## Workflow BOM Appendix")
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
	if primaryIdx > appendixIdx {
		t.Fatalf("expected primary workflow BOM to lead before appendix, got %q", markdown)
	}
	if !strings.Contains(markdown, "Workflow: codex in acme/release / pr/108 via .github/workflows/release.yml.") {
		t.Fatalf("expected human-readable workflow line in markdown, got %q", markdown)
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

func TestAgentActionBOMPrimaryViewFitsLineBudget(t *testing.T) {
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
