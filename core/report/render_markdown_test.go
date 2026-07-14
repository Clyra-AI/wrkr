package report

import (
	"fmt"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/governancequeue"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestContradictionMarkdownIsEvidenceScoped(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-05-25T18:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-1",
			Summary: AgentActionBOMSummary{
				TotalItems:         1,
				ControlFirstItems:  1,
				CoverageConfidence: "high",
			},
			Items: []AgentActionBOMItem{{
				Repo:                   "acme/release",
				Location:               ".github/workflows/release.yml",
				ConfidenceLane:         "confirmed_action_path",
				ActionPathType:         "ci_cd_workflow",
				ControlState:           "block_recommended",
				RiskZone:               "release",
				TargetClass:            "production_impacting",
				ReviewBurden:           "critical",
				ControlPriority:        "control_first",
				RiskTier:               "critical",
				ControlResolutionState: "contradictory_control",
				ApprovalEvidenceState:  "unknown",
				OwnerEvidenceState:     "unknown",
				ProofEvidenceState:     "unknown",
				RuntimeEvidenceState:   "unknown",
				Confidence:             "high",
				EvidenceStrength:       "high",
				Queue:                  "control_first",
				Remediation:            "Resolve contradictory evidence.",
				Contradictions: []evidencepolicy.Contradiction{{
					Class:       "non_prod_vs_credential",
					ReasonCodes: []string{"contradiction:non_prod_declared_with_production_credential"},
					EvidenceRefs: []string{
						"evidence://customer/declarations.yaml#non-prod",
						"credential:static_secret",
					},
				}},
			}},
		},
	})
	if !strings.Contains(markdown, "contradictions=") {
		t.Fatalf("expected contradiction summary in markdown, got %q", markdown)
	}
	if strings.Contains(markdown, "ghp_") {
		t.Fatalf("expected markdown to stay evidence-scoped, got %q", markdown)
	}
}

func TestRenderMarkdownNamesProposedActionContractAsReportOnly(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-07-13T18:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-1",
			Summary: AgentActionBOMSummary{
				TotalItems:         1,
				ControlFirstItems:  1,
				CoverageConfidence: "complete",
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                     "apc-primary",
					SelectionReason:            AgentActionBOMPrimarySelectionDefaultTopPath,
					PathMap:                    AgentActionBOMPrimaryPathMap{Tool: "codex", RepoPR: "acme/app", Workflow: "release", Credential: "github token", Action: "deploy", Target: "production"},
					DelegationReadinessState:   risk.DelegationReadinessReviewRequired,
					RiskTier:                   risk.RiskTierHigh,
					AutonomyTier:               risk.AutonomyTier4ProdPrivilegedCustomerImpact,
					RecommendedControl:         risk.RecommendedControlApprovalRequired,
					ProposedActionContractRefs: []string{"pac-1234"},
				},
			},
			Items: []AgentActionBOMItem{{PathID: "apc-primary"}},
		},
	})
	if !strings.Contains(markdown, "Proposed Action Contract refs: pac-1234 (report-only; Wrkr does not enforce runtime policy).") {
		t.Fatalf("expected report-only proposed Action Contract wording, got %q", markdown)
	}
	if strings.Contains(markdown, "Wrkr enforces") {
		t.Fatalf("markdown must not imply Wrkr enforces proposed contracts, got %q", markdown)
	}
}

func TestMarkdownProposedActionContractRefsStayBounded(t *testing.T) {
	t.Parallel()

	got := markdownProposedActionContractRefs([]string{"pac-4", "pac-2", "pac-1", "pac-3"})
	if got != "pac-1, pac-2, pac-3 (+1 more)" {
		t.Fatalf("expected bounded sorted proposed contract refs, got %q", got)
	}
}

func TestRenderMarkdownUsesEvidenceScopedLifecycleAndGaitLabels(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-06-23T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-1",
			Summary: AgentActionBOMSummary{
				TotalItems:         1,
				CoverageConfidence: "medium",
			},
			Items: []AgentActionBOMItem{{
				Repo:                     "acme/app",
				Location:                 ".github/workflows/ci.yml",
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				ControlPriority:          risk.ControlPriorityInventoryHygiene,
				RiskTier:                 risk.RiskTierLow,
				ApprovalEvidenceState:    risk.EvidenceStateUnknown,
				ProofEvidenceState:       risk.EvidenceStateUnknown,
				RuntimeEvidenceState:     risk.EvidenceStateUnknown,
				TargetClass:              risk.TargetClassUnknown,
				DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				LifecycleQueue: &governancequeue.Item{
					ReasonCode:       "missing_approval",
					Severity:         "medium",
					CredentialStatus: governancequeue.CredentialStatusNone,
					ClosureCriteria:  "Attach fresh approval evidence.",
				},
				GaitCoverage: &risk.GaitCoverage{
					PolicyDecision:    risk.GaitCoverageDetail{Status: risk.GaitStatusMissing},
					Approval:          risk.GaitCoverageDetail{Status: risk.GaitStatusMissing},
					JITCredential:     risk.GaitCoverageDetail{Status: risk.GaitStatusNotApplicable},
					FreezeWindow:      risk.GaitCoverageDetail{Status: risk.GaitStatusMissing},
					KillSwitch:        risk.GaitCoverageDetail{Status: risk.GaitStatusMissing},
					ActionOutcome:     risk.GaitCoverageDetail{Status: risk.GaitStatusMissing},
					ProofVerification: risk.GaitCoverageDetail{Status: risk.GaitStatusMissing},
				},
			}},
		},
	})

	if strings.Contains(markdown, "missing_approval") || strings.Contains(markdown, "approval:missing") {
		t.Fatalf("expected evidence-scoped lifecycle and Gait labels, got %q", markdown)
	}
	if !strings.Contains(markdown, "approval_evidence_not_found") || !strings.Contains(markdown, "approval:not_observed") {
		t.Fatalf("expected readable evidence labels, got %q", markdown)
	}
}

func TestBuildAttackPathFactsExplainsNonGenerationForHighImpactPaths(t *testing.T) {
	t.Parallel()

	facts := buildAttackPathFacts(risk.Report{
		ActionPaths: []risk.ActionPath{{
			PathID:                   "apc-critical",
			ActionPathEligible:       true,
			ActionBindingState:       risk.ActionBindingStateBound,
			TargetClass:              risk.TargetClassProductionImpacting,
			DelegationReadinessState: risk.DelegationReadinessBlocked,
			CredentialAccess:         true,
		}},
	})

	if len(facts) != 1 {
		t.Fatalf("expected one attack-path fact, got %+v", facts)
	}
	if !strings.Contains(facts[0], "graph") || !strings.Contains(facts[0], "governable action paths") {
		t.Fatalf("expected graph-prerequisite explanation, got %+v", facts)
	}

	emptyFacts := buildAttackPathFacts(risk.Report{})
	if len(emptyFacts) != 1 || emptyFacts[0] != "attack paths: none generated from current findings" {
		t.Fatalf("expected simple empty-report wording, got %+v", emptyFacts)
	}

	contextOnlyFacts := buildAttackPathFacts(risk.Report{
		ActionPaths: []risk.ActionPath{{
			PathID:                   "apc-context",
			ActionPathEligible:       false,
			ActionBindingState:       risk.ActionBindingStateUnboundContext,
			ConfidenceLane:           risk.ConfidenceLaneContextOnly,
			TargetClass:              risk.TargetClassProductionImpacting,
			DelegationReadinessState: risk.DelegationReadinessBlocked,
			CredentialAccess:         true,
		}},
	})
	if len(contextOnlyFacts) != 1 || contextOnlyFacts[0] != "attack paths: none generated from current findings" {
		t.Fatalf("expected context-only paths to avoid governable gap wording, got %+v", contextOnlyFacts)
	}
}

func TestRenderMarkdownSummarizesFirstRunEvidenceOnboarding(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-06-26T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{
			BOMID: "bom-evidence-onboarding",
			Summary: AgentActionBOMSummary{
				TotalItems:                   3,
				ControlFirstItems:            3,
				ApprovalEvidenceUnknownItems: 3,
				ProofEvidenceUnknownItems:    3,
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                   "apc-1",
					PathMap:                  AgentActionBOMPrimaryPathMap{Tool: "workflow", RepoPR: "repo-a", Workflow: "loc-release", Credential: "github_pat | standing", Action: "deploy", Target: risk.TargetClassProductionImpacting},
					BoundaryLabel:            BoundaryLabelReportOnly,
					DelegationReadinessState: risk.DelegationReadinessReviewRequired,
					RecommendedControl:       risk.RecommendedControlSecurityReview,
					RiskTier:                 risk.RiskTierCritical,
					ControlResolutionState:   risk.ControlResolutionStateDetectedControl,
					ApprovalEvidenceState:    risk.EvidenceStateUnknown,
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					RuntimeEvidenceState:     risk.EvidenceStateUnknown,
					UnresolvedEvidence:       []string{"approval", "proof"},
					RecommendedNextActions:   []string{"Attach approval evidence for this exact workflow path", "Attach path-specific proof before promotion"},
				},
			},
			Items: []AgentActionBOMItem{{
				PathID:                   "apc-1",
				Repo:                     "repo-a",
				Location:                 "loc-release",
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				TargetClass:              risk.TargetClassProductionImpacting,
				DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				ControlResolutionState:   risk.ControlResolutionStateDetectedControl,
				ApprovalEvidenceState:    risk.EvidenceStateUnknown,
				ProofEvidenceState:       risk.EvidenceStateUnknown,
				RuntimeEvidenceState:     risk.EvidenceStateUnknown,
			}},
		},
		WorkflowHighlights: &WorkflowHighlights{
			TotalItems: 1,
			Highlights: []WorkflowHighlight{{
				PathID:              "apc-1",
				Repo:                "repo-a",
				Workflow:            "loc-release",
				PathType:            risk.ActionPathTypeCICDWorkflow,
				TargetClass:         risk.TargetClassProductionImpacting,
				DelegationReadiness: risk.DelegationReadinessReviewRequired,
				Authority:           "github_pat | workflow | standing",
				EvidenceSummary:     "control=visible control evidence detected",
				ApprovalPath:        "approval evidence not found",
				ProofStatus:         "path-specific proof not found",
				RuntimeStatus:       "runtime evidence not collected",
				Recommendation:      "Attach approval evidence for this exact workflow path",
			}},
		},
	}

	markdown := RenderMarkdown(summary)
	contextIdx := strings.Index(markdown, "## Report Context Appendix")
	if contextIdx < 0 {
		t.Fatalf("expected report context appendix, got %q", markdown)
	}
	lead := markdown[:contextIdx]
	if !strings.Contains(lead, "Evidence onboarding: approval/proof evidence was not imported or observed") {
		t.Fatalf("expected evidence onboarding note, got:\n%s", lead)
	}
	if count := strings.Count(lead, "approval evidence not found"); count > 1 {
		t.Fatalf("expected repeated raw approval evidence gap to be summarized in lead, got %d:\n%s", count, lead)
	}
	if count := strings.Count(lead, "path-specific proof not found"); count > 1 {
		t.Fatalf("expected repeated raw proof evidence gap to be summarized in lead, got %d:\n%s", count, lead)
	}
}

func TestEvidenceOnboardingUsesGovernableItemCounts(t *testing.T) {
	t.Parallel()

	summary := Summary{
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{
				TotalItems:                   3,
				ApprovalEvidenceUnknownItems: 2,
				ProofEvidenceUnknownItems:    2,
			},
			Items: []AgentActionBOMItem{
				{
					PathID:                   "context-1",
					ActionPathEligible:       false,
					ActionBindingState:       risk.ActionBindingStateUnboundContext,
					ConfidenceLane:           risk.ConfidenceLaneContextOnly,
					ActionPathType:           risk.ActionPathTypePlainSourceCode,
					TargetClass:              risk.TargetClassProductionImpacting,
					ApprovalEvidenceState:    risk.EvidenceStateUnknown,
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				},
				{
					PathID:                   "context-2",
					ActionPathEligible:       false,
					ActionBindingState:       risk.ActionBindingStateUnboundContext,
					ConfidenceLane:           risk.ConfidenceLaneContextOnly,
					ActionPathType:           risk.ActionPathTypePlainSourceCode,
					TargetClass:              risk.TargetClassProductionImpacting,
					ApprovalEvidenceState:    risk.EvidenceStateUnknown,
					ProofEvidenceState:       risk.EvidenceStateUnknown,
					DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				},
				{
					PathID:                   "workflow-1",
					ActionPathEligible:       true,
					ActionBindingState:       risk.ActionBindingStateBound,
					ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
					ActionPathType:           risk.ActionPathTypeCICDWorkflow,
					TargetClass:              risk.TargetClassProductionImpacting,
					ApprovalEvidenceState:    risk.EvidenceStateVerified,
					ProofEvidenceState:       risk.EvidenceStateVerified,
					DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				},
			},
		},
	}
	if shouldRenderEvidenceOnboarding(summary) {
		t.Fatalf("expected context-only evidence gaps to be excluded from governable onboarding decision")
	}

	summary.AgentActionBOM.Items[2].ApprovalEvidenceState = risk.EvidenceStateUnknown
	summary.AgentActionBOM.Items[2].ProofEvidenceState = risk.EvidenceStateUnknown
	if !shouldRenderEvidenceOnboarding(summary) {
		t.Fatalf("expected eligible governable evidence gaps to enable onboarding decision")
	}

	summary.AgentActionBOM.Items = append(summary.AgentActionBOM.Items, AgentActionBOMItem{
		PathID:                   "workflow-2",
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		ApprovalEvidenceState:    risk.EvidenceStateVerified,
		ProofEvidenceState:       risk.EvidenceStateVerified,
		DelegationReadinessState: risk.DelegationReadinessReviewRequired,
	})
	if shouldRenderEvidenceOnboarding(summary) {
		t.Fatalf("expected half of eligible governable paths missing evidence to stay below most-paths threshold")
	}
	summary.AgentActionBOM.Items[3].ApprovalEvidenceState = risk.EvidenceStateUnknown
	summary.AgentActionBOM.Items[3].ProofEvidenceState = risk.EvidenceStateUnknown
	if !shouldRenderEvidenceOnboarding(summary) {
		t.Fatalf("expected strict majority of eligible governable paths missing evidence to enable onboarding")
	}
}

func TestEvidenceOnboardingUsesUncappedFocusSourceItems(t *testing.T) {
	t.Parallel()

	missing := AgentActionBOMItem{
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		ApprovalEvidenceState:    risk.EvidenceStateUnknown,
		ProofEvidenceState:       risk.EvidenceStateUnknown,
		DelegationReadinessState: risk.DelegationReadinessReviewRequired,
	}
	verified := missing
	verified.ApprovalEvidenceState = risk.EvidenceStateVerified
	verified.ProofEvidenceState = risk.EvidenceStateVerified

	summary := Summary{
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{
				missing,
				missing,
			},
			focusSourceItems: []AgentActionBOMItem{
				missing,
				missing,
				verified,
				verified,
				verified,
			},
		},
	}
	if shouldRenderEvidenceOnboarding(summary) {
		t.Fatalf("expected uncapped source rows to keep capped missing rows below most-paths threshold")
	}
}

func TestSummarizedLeadUnresolvedEvidenceKeepsEmptyCardsResolved(t *testing.T) {
	t.Parallel()

	if got := summarizedLeadUnresolvedEvidence(nil); got != "none" {
		t.Fatalf("expected empty unresolved evidence to remain resolved, got %q", got)
	}
	if got := summarizedLeadUnresolvedEvidence([]string{""}); got != "none" {
		t.Fatalf("expected blank unresolved evidence to remain resolved, got %q", got)
	}
	if got := summarizedLeadUnresolvedEvidence([]string{"approval", "runtime"}); got != "see evidence onboarding note, runtime" {
		t.Fatalf("expected approval/proof gaps to collapse to onboarding note with other gaps preserved, got %q", got)
	}
}

func TestBuyerDiagnosticCardsKeepFocusedSiblingHighlightVisible(t *testing.T) {
	t.Parallel()

	primary := AgentActionBOMItem{
		PathID:                   "apc-focused",
		Repo:                     "acme/release",
		Location:                 ".github/workflows/release.yml",
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassReleaseAdjacent,
		DelegationReadinessState: risk.DelegationReadinessReviewRequired,
		ControlResolutionState:   risk.ControlResolutionStateDetectedControl,
		ApprovalEvidenceState:    risk.EvidenceStateVerified,
		ProofEvidenceState:       risk.EvidenceStateVerified,
		RuntimeEvidenceState:     risk.EvidenceStateUnknown,
	}
	siblingA := primary
	siblingA.PathID = "apc-sibling-a"
	siblingB := primary
	siblingB.PathID = "apc-sibling-b"

	summary := Summary{
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{
					PathID:                   primary.PathID,
					PathMap:                  AgentActionBOMPrimaryPathMap{Tool: "workflow", RepoPR: primary.Repo, Workflow: primary.Location, Target: primary.TargetClass},
					DelegationReadinessState: primary.DelegationReadinessState,
					ControlResolutionState:   primary.ControlResolutionState,
					ApprovalEvidenceState:    primary.ApprovalEvidenceState,
					ProofEvidenceState:       primary.ProofEvidenceState,
					RuntimeEvidenceState:     primary.RuntimeEvidenceState,
					RecommendedNextActions:   []string{"review focused path"},
				},
			},
			Items: []AgentActionBOMItem{primary, siblingA, siblingB},
		},
		WorkflowHighlights: &WorkflowHighlights{
			TotalItems: 2,
			Highlights: []WorkflowHighlight{
				workflowHighlightFromItem(siblingA),
				workflowHighlightFromItem(siblingB),
			},
		},
	}

	cards := buildBuyerDiagnosticCards(summary)
	if len(cards) < 2 {
		t.Fatalf("expected focused primary and sibling highlight cards, got %+v", cards)
	}
	if cards[0].RelatedCount != 0 {
		t.Fatalf("expected sibling group not to collapse into focused primary, got related=%d", cards[0].RelatedCount)
	}
	if cards[1].RelatedCount != 2 {
		t.Fatalf("expected sibling card to retain collapsed sibling count, got %+v", cards[1])
	}
}

func TestWorkflowHighlightAuthorityFamilyKeepsNoCredentialSeparate(t *testing.T) {
	t.Parallel()

	if got := workflowHighlightAuthorityFamily("no credential authority linked"); got != "no_credential" {
		t.Fatalf("expected no-credential authority family, got %q", got)
	}
	if got := workflowHighlightAuthorityFamily("credential authority linked"); got != "credential" {
		t.Fatalf("expected generic credential authority family, got %q", got)
	}
}

func TestBuyerDiagnosticCardsUseUncappedBOMSourceItems(t *testing.T) {
	t.Parallel()

	base := AgentActionBOMItem{
		Repo:                     "acme/release",
		Location:                 ".github/workflows/release.yml",
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		DelegationReadinessState: risk.DelegationReadinessReviewRequired,
		CredentialAccess:         true,
		ApprovalEvidenceState:    risk.EvidenceStateUnknown,
		ProofEvidenceState:       risk.EvidenceStateUnknown,
		RuntimeEvidenceState:     risk.EvidenceStateUnknown,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
		},
	}
	items := make([]AgentActionBOMItem, 0, workflowHighlightLimit+1)
	for idx := 0; idx < workflowHighlightLimit; idx++ {
		item := base
		item.PathID = fmt.Sprintf("apc-duplicate-%d", idx+1)
		items = append(items, item)
	}
	distinct := base
	distinct.PathID = "apc-distinct"
	distinct.Location = ".github/workflows/deploy-prod.yml"
	distinct.DelegationReadinessState = risk.DelegationReadinessBlocked
	distinct.ControlState = "block_recommended"
	distinct.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		StandingAccess:         true,
	}
	items = append(items, distinct)

	bom := &AgentActionBOM{
		Items:            append([]AgentActionBOMItem(nil), items[:workflowHighlightLimit]...),
		focusSourceItems: items,
	}
	bom.Summary.PrimaryView = &AgentActionBOMPrimaryView{
		PathID: items[0].PathID,
		PathMap: AgentActionBOMPrimaryPathMap{
			Tool:     "workflow",
			RepoPR:   items[0].Repo,
			Workflow: items[0].Location,
			Target:   items[0].TargetClass,
		},
		DelegationReadinessState: items[0].DelegationReadinessState,
		ApprovalEvidenceState:    risk.EvidenceStateUnknown,
		ProofEvidenceState:       risk.EvidenceStateUnknown,
		RuntimeEvidenceState:     risk.EvidenceStateUnknown,
		UnresolvedEvidence:       []string{"approval", "proof"},
		RecommendedNextActions:   []string{"attach scoped approval evidence for this CI/CD workflow path"},
	}

	summary := Summary{
		Template:           string(TemplateAgentActionBOM),
		ShareProfile:       string(ShareProfileInternal),
		AgentActionBOM:     bom,
		WorkflowHighlights: BuildWorkflowHighlights(Summary{AgentActionBOM: bom}),
	}
	markdown := RenderMarkdown(summary)
	leadEnd := strings.Index(markdown, "## Primary Workflow BOM")
	if leadEnd < 0 {
		t.Fatalf("expected primary workflow section, got:\n%s", markdown)
	}
	lead := markdown[:leadEnd]
	if !strings.Contains(lead, "Inspect next") || !strings.Contains(lead, "deploy-prod.yml") {
		t.Fatalf("expected inspect card for distinct path beyond public item cap, got:\n%s", lead)
	}
}

func TestWorkflowHighlightGroupingSeparatesGitHubCredentialKinds(t *testing.T) {
	t.Parallel()

	if got := workflowHighlightAuthorityFamily("github_pat | workflow"); got != "github_pat" {
		t.Fatalf("expected GitHub PAT authority family, got %q", got)
	}
	if got := workflowHighlightAuthorityFamily("github_workflow_token | workflow"); got != "github_workflow_token" {
		t.Fatalf("expected GitHub workflow token authority family, got %q", got)
	}

	base := WorkflowHighlight{
		Repo:                "acme/release",
		Workflow:            ".github/workflows/release.yml",
		PathType:            risk.ActionPathTypeCICDWorkflow,
		TargetClass:         risk.TargetClassProductionImpacting,
		DelegationReadiness: risk.DelegationReadinessReviewRequired,
	}
	workflowToken := base
	workflowToken.PathID = "apc-workflow-token"
	workflowToken.Authority = "github_workflow_token | workflow"
	pat := base
	pat.PathID = "apc-pat"
	pat.Authority = "github_pat | workflow"

	groups := compactWorkflowHighlightGroups([]WorkflowHighlight{workflowToken, pat})
	if len(groups) != 2 {
		t.Fatalf("expected GitHub workflow token and PAT highlights to stay separate, got %+v", groups)
	}
}

func TestWorkflowHighlightGroupingSeparatesRecommendationFamilies(t *testing.T) {
	t.Parallel()

	base := WorkflowHighlight{
		Repo:                "acme/release",
		Workflow:            ".github/workflows/release.yml",
		PathType:            risk.ActionPathTypeCICDWorkflow,
		TargetClass:         risk.TargetClassProductionImpacting,
		DelegationReadiness: risk.DelegationReadinessBlocked,
		Authority:           "github_pat | workflow | standing",
		EvidenceSummary:     "control=no visible control evidence found | owner=owner evidence verified",
		ApprovalPath:        "approval evidence not found",
		ProofStatus:         "path-specific proof not found",
		RuntimeStatus:       "runtime evidence not collected",
	}
	replaceCredential := base
	replaceCredential.PathID = "apc-standing"
	replaceCredential.Recommendation = "replace standing credential authority on this CI/CD workflow path with brokered or repo-scoped JIT access"
	attachApproval := base
	attachApproval.PathID = "apc-approval"
	attachApproval.Recommendation = "attach scoped approval evidence for this CI/CD workflow path"

	groups := compactWorkflowHighlightGroups([]WorkflowHighlight{replaceCredential, attachApproval})
	if len(groups) != 2 {
		t.Fatalf("expected distinct recommendation families to stay separate, got %+v", groups)
	}
}

func TestWorkflowHighlightGroupingSeparatesEvidenceFamilies(t *testing.T) {
	t.Parallel()

	base := WorkflowHighlight{
		Repo:                "acme/release",
		Workflow:            ".github/workflows/release.yml",
		PathType:            risk.ActionPathTypeCICDWorkflow,
		TargetClass:         risk.TargetClassProductionImpacting,
		DelegationReadiness: risk.DelegationReadinessReviewRequired,
		Authority:           "github_workflow_token | workflow",
		Recommendation:      "review this workflow path",
		EvidenceSummary:     "control=visible control evidence detected | owner=owner evidence verified",
		RuntimeStatus:       "runtime evidence not collected",
	}
	approvalGap := base
	approvalGap.PathID = "apc-approval"
	approvalGap.ApprovalPath = "approval evidence not found"
	approvalGap.ProofStatus = "path-specific proof verified"
	proofGap := base
	proofGap.PathID = "apc-proof"
	proofGap.ApprovalPath = "approval evidence verified"
	proofGap.ProofStatus = "path-specific proof not found"

	groups := compactWorkflowHighlightGroups([]WorkflowHighlight{approvalGap, proofGap})
	if len(groups) != 2 {
		t.Fatalf("expected unresolved evidence drivers to stay separate, got %+v", groups)
	}
}

func TestCompactTopActionPathsGroupsBeforeDisplayCap(t *testing.T) {
	t.Parallel()

	base := AgentActionBOMItem{
		Repo:                     "acme/release",
		Location:                 ".github/workflows/release.yml",
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		DelegationReadinessState: risk.DelegationReadinessReviewRequired,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubPAT,
		},
	}
	items := make([]AgentActionBOMItem, 0, workflowHighlightLimit+1)
	for idx := 0; idx < workflowHighlightLimit; idx++ {
		item := base
		item.PathID = "apc-duplicate-" + string(rune('a'+idx))
		items = append(items, item)
	}
	distinct := base
	distinct.PathID = "apc-distinct"
	distinct.Location = ".github/workflows/deploy-prod.yml"
	items = append(items, distinct)

	highlights := BuildWorkflowHighlights(Summary{AgentActionBOM: &AgentActionBOM{Items: items}})
	if highlights == nil || len(highlights.Highlights) != workflowHighlightLimit {
		t.Fatalf("expected public highlights to stay capped at %d, got %+v", workflowHighlightLimit, highlights)
	}

	var builder strings.Builder
	renderCompactTopActionPathsSection(&builder, highlights)
	markdown := builder.String()
	if !strings.Contains(markdown, "deploy-prod.yml") {
		t.Fatalf("expected compact section to include distinct group beyond raw cap, got:\n%s", markdown)
	}
	if count := strings.Count(markdown, "- "); count != 2 {
		t.Fatalf("expected duplicate group plus distinct group, got %d rows:\n%s", count, markdown)
	}
}

func TestWorkflowHighlightGroupingSeparatesStandingCredentialMetadata(t *testing.T) {
	t.Parallel()

	base := AgentActionBOMItem{
		PathID:                   "apc-non-standing",
		Repo:                     "acme/release",
		Location:                 ".github/workflows/release.yml",
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassReleaseAdjacent,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		AuthorityBindings: []*agginventory.AuthorityBinding{{
			Kind:         agginventory.AuthorityBindingCloudRole,
			Provider:     "aws",
			TargetSystem: "deploy",
			AccessLevel:  agginventory.AuthorityAccessWrite,
		}},
	}
	standing := base
	standing.PathID = "apc-standing"
	standing.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		StandingAccess:         true,
	}

	standingAuthority := workflowAuthoritySummary(standing)
	if !strings.Contains(strings.ToLower(standingAuthority), "standing credential") {
		t.Fatalf("expected standing metadata in authority summary, got %q", standingAuthority)
	}
	groups := compactWorkflowHighlightGroups([]WorkflowHighlight{
		workflowHighlightFromItem(base),
		workflowHighlightFromItem(standing),
	})
	if len(groups) != 2 {
		t.Fatalf("expected standing and non-standing authority highlights to stay separate, got %+v", groups)
	}
}

func TestWorkflowHighlightGroupingSeparatesStandingCredentialWithoutAccessType(t *testing.T) {
	t.Parallel()

	base := AgentActionBOMItem{
		PathID:                   "apc-non-standing",
		Repo:                     "acme/release",
		Location:                 ".github/workflows/release.yml",
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		TargetClass:              risk.TargetClassReleaseAdjacent,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
		},
	}
	standing := base
	standing.PathID = "apc-standing"
	standing.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		CredentialKind:         agginventory.CredentialKindGitHubWorkflowToken,
		StandingAccess:         true,
	}

	standingAuthority := workflowAuthoritySummary(standing)
	if !strings.Contains(strings.ToLower(standingAuthority), "standing credential") {
		t.Fatalf("expected standing metadata without access type in authority summary, got %q", standingAuthority)
	}
	groups := compactWorkflowHighlightGroups([]WorkflowHighlight{
		workflowHighlightFromItem(base),
		workflowHighlightFromItem(standing),
	})
	if len(groups) != 2 {
		t.Fatalf("expected standing and non-standing credential highlights to stay separate, got %+v", groups)
	}
}
