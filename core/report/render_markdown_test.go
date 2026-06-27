package report

import (
	"strings"
	"testing"

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

func TestWorkflowHighlightAuthorityFamilyKeepsNoCredentialSeparate(t *testing.T) {
	t.Parallel()

	if got := workflowHighlightAuthorityFamily("no credential authority linked"); got != "no_credential" {
		t.Fatalf("expected no-credential authority family, got %q", got)
	}
	if got := workflowHighlightAuthorityFamily("credential authority linked"); got != "credential" {
		t.Fatalf("expected generic credential authority family, got %q", got)
	}
}
