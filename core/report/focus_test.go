package report

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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

func TestWorkflowRecommendationForStandardCIImportsControlEvidence(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{
		ActionPathType:        risk.ActionPathTypeCICDWorkflow,
		ControlPriority:       risk.ControlPriorityInventoryHygiene,
		CredentialAccess:      true,
		ApprovalEvidenceState: risk.EvidenceStateUnknown,
		ProofEvidenceState:    risk.EvidenceStateUnknown,
	}

	recommendation := workflowRecommendation(item)
	if !strings.Contains(recommendation, "import PR review, branch protection, deployment environment, or owner-map evidence") {
		t.Fatalf("expected standard CI recommendation to ask for evidence import, got %q", recommendation)
	}
	explanation := workflowExplanation(item)
	if !strings.Contains(explanation, "standard CI authority") || !strings.Contains(explanation, "has not imported") {
		t.Fatalf("expected standard CI explanation to avoid missing-control claim, got %q", explanation)
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

func TestApplyAgentActionBOMFocusPreservesAuthorityDetailFromFocusSourceItems(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt: "2026-06-17T03:00:00Z",
		ActionPaths: []risk.ActionPath{risk.ProjectActionPath(risk.ActionPath{
			PathID:                   "apc-focus-authority",
			Org:                      "acme",
			Repo:                     "acme/release",
			ToolType:                 "compiled_action",
			Location:                 ".github/workflows/release.yml",
			WriteCapable:             true,
			CredentialAccess:         true,
			ApprovalGap:              true,
			ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
			ActionPathType:           risk.ActionPathTypeCICDWorkflow,
			DelegationReadinessState: risk.DelegationReadinessBlocked,
			RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
			CredentialAuthority: &agginventory.CredentialAuthority{
				CredentialPresent:      true,
				CredentialUsableByPath: true,
				CredentialKind:         agginventory.CredentialKindGitHubPAT,
				TargetSystem:           "source_control",
				LikelyScope:            "repo_write",
				AccessType:             agginventory.CredentialAccessTypeStanding,
				StandingAccess:         true,
			},
		})},
	}
	summary.AgentActionBOM = BuildAgentActionBOM(summary)
	if summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", summary.AgentActionBOM)
	}
	if summary.AgentActionBOM.Items[0].CredentialAuthority != nil {
		t.Fatalf("expected returned BOM items to be stripped by default, got %+v", summary.AgentActionBOM.Items[0])
	}

	if err := ApplyAgentActionBOMFocus(&summary, "apc-focus-authority"); err != nil {
		t.Fatalf("apply focus: %v", err)
	}
	if summary.AgentActionBOM.Summary.PrimaryView == nil {
		t.Fatalf("expected primary view after focus, got %+v", summary.AgentActionBOM.Summary)
	}
	if got := summary.AgentActionBOM.Summary.PrimaryView.PathMap.Credential; !strings.Contains(got, agginventory.CredentialKindGitHubPAT) || !strings.Contains(got, "standing") {
		t.Fatalf("expected focused primary view to preserve authority detail, got %q", got)
	}
}

func TestStaticAPIFindingRecommendsCallerCorrelation(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{
		ToolType:              "openapi",
		Location:              "openapi/payments.yaml",
		ActionPathType:        risk.ActionPathTypePlainSourceCode,
		ControlPriority:       risk.ControlPriorityReviewQueue,
		OwnerEvidenceState:    risk.EvidenceStateUnknown,
		ApprovalEvidenceState: risk.EvidenceStateUnknown,
		ProofEvidenceState:    risk.EvidenceStateUnknown,
		ConfidenceLane:        risk.ConfidenceLaneConfirmedActionPath,
		RecommendedControl:    risk.RecommendedControlProofRequired,
		RecommendedNextAction: "proof",
	}

	recommendation := strings.ToLower(workflowRecommendation(item))
	if strings.Contains(recommendation, "owner evidence") || strings.Contains(recommendation, "standing credential") {
		t.Fatalf("expected static API guidance to avoid owner or credential-first remediation, got %q", recommendation)
	}
	if !strings.Contains(recommendation, "caller") && !strings.Contains(recommendation, "correlat") {
		t.Fatalf("expected static API guidance to request caller correlation, got %q", recommendation)
	}
}

func TestWorkflowRecommendationDetectsStandingCredentialAuthorityBeforeBindingSummary(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		ControlState:             "block_recommended",
		ApprovalEvidenceState:    risk.EvidenceStateVerified,
		ProofEvidenceState:       risk.EvidenceStateVerified,
		OwnerEvidenceState:       risk.EvidenceStateVerified,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubPAT,
			AccessType:             agginventory.CredentialAccessTypeStanding,
			StandingAccess:         true,
		},
		AuthorityBindings: []*agginventory.AuthorityBinding{{
			Kind:         agginventory.AuthorityBindingCloudRole,
			Provider:     "aws",
			TargetSystem: "deploy",
			AccessLevel:  agginventory.AuthorityAccessWrite,
		}},
	}

	authoritySummary := strings.ToLower(workflowAuthoritySummary(item))
	if !strings.Contains(authoritySummary, "standing credential") {
		t.Fatalf("expected authority summary to preserve standing credential metadata, got %q", authoritySummary)
	}
	recommendation := strings.ToLower(workflowRecommendation(item))
	if !strings.Contains(recommendation, "replace standing credential authority") {
		t.Fatalf("expected standing credential replacement recommendation, got %q", recommendation)
	}
}

func TestWorkflowRecommendationPrioritizesBlockedStandingCredentialBeforeCorrelation(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		ControlState:             "block_recommended",
		CredentialAccess:         true,
		ApprovalEvidenceState:    risk.EvidenceStateVerified,
		ProofEvidenceState:       risk.EvidenceStateVerified,
		OwnerEvidenceState:       risk.EvidenceStateVerified,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: false,
			StandingAccess:         true,
		},
	}

	if !bomItemNeedsAuthorityCorrelation(item) {
		t.Fatalf("expected incomplete standing credential metadata to require authority correlation")
	}
	recommendation := strings.ToLower(workflowRecommendation(item))
	if !strings.Contains(recommendation, "replace standing credential authority") {
		t.Fatalf("expected blocked standing credential remediation to lead, got %q", recommendation)
	}
	if strings.Contains(recommendation, "classify or correlate") {
		t.Fatalf("expected remediation to avoid correlation-first wording, got %q", recommendation)
	}
	explanation := strings.ToLower(workflowExplanation(item))
	if !strings.Contains(explanation, "replacement or jit reduction") {
		t.Fatalf("expected explanation to preserve remediation-first rationale, got %q", explanation)
	}
}

func TestWorkflowRecommendationPrioritizesBlockedStandingCredentialBeforeStandardCI(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		ControlPriority:          risk.ControlPriorityInventoryHygiene,
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		ControlState:             "block_recommended",
		CredentialAccess:         true,
		ApprovalEvidenceState:    risk.EvidenceStateUnknown,
		ProofEvidenceState:       risk.EvidenceStateUnknown,
		OwnerEvidenceState:       risk.EvidenceStateVerified,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubPAT,
			StandingAccess:         true,
		},
	}

	if !bomItemStandardCIControlContext(item) {
		t.Fatalf("expected fixture to match standard CI context")
	}
	if !bomItemBlockedStandingCredential(item) {
		t.Fatalf("expected fixture to match blocked standing credential")
	}
	recommendation := strings.ToLower(workflowRecommendation(item))
	if !strings.Contains(recommendation, "replace standing credential authority") {
		t.Fatalf("expected blocked standing credential remediation to lead, got %q", recommendation)
	}
	if strings.Contains(recommendation, "import pr review") {
		t.Fatalf("expected remediation to avoid standard-CI import-first wording, got %q", recommendation)
	}
	explanation := strings.ToLower(workflowExplanation(item))
	if !strings.Contains(explanation, "replacement or jit reduction") {
		t.Fatalf("expected explanation to preserve standing remediation priority, got %q", explanation)
	}
}
