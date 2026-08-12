package report

import (
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestRenderMarkdownLeadsWithConfirmedExposuresAndSeparatesCandidates(t *testing.T) {
	t.Parallel()

	summary := Summary{
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{Items: []AgentActionBOMItem{
			{
				PathID:                   "confirmed-release-a",
				Repo:                     "repo-a",
				Location:                 ".github/workflows/release.yml",
				Owner:                    "release-team",
				ActionPathEligible:       true,
				ActionBindingState:       risk.ActionBindingStateBound,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				CredentialAccess:         true,
				StandingPrivilege:        true,
				TargetClass:              risk.TargetClassProductionImpacting,
				ActionClasses:            []string{"deploy"},
				DelegationReadinessState: risk.DelegationReadinessBlocked,
				RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
				CredentialAuthority:      &credentialAuthorityForBrief,
				ExecutionRelationships: []model.ExecutionRelationship{{
					Kind: "github_reusable_workflow", Caller: ".github/workflows/release.yml", Callee: ".github/workflows/shared.yml", Origin: "source_declared", ResolutionState: "resolved_local",
				}},
				ApprovalEvidenceState: risk.EvidenceStateUnknown,
				ProofEvidenceState:    risk.EvidenceStateUnknown,
				TargetEvidenceState:   risk.EvidenceStateInferred,
				ClosureActions: []risk.ClosureAction{{
					Title: "Attach deployment approval evidence",
				}},
			},
			{
				PathID:                   "confirmed-release-b",
				Repo:                     "repo-b",
				Location:                 ".github/workflows/publish.yml",
				Owner:                    "release-team",
				ActionPathEligible:       true,
				ActionBindingState:       risk.ActionBindingStateBound,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				CredentialAccess:         true,
				StandingPrivilege:        true,
				TargetClass:              risk.TargetClassProductionImpacting,
				ActionClasses:            []string{"deploy"},
				DelegationReadinessState: risk.DelegationReadinessBlocked,
				RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
				CredentialAuthority:      &credentialAuthorityForBrief,
			},
			{
				PathID:                   "inferred-egress",
				Repo:                     "repo-c",
				Location:                 "agents/export.go",
				Owner:                    "data-team",
				ActionPathEligible:       true,
				ActionBindingState:       risk.ActionBindingStatePartiallyBound,
				ActionPathType:           risk.ActionPathTypeAgentFramework,
				ConfidenceLane:           risk.ConfidenceLaneLikelyActionPath,
				CredentialAccess:         true,
				TargetClass:              risk.TargetClassCustomerDataAdjacent,
				ActionClasses:            []string{"egress"},
				DelegationReadinessState: risk.DelegationReadinessReviewRequired,
				RecommendedControl:       risk.RecommendedControlApprovalRequired,
				EvidenceDecisions: []evidencepolicy.Decision{{
					Field:                  evidencepolicy.FieldApproval,
					SelectedSourceType:     evidencepolicy.SourceTypeProviderExport,
					SelectedSource:         "github-branch-protection",
					SelectedFreshnessState: evidencepolicy.FreshnessStateFresh,
				}},
			},
		}},
	}

	markdown := RenderMarkdown(summary)
	confirmed := markdownSection(markdown, "## Confirmed Exposures", "## Validate Next")
	validateNext := markdownSection(markdown, "## Validate Next", "## Report Context Appendix")

	for _, want := range []string{
		"Credential to deploy or release",
		"repository configuration observed in this scan (freshness: current scan)",
		"approval: not observed in this scan or imported evidence (source: none; freshness: unknown)",
		"Related paths collapsed: 1",
		"Workflow: .github/workflows/release.yml",
		"Credential reference: service token",
		"Target: production impacting",
		"Likely owner: release-team",
		"Closure evidence: Attach deployment approval evidence",
		"Inherited origin: github reusable workflow from .github/workflows/shared.yml",
		"Evidence receipt: observed=2 paths; bound=2 paths; confirmed=2 paths; displayed=1 outcome group",
	} {
		if !strings.Contains(confirmed, want) {
			t.Fatalf("expected confirmed brief to contain %q, got %q", want, confirmed)
		}
	}
	if strings.Contains(confirmed, "agents/export.go") {
		t.Fatalf("expected inferred candidate to stay out of confirmed exposures, got %q", confirmed)
	}
	for _, want := range []string{
		"Candidate: Credential or workflow to external egress",
		"Relationship: inferred from static source correlation; validate the executable binding before treating this as confirmed",
		"agents/export.go",
		"approval: observed from provider export (freshness: fresh)",
	} {
		if !strings.Contains(validateNext, want) {
			t.Fatalf("expected validate-next brief to contain %q, got %q", want, validateNext)
		}
	}
}

func TestExecutionRelationshipOriginIsRedactedWithPaths(t *testing.T) {
	t.Parallel()

	config := ResolveRedactionConfig(ShareProfileCustomerRedacted, nil)
	got := sanitizeExecutionRelationshipsWithConfig([]model.ExecutionRelationship{{
		Kind: "jenkins_shared_library", Caller: "Jenkinsfile", Callee: "vars/deploy.groovy", Origin: "vars/deploy.groovy", ResolutionState: "resolved_local",
	}}, config)
	if len(got) != 1 || got[0].Origin == "vars/deploy.groovy" || !strings.HasPrefix(got[0].Origin, "loc-") {
		t.Fatalf("expected relationship origin path redaction, got %+v", got)
	}
}

func TestExecutionRelationshipSemanticOriginSurvivesRedaction(t *testing.T) {
	t.Parallel()

	config := ResolveRedactionConfig(ShareProfileCustomerRedacted, nil)
	for _, origin := range []string{"source_declared", "customer_topology", "resolver_receipt"} {
		got := sanitizeExecutionRelationshipsWithConfig([]model.ExecutionRelationship{{
			Kind: "github_composite_action", Caller: ".github/workflows/release.yml", Callee: ".github/actions/release/action.yml", Origin: origin, ResolutionState: "resolved_local",
		}}, config)
		if len(got) != 1 || got[0].Origin != origin {
			t.Fatalf("semantic relationship origin %q must survive redaction, got %+v", origin, got)
		}
	}
}

func TestRenderMarkdownAddsInternalRemediationBriefOnlyToInternalReports(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{
		PathID:                   "confirmed-release",
		Repo:                     "acme/payments",
		Location:                 ".github/workflows/release.yml",
		Owner:                    "@acme/release",
		ActionPathEligible:       true,
		ActionBindingState:       risk.ActionBindingStateBound,
		ActionPathType:           risk.ActionPathTypeCICDWorkflow,
		ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
		CredentialAccess:         true,
		StandingPrivilege:        true,
		TargetClass:              risk.TargetClassProductionImpacting,
		ActionClasses:            []string{"deploy"},
		DelegationReadinessState: risk.DelegationReadinessBlocked,
		RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
		CredentialAuthority:      &credentialAuthorityForBrief,
	}
	internal := RenderMarkdown(Summary{
		Template:       string(TemplateAgentActionBOM),
		ShareProfile:   string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{Items: []AgentActionBOMItem{item}},
	})
	redacted := RenderMarkdown(Summary{
		Template:       string(TemplateAgentActionBOM),
		ShareProfile:   string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{Items: []AgentActionBOMItem{item}},
	})

	internalSection := markdownSection(internal, "## Internal Remediation Brief", "## Report Context Appendix")
	for _, want := range []string{
		"Repository: acme/payments",
		"Workflow: .github/workflows/release.yml",
		"Credential reference: service token",
		"Target: production impacting",
		"Likely owner: @acme/release",
	} {
		if !strings.Contains(internalSection, want) {
			t.Fatalf("expected internal remediation brief to contain %q, got %q", want, internalSection)
		}
	}
	if strings.Contains(redacted, "## Internal Remediation Brief") {
		t.Fatalf("customer-redacted report must not render an internal remediation brief: %q", redacted)
	}
}

func TestRenderMarkdownQualifiesReducedCoverageWithoutSuppressingConfirmedExposure(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileCustomerRedacted),
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{CoverageConfidence: "reduced"},
			Items: []AgentActionBOMItem{{
				PathID:                   "confirmed-reduced",
				Repo:                     "repo-a",
				Location:                 ".github/workflows/release.yml",
				ActionPathEligible:       true,
				ActionBindingState:       risk.ActionBindingStateBound,
				ActionPathType:           risk.ActionPathTypeCICDWorkflow,
				ConfidenceLane:           risk.ConfidenceLaneConfirmedActionPath,
				CredentialAccess:         true,
				StandingPrivilege:        true,
				TargetClass:              risk.TargetClassProductionImpacting,
				ActionClasses:            []string{"deploy"},
				DelegationReadinessState: risk.DelegationReadinessBlocked,
				RecommendedControl:       risk.RecommendedControlBlockStandingCredential,
				CredentialAuthority: &agginventory.CredentialAuthority{
					CredentialKind: "static_secret",
					AccessType:     "standing",
				},
			}},
		},
	})

	for _, want := range []string{
		"Scan quality: reduced coverage.",
		"cannot support an absence-of-exposure or safe-control conclusion",
		"Credential to deploy or release",
		"secret reference",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("expected reduced-coverage report to contain %q, got %q", want, markdown)
		}
	}
	if strings.Contains(markdown, "static_secret") {
		t.Fatalf("expected buyer brief to hide raw credential taxonomy, got %q", markdown)
	}
}

func TestBuyerExposureOutcomeUsesActionSemanticsBeforeTargetClass(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		item AgentActionBOMItem
		want string
	}{
		{
			name: "production impacting egress",
			item: AgentActionBOMItem{
				TargetClass:      risk.TargetClassProductionImpacting,
				CredentialAccess: true,
				ActionClasses:    []string{"egress"},
			},
			want: "Credential or workflow to external egress",
		},
		{
			name: "production impacting data mutation",
			item: AgentActionBOMItem{
				TargetClass:   risk.TargetClassProductionImpacting,
				ActionClasses: []string{"write"},
			},
			want: "Workflow mutation to consequential data or state",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buyerExposureOutcome(tc.item); got != tc.want {
				t.Fatalf("buyerExposureOutcome() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuyerExposureEvidenceFieldPreservesUnmatchedStateAndHidesRawSource(t *testing.T) {
	t.Parallel()

	item := AgentActionBOMItem{EvidenceDecisions: []evidencepolicy.Decision{{
		Field:                  evidencepolicy.FieldApproval,
		SelectedSourceType:     "private-control-system",
		SelectedSource:         "https://controls.internal.example/acme/release-policy",
		SelectedFreshnessState: evidencepolicy.FreshnessStateFresh,
		SelectedStatus:         "unmatched",
	}}}
	got := buyerExposureEvidenceField(item, evidencepolicy.FieldApproval, "approval", risk.EvidenceStateUnknown)

	for _, want := range []string{
		"approval: not observed in this scan or imported evidence",
		"source: imported evidence",
		"freshness: fresh",
		"evidence match: unmatched",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected unmatched evidence field to contain %q, got %q", want, got)
		}
	}
	if strings.Contains(got, "controls.internal.example") || strings.Contains(got, "private-control-system") {
		t.Fatalf("buyer evidence field leaked raw source details: %q", got)
	}
}

func TestRenderBuyerExposureBriefDoesNotPromiseAnAppendix(t *testing.T) {
	t.Parallel()

	base := AgentActionBOMItem{
		ActionPathEligible: true,
		ActionBindingState: risk.ActionBindingStateBound,
		ActionPathType:     risk.ActionPathTypeCICDWorkflow,
		ConfidenceLane:     risk.ConfidenceLaneConfirmedActionPath,
	}
	items := []AgentActionBOMItem{
		base,
		base,
		base,
		base,
	}
	items[0].PathID, items[0].ActionClasses = "deploy", []string{"deploy"}
	items[1].PathID, items[1].ActionClasses = "egress", []string{"egress"}
	items[2].PathID, items[2].ActionClasses = "write", []string{"write"}
	items[3].PathID, items[3].CredentialAccess = "credential", true

	var builder strings.Builder
	renderBuyerExposureBrief(&builder, Summary{AgentActionBOM: &AgentActionBOM{Items: items}})
	got := builder.String()
	if !strings.Contains(got, "1 additional confirmed outcome group(s) are retained in the report JSON.") {
		t.Fatalf("expected suppressed group to be retained in report JSON, got %q", got)
	}
	if strings.Contains(got, "remain in the appendix") {
		t.Fatalf("buyer exposure brief must not promise an appendix it does not render: %q", got)
	}
}

var credentialAuthorityForBrief = agginventory.CredentialAuthority{
	CredentialKind: "service_token",
	AccessType:     "standing",
}

func markdownSection(markdown string, start string, end string) string {
	startIndex := strings.Index(markdown, start)
	if startIndex < 0 {
		return ""
	}
	section := markdown[startIndex:]
	if endIndex := strings.Index(section, end); endIndex >= 0 {
		return section[:endIndex]
	}
	return section
}
