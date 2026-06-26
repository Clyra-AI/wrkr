package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildDeclarationSnippetFromBOMUsesResolutionKey(t *testing.T) {
	t.Parallel()

	snippet, err := BuildDeclarationSnippetFromBOM(AgentActionBOMItem{
		PathID:              "apc-release",
		ResolutionKey:       "rk-release",
		Repo:                "acme/payments",
		Location:            ".github/workflows/release.yml",
		ReviewScope:         "production",
		ReviewOwner:         "@acme/platform",
		ReviewSource:        "customer_review",
		ControlEvidenceRefs: []string{"evidence://review/branch-protection"},
		ClosureActions: []risk.ClosureAction{{
			ActionType:             risk.ClosureActionAcceptRiskWithExpiry,
			Title:                  "Accept risk with expiry",
			DeclarationKind:        risk.ClosureActionDeclarationKindReviewDisposition,
			ReviewDispositionState: risk.ReviewLifecycleStateAcceptedRisk,
		}},
	}, ShareProfileInternal, risk.ClosureActionAcceptRiskWithExpiry, DeclarationExportModeRepoLocal, time.Date(2026, 6, 25, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build declaration snippet: %v", err)
	}
	if snippet.CorrelationKind != "resolution_key" {
		t.Fatalf("expected resolution_key correlation, got %+v", snippet)
	}
	if !snippet.DirectlyApplicable {
		t.Fatalf("expected internal snippet to be directly applicable, got %+v", snippet)
	}
	if !strings.Contains(snippet.Content, "resolution_key: rk-release") {
		t.Fatalf("expected snippet to include resolution key, got %q", snippet.Content)
	}
	if !strings.Contains(snippet.Content, "state: accepted_risk") {
		t.Fatalf("expected snippet to include accepted_risk state, got %q", snippet.Content)
	}
}

func TestBuildDeclarationSnippetFromRedactedOwnerActionWarns(t *testing.T) {
	t.Parallel()

	snippet, err := BuildDeclarationSnippetFromBOM(AgentActionBOMItem{
		PathID:      "path-abcd1234",
		Repo:        "repo-123456",
		Location:    "path-abcdef12",
		Owner:       "owner-abcdef12",
		TargetClass: risk.TargetClassDeveloperProductivity,
		ClosureActions: []risk.ClosureAction{{
			ActionType:      risk.ClosureActionDeclareRepoOwner,
			Title:           "Declare repo owner",
			DeclarationKind: risk.ClosureActionDeclarationKindOwner,
		}},
	}, ShareProfileCustomerRedacted, risk.ClosureActionDeclareRepoOwner, DeclarationExportModeRepoLocal, time.Date(2026, 6, 25, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build redacted declaration snippet: %v", err)
	}
	if snippet.DirectlyApplicable {
		t.Fatalf("expected shareable owner snippet to require internal artifacts, got %+v", snippet)
	}
	if len(snippet.Warnings) == 0 {
		t.Fatalf("expected warning for redacted owner snippet, got %+v", snippet)
	}
	for _, forbidden := range []string{"acme/payments", ".github/workflows/release.yml"} {
		if strings.Contains(snippet.Content, forbidden) {
			t.Fatalf("expected snippet to avoid leaking %q, got %q", forbidden, snippet.Content)
		}
	}
	if !strings.Contains(snippet.Content, "owner-review-required") {
		t.Fatalf("expected owner placeholder in redacted snippet, got %q", snippet.Content)
	}
}

func TestBuildDeclarationSnippetDoesNotTreatReviewOwnerAsDeclaredOwner(t *testing.T) {
	t.Parallel()

	snippet, err := BuildDeclarationSnippetFromBOM(AgentActionBOMItem{
		PathID:      "apc-owner-gap",
		Repo:        "acme/payments",
		Location:    ".github/workflows/release.yml",
		ReviewOwner: "@acme/reviewer",
		ClosureActions: []risk.ClosureAction{{
			ActionType:      risk.ClosureActionDeclareRepoOwner,
			Title:           "Declare repo owner",
			DeclarationKind: risk.ClosureActionDeclarationKindOwner,
		}},
	}, ShareProfileInternal, risk.ClosureActionDeclareRepoOwner, DeclarationExportModeRepoLocal, time.Date(2026, 6, 25, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build owner declaration snippet: %v", err)
	}
	if !strings.Contains(snippet.Content, "owner: owner-review-required") {
		t.Fatalf("expected missing owner placeholder, got %q", snippet.Content)
	}
	if strings.Contains(snippet.Content, "owner: '@acme/reviewer'") || strings.Contains(snippet.Content, "owner: \"@acme/reviewer\"") {
		t.Fatalf("expected review owner not to be copied into the owner declaration, got %q", snippet.Content)
	}
}
