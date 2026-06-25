package risk

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestAcceptedRiskFutureExpiryNotTopControlFirst(t *testing.T) {
	t.Parallel()

	paths := ProjectReviewLifecycleTransitions([]ActionPath{
		{
			PathID:               "apc-accepted-risk",
			Org:                  "acme",
			Repo:                 "acme/release",
			ToolType:             "compiled_action",
			Location:             ".github/workflows/release.yml",
			WriteCapable:         true,
			ProductionWrite:      true,
			ApprovalGap:          true,
			ActionClasses:        []string{"deploy"},
			TargetClass:          TargetClassProductionImpacting,
			ReviewLifecycleState: ReviewLifecycleStateAcceptedRisk,
			ReviewValidUntil:     "2026-07-01T12:00:00Z",
		},
		{
			PathID:               "apc-open",
			Org:                  "acme",
			Repo:                 "acme/release",
			ToolType:             "compiled_action",
			Location:             ".github/workflows/hotfix.yml",
			WriteCapable:         true,
			ProductionWrite:      true,
			ApprovalGap:          true,
			ActionClasses:        []string{"deploy"},
			TargetClass:          TargetClassProductionImpacting,
			ReviewLifecycleState: ReviewLifecycleStateOpen,
		},
	}, nil)

	if len(paths) != 2 {
		t.Fatalf("expected two projected paths, got %+v", paths)
	}
	if paths[0].PathID != "apc-open" {
		t.Fatalf("expected unresolved path to lead after lifecycle projection, got %+v", paths)
	}
	resolved := findReviewLifecyclePath(t, paths, "apc-accepted-risk")
	if resolved.ResolvedVisibility != ReviewResolvedVisibilityAppendix {
		t.Fatalf("expected accepted-risk path to move to appendix visibility, got %+v", resolved)
	}
	if resolved.ControlPriority != ControlPriorityInventoryHygiene {
		t.Fatalf("expected accepted-risk path to downgrade out of control-first ordering, got %+v", resolved)
	}
}

func TestExpiredAcceptedRiskReopens(t *testing.T) {
	t.Parallel()

	current := ProjectReviewLifecycleTransitions([]ActionPath{{
		PathID:               "apc-release",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		ProductionWrite:      true,
		ApprovalGap:          true,
		ActionClasses:        []string{"deploy"},
		TargetClass:          TargetClassProductionImpacting,
		ResolutionKey:        "rk-release",
		ReviewLifecycleState: ReviewLifecycleStateExpired,
		ReviewLifecycleReasons: []string{
			"review_declaration:expired",
		},
		ReviewValidUntil: "2026-06-20T12:00:00Z",
	}}, []ActionPath{{
		PathID:               "apc-release-old",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		ProductionWrite:      true,
		ApprovalGap:          true,
		ActionClasses:        []string{"deploy"},
		TargetClass:          TargetClassProductionImpacting,
		ResolutionKey:        "rk-release",
		ReviewLifecycleState: ReviewLifecycleStateAcceptedRisk,
		ReviewValidUntil:     "2026-06-30T12:00:00Z",
	}})

	if len(current) != 1 {
		t.Fatalf("expected one projected path, got %+v", current)
	}
	path := current[0]
	if path.ReviewLifecycleState != ReviewLifecycleStateReopenedByDrift {
		t.Fatalf("expected expired accepted risk to reopen, got %+v", path)
	}
	if path.PreviousReviewLifecycleState != ReviewLifecycleStateAcceptedRisk {
		t.Fatalf("expected previous lifecycle state to carry through, got %+v", path)
	}
	if path.ReopenState != ReviewReopenStateReopened {
		t.Fatalf("expected reopen state to be marked, got %+v", path)
	}
	if !containsReviewLifecycleReason(path.ReopenReasons, "declaration_expired") {
		t.Fatalf("expected declaration_expired reopen reason, got %+v", path)
	}
	if path.ResolvedVisibility != ReviewResolvedVisibilityPrimary {
		t.Fatalf("expected reopened path to return to primary visibility, got %+v", path)
	}
}

func TestNonProdDeclarationContradictedByProductionSecretReopens(t *testing.T) {
	t.Parallel()

	current := ProjectReviewLifecycleTransitions([]ActionPath{{
		PathID:           "apc-release",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		ProductionWrite:  true,
		CredentialAccess: true,
		ApprovalGap:      true,
		ActionClasses:    []string{"deploy"},
		TargetClass:      TargetClassProductionImpacting,
		ResolutionKey:    "rk-release",
		ReviewScope:      "non_production",
		ReviewLifecycleReasons: []string{
			"review_declaration:scope_contradiction",
		},
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			CredentialKind:         agginventory.CredentialKindGitHubPAT,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
	}}, []ActionPath{{
		PathID:               "apc-release-old",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		ApprovalGap:          true,
		ActionClasses:        []string{"deploy"},
		TargetClass:          TargetClassTestDemoSandbox,
		ResolutionKey:        "rk-release",
		ReviewScope:          "non_production",
		ReviewLifecycleState: ReviewLifecycleStateDeclaredControlled,
	}})

	if len(current) != 1 {
		t.Fatalf("expected one projected path, got %+v", current)
	}
	path := current[0]
	if path.ReviewLifecycleState != ReviewLifecycleStateReopenedByDrift {
		t.Fatalf("expected contradicted declaration to reopen, got %+v", path)
	}
	if !containsReviewLifecycleReason(path.ReopenReasons, "scope_contradicted_by_production_evidence") {
		t.Fatalf("expected production-scope contradiction reopen reason, got %+v", path)
	}
}

func TestReviewAuditContextCarriesDeclarationEvidenceRefs(t *testing.T) {
	t.Parallel()

	current := ProjectReviewLifecycleTransitions([]ActionPath{{
		PathID:               "apc-declared",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		ResolutionKey:        "rk-declared",
		ReviewLifecycleState: ReviewLifecycleStateAcceptedRisk,
		ReviewSource:         "governance-ticket",
		ReviewOwner:          "release-cab",
		ReviewRationale:      "Accepted residual risk after review.",
		ReviewObservedAt:     "2026-06-25T10:00:00Z",
		ReviewScope:          "repo",
		ReviewEvidenceRefs:   []string{"evidence://governance/release-risk-123"},
	}}, nil)

	if len(current) != 1 {
		t.Fatalf("expected one projected path, got %+v", current)
	}
	if current[0].ReviewAuditContext == nil || !containsReviewLifecycleReason(current[0].ReviewAuditContext.EvidenceRefs, "evidence://governance/release-risk-123") {
		t.Fatalf("expected review audit context to carry declaration evidence refs, got %+v", current[0].ReviewAuditContext)
	}
}

func findReviewLifecyclePath(t *testing.T, paths []ActionPath, pathID string) ActionPath {
	t.Helper()
	for _, path := range paths {
		if path.PathID == pathID {
			return path
		}
	}
	t.Fatalf("path_id %q not found in %+v", pathID, paths)
	return ActionPath{}
}

func containsReviewLifecycleReason(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
