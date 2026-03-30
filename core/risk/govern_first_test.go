package risk

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestBuildActionPathsRaisesWeakOwnershipAndClassifiesBusinessStateSurface(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                  "wrkr:one:acme",
				Framework:                "ci_agent",
				Org:                      "acme",
				Repos:                    []string{"acme/release"},
				Location:                 ".github/workflows/release.yml",
				RiskScore:                8.0,
				WriteCapable:             true,
				DeployWrite:              true,
				DeliveryChainStatus:      "deploy_only",
				ApprovalClassification:   "approved",
				OwnerSource:              "multi_repo_conflict",
				OwnershipStatus:          "unresolved",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityApproved,
			},
			{
				AgentID:                  "wrkr:two:acme",
				Framework:                "ci_agent",
				Org:                      "acme",
				Repos:                    []string{"acme/review"},
				Location:                 ".github/workflows/review.yml",
				RiskScore:                8.0,
				WriteCapable:             true,
				PullRequestWrite:         true,
				DeliveryChainStatus:      "pr_only",
				ApprovalClassification:   "approved",
				OwnerSource:              "codeowners",
				OwnershipStatus:          "explicit",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityApproved,
			},
		},
	})

	if len(paths) != 2 {
		t.Fatalf("expected two paths, got %+v", paths)
	}
	if paths[0].OwnershipStatus != "unresolved" {
		t.Fatalf("expected weak ownership path to sort first, got %+v", paths)
	}
	if paths[0].BusinessStateSurface != "deploy" {
		t.Fatalf("expected deploy business_state_surface, got %+v", paths[0])
	}
	if paths[1].BusinessStateSurface != "code" {
		t.Fatalf("expected code business_state_surface, got %+v", paths[1])
	}
}

func TestBuildIdentityExposureSummaryAndTargets(t *testing.T) {
	t.Parallel()

	paths := DecorateActionPaths([]ActionPath{
		{
			PathID:                   "apc-1",
			Repo:                     "acme/release",
			WriteCapable:             true,
			DeployWrite:              true,
			OwnershipStatus:          "unresolved",
			ExecutionIdentity:        "release-app",
			ExecutionIdentityType:    "github_app",
			ExecutionIdentitySource:  "workflow_static_signal",
			ExecutionIdentityStatus:  "known",
			BusinessStateSurface:     "deploy",
			SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
		},
		{
			PathID:                  "apc-2",
			Repo:                    "acme/ops",
			WriteCapable:            true,
			OwnershipStatus:         "explicit",
			ExecutionIdentity:       "release-app",
			ExecutionIdentityType:   "github_app",
			ExecutionIdentitySource: "workflow_static_signal",
			ExecutionIdentityStatus: "known",
			BusinessStateSurface:    "admin_api",
		},
		{
			PathID:                  "apc-3",
			Repo:                    "acme/lab",
			WriteCapable:            true,
			OwnershipStatus:         "explicit",
			ExecutionIdentity:       "ops-bot",
			ExecutionIdentityType:   "bot_user",
			ExecutionIdentitySource: "workflow_static_signal",
			ExecutionIdentityStatus: "known",
			BusinessStateSurface:    "code",
		},
	})

	summary := BuildIdentityExposureSummary(paths, &agginventory.Inventory{
		NonHumanIdentities: []agginventory.NonHumanIdentity{
			{Subject: "release-app", IdentityType: "github_app", Source: "workflow_static_signal"},
			{Subject: "ops-bot", IdentityType: "bot_user", Source: "workflow_static_signal"},
			{Subject: "orphan-bot", IdentityType: "bot_user", Source: "workflow_static_signal"},
		},
	})
	if summary == nil {
		t.Fatal("expected identity exposure summary")
	}
	if summary.TotalNonHumanIdentitiesObserved != 3 {
		t.Fatalf("expected total identities=3, got %+v", summary)
	}
	if summary.IdentitiesBackingWriteCapablePaths != 2 {
		t.Fatalf("expected write-backed identities=2, got %+v", summary)
	}
	if summary.IdentitiesBackingDeployCapablePaths != 1 {
		t.Fatalf("expected deploy-backed identities=1, got %+v", summary)
	}
	if summary.IdentitiesWithUnresolvedOwnership != 1 {
		t.Fatalf("expected unresolved-owner identities=1, got %+v", summary)
	}
	if summary.IdentitiesWithUnknownExecutionLinked != 1 {
		t.Fatalf("expected unknown execution correlation identities=1, got %+v", summary)
	}

	review, revoke := BuildIdentityActionTargets(paths)
	if review == nil || revoke == nil {
		t.Fatalf("expected review and revoke identity targets, got review=%+v revoke=%+v", review, revoke)
	}
	if review.ExecutionIdentity != "release-app" {
		t.Fatalf("expected release-app to rank first for review, got %+v", review)
	}
	if revoke.ExecutionIdentity != "release-app" {
		t.Fatalf("expected release-app to rank first for revocation, got %+v", revoke)
	}
	if !review.SharedExecutionIdentity || !revoke.StandingPrivilege {
		t.Fatalf("expected shared/standing privilege heuristics on top identity, review=%+v revoke=%+v", review, revoke)
	}
}

func TestBuildExposureGroupsCollapsesStableClusters(t *testing.T) {
	t.Parallel()

	paths := DecorateActionPaths([]ActionPath{
		{
			PathID:                  "apc-1",
			Org:                     "acme",
			Repo:                    "acme/release",
			ToolType:                "compiled_action",
			Location:                ".github/workflows/release.yml",
			DeliveryChainStatus:     "pr_merge_deploy",
			BusinessStateSurface:    "deploy",
			RecommendedAction:       "proof",
			ExecutionIdentity:       "release-app",
			ExecutionIdentityType:   "github_app",
			ExecutionIdentitySource: "workflow_static_signal",
			ExecutionIdentityStatus: "known",
			WriteCapable:            true,
		},
		{
			PathID:                  "apc-2",
			Org:                     "acme",
			Repo:                    "acme/release",
			ToolType:                "compiled_action",
			Location:                ".github/workflows/release-extra.yml",
			DeliveryChainStatus:     "pr_merge_deploy",
			BusinessStateSurface:    "deploy",
			RecommendedAction:       "proof",
			ExecutionIdentity:       "release-app",
			ExecutionIdentityType:   "github_app",
			ExecutionIdentitySource: "workflow_static_signal",
			ExecutionIdentityStatus: "known",
			WriteCapable:            true,
		},
	})

	first := BuildExposureGroups(paths)
	second := BuildExposureGroups(paths)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one grouped exposure, got first=%+v second=%+v", first, second)
	}
	if first[0].GroupID != second[0].GroupID {
		t.Fatalf("expected deterministic group ids, first=%+v second=%+v", first, second)
	}
	if first[0].PathCount != 2 {
		t.Fatalf("expected grouped path_count=2, got %+v", first[0])
	}
	if len(first[0].PathIDs) != 2 {
		t.Fatalf("expected both path ids to remain visible in group, got %+v", first[0])
	}
}
