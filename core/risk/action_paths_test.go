package risk

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestBuildActionPathsCorrelatesExecutionIdentity(t *testing.T) {
	t.Parallel()

	paths, controlFirst := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:ci:acme",
				Framework:              "ci_agent",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               ".github/workflows/release.yml",
				RiskScore:              8.5,
				WriteCapable:           true,
				PullRequestWrite:       true,
				ApprovalClassification: "approved",
			},
		},
		NonHumanIdentities: []agginventory.NonHumanIdentity{
			{
				IdentityID:   "one",
				IdentityType: "github_app",
				Subject:      "github_app",
				Source:       "workflow_static_signal",
				Org:          "acme",
				Repo:         "acme/release",
				Location:     ".github/workflows/release.yml",
			},
		},
	})

	if len(paths) != 1 || controlFirst == nil {
		t.Fatalf("expected one action path, got %+v / %+v", paths, controlFirst)
	}
	if paths[0].ExecutionIdentityStatus != "known" || paths[0].ExecutionIdentityType != "github_app" {
		t.Fatalf("expected github_app execution identity, got %+v", paths[0])
	}
}

func TestBuildActionPathsLeavesConflictingExecutionIdentityAmbiguous(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:ci:acme",
				Framework:              "ci_agent",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               ".github/workflows/release.yml",
				RiskScore:              8.5,
				WriteCapable:           true,
				PullRequestWrite:       true,
				ApprovalClassification: "approved",
			},
		},
		NonHumanIdentities: []agginventory.NonHumanIdentity{
			{IdentityID: "one", IdentityType: "github_app", Subject: "github_app", Source: "workflow_static_signal", Org: "acme", Repo: "acme/release", Location: ".github/workflows/release.yml"},
			{IdentityID: "two", IdentityType: "bot_user", Subject: "dependabot[bot]", Source: "workflow_static_signal", Org: "acme", Repo: "acme/release", Location: ".github/workflows/release.yml"},
		},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].ExecutionIdentityStatus != "ambiguous" || paths[0].ExecutionIdentity != "" {
		t.Fatalf("expected ambiguous execution identity, got %+v", paths[0])
	}
}
