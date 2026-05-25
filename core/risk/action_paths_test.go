package risk

import (
	"maps"
	"regexp"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
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

func TestBuildActionPathsCarriesWritePathClassesAndControls(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                  "wrkr:ci:acme",
				Framework:                "ci_agent",
				Org:                      "acme",
				Repos:                    []string{"acme/release"},
				Location:                 ".github/workflows/release.yml",
				RiskScore:                8.5,
				WriteCapable:             true,
				PullRequestWrite:         true,
				CredentialAccess:         true,
				WritePathClasses:         []string{agginventory.WritePathPullRequestWrite, agginventory.WritePathSecretBearingExec},
				ApprovalClassification:   "unapproved",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
				GovernanceControls: []agginventory.GovernanceControlMapping{{
					Control: agginventory.GovernanceControlApproval,
					Status:  agginventory.ControlStatusGap,
					Gaps:    []string{"approval_evidence_missing"},
				}},
			},
		},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if !containsPathClass(paths[0].WritePathClasses, agginventory.WritePathPullRequestWrite) || !containsPathClass(paths[0].WritePathClasses, agginventory.WritePathSecretBearingExec) {
		t.Fatalf("expected write path classes to carry through, got %+v", paths[0])
	}
	if len(paths[0].GovernanceControls) != 1 || paths[0].GovernanceControls[0].Control != agginventory.GovernanceControlApproval {
		t.Fatalf("expected governance controls to carry through, got %+v", paths[0])
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

func TestBuildActionPathsFallsBackToRepoScopedIdentityCorrelation(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:ci:acme",
				Framework:              "ci_agent",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               ".github/workflows/deploy-job.yml",
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
				Subject:      "release-app",
				Source:       "workflow_static_signal",
				Org:          "acme",
				Repo:         "acme/release",
				Location:     ".github/workflows/release.yml",
			},
		},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].ExecutionIdentityStatus != "known" || paths[0].ExecutionIdentity != "release-app" {
		t.Fatalf("expected repo-scoped identity fallback, got %+v", paths[0])
	}
}

func TestBuildActionPathsDeduplicatesRepeatedEntriesAndStabilizesPathID(t *testing.T) {
	t.Parallel()

	inventory := &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                  "wrkr:compiled_action:acme",
				AgentInstanceID:          "workflow-release",
				ToolID:                   "compiled_action:.github/workflows/release.yml#release",
				Framework:                "compiled_action",
				Symbol:                   "release",
				Org:                      "acme",
				Repos:                    []string{"acme/release"},
				Location:                 ".github/workflows/release.yml",
				LocationRange:            &model.LocationRange{StartLine: 1, EndLine: 18},
				RiskScore:                8.9,
				WriteCapable:             true,
				CredentialAccess:         true,
				PullRequestWrite:         true,
				MergeExecute:             true,
				DeployWrite:              true,
				DeliveryChainStatus:      "pr_merge_deploy",
				ProductionTargetStatus:   agginventory.ProductionTargetsStatusConfigured,
				ProductionWrite:          true,
				MatchedProductionTargets: []string{"cluster/prod"},
				ApprovalClassification:   "approved",
				ApprovalGapReasons:       []string{"deployment_gate_missing"},
			},
			{
				AgentID:                  "wrkr:compiled_action:acme",
				AgentInstanceID:          "workflow-release",
				ToolID:                   "compiled_action:.github/workflows/release.yml#release",
				Framework:                "compiled_action",
				Symbol:                   "release",
				Org:                      "acme",
				Repos:                    []string{"acme/release"},
				Location:                 ".github/workflows/release.yml",
				LocationRange:            &model.LocationRange{StartLine: 1, EndLine: 18},
				RiskScore:                8.4,
				WriteCapable:             true,
				CredentialAccess:         false,
				PullRequestWrite:         true,
				MergeExecute:             true,
				DeployWrite:              true,
				DeliveryChainStatus:      "pr_merge_deploy",
				ProductionTargetStatus:   agginventory.ProductionTargetsStatusConfigured,
				ProductionWrite:          true,
				MatchedProductionTargets: []string{"cluster/prod"},
				ApprovalClassification:   "approved",
				ApprovalGapReasons:       []string{"approval_source_missing"},
			},
		},
	}
	attackPaths := []riskattack.ScoredPath{{Org: "acme", Repo: "acme/release", PathScore: 9.2}}

	firstPaths, firstChoice := BuildActionPaths(attackPaths, inventory)
	secondPaths, secondChoice := BuildActionPaths(attackPaths, inventory)

	if len(firstPaths) != 1 {
		t.Fatalf("expected duplicate entries to collapse into one action path, got %+v", firstPaths)
	}
	if firstChoice == nil {
		t.Fatal("expected control-first choice after dedupe")
		return
	}
	selectedFirstChoice := *firstChoice
	if selectedFirstChoice.Path.PathID != firstPaths[0].PathID {
		t.Fatalf("expected control-first choice to reference deduped path row, choice=%+v paths=%+v", selectedFirstChoice.Path, firstPaths)
	}
	if firstPaths[0].PathID != secondPaths[0].PathID {
		t.Fatalf("expected path_id to remain stable across repeat runs, first=%s second=%s", firstPaths[0].PathID, secondPaths[0].PathID)
	}
	if !regexp.MustCompile("^" + actionPathIDPrefix + "[0-9a-f]{12}$").MatchString(firstPaths[0].PathID) {
		t.Fatalf("expected opaque apc-<hex> path_id, got %q", firstPaths[0].PathID)
	}
	if !maps.Equal(sliceToSet(firstPaths[0].ApprovalGapReasons), sliceToSet([]string{"approval_source_missing", "deployment_gate_missing"})) {
		t.Fatalf("expected merged approval gap reasons, got %+v", firstPaths[0].ApprovalGapReasons)
	}
	if secondChoice == nil {
		t.Fatalf("expected repeat run control-first choice to reference deduped path, choice=%+v paths=%+v", secondChoice, secondPaths)
		return
	}
	selectedSecondChoice := *secondChoice
	if selectedSecondChoice.Path.PathID != secondPaths[0].PathID {
		t.Fatalf("expected repeat run control-first choice to reference deduped path, choice=%+v paths=%+v", selectedSecondChoice, secondPaths)
	}
}

func TestGovernFirstRanksSourceMCPAboveDependencyInventory(t *testing.T) {
	t.Parallel()

	paths, controlFirst := BuildActionPaths([]riskattack.ScoredPath{
		{
			PathID:         "ap-source",
			Org:            "acme",
			Repo:           "acme/app",
			PathScore:      8.9,
			SourceFindings: []string{"mcp_server||mcp|.mcp.json|acme/app|acme"},
		},
	}, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:dependency:acme",
				Framework:              "dependency",
				Org:                    "acme",
				Repos:                  []string{"acme/app"},
				Location:               "package.json",
				RiskScore:              4.1,
				WriteCapable:           true,
				ApprovalClassification: "approved",
			},
			{
				AgentID:                "wrkr:mcp:acme",
				Framework:              "mcp",
				Org:                    "acme",
				Repos:                  []string{"acme/app"},
				Location:               ".mcp.json",
				RiskScore:              6.7,
				WriteCapable:           true,
				CredentialAccess:       true,
				ApprovalClassification: "approved",
			},
		},
	})

	if len(paths) != 2 || controlFirst == nil {
		t.Fatalf("expected two action paths and a control-first choice, got %+v / %+v", paths, controlFirst)
	}
	if paths[0].Location != ".mcp.json" {
		t.Fatalf("expected source-level MCP path to outrank dependency inventory, got %+v", paths)
	}
	if paths[0].ControlPriority != ControlPriorityControlFirst {
		t.Fatalf("expected source-level MCP path to land in control_first, got %+v", paths[0])
	}
	if paths[1].ControlPriority != ControlPriorityInventoryHygiene || paths[1].RecommendedAction != "inventory" {
		t.Fatalf("expected dependency path to remain inventory hygiene, got %+v", paths[1])
	}
	if !containsPathClass(paths[0].AttackPathRefs, "ap-source") {
		t.Fatalf("expected attack path refs to link onto the source path, got %+v", paths[0].AttackPathRefs)
	}
}

func TestRecommendedActionFollowsStrongestGovernableSignal(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths([]riskattack.ScoredPath{
		{
			PathID:         "ap-high",
			Org:            "acme",
			Repo:           "acme/release",
			PathScore:      9.4,
			SourceFindings: []string{"compiled_action||ci_agent|.github/workflows/release.yml|acme/release|acme"},
		},
	}, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
			AgentID:                "wrkr:release:acme",
			Framework:              "compiled_action",
			Org:                    "acme",
			Repos:                  []string{"acme/release"},
			Location:               ".github/workflows/release.yml",
			RiskScore:              5.4,
			WriteCapable:           true,
			DeployWrite:            true,
			CredentialAccess:       true,
			ApprovalClassification: "approved",
		}},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].RecommendedAction != "control" || paths[0].ControlPriority != ControlPriorityControlFirst {
		t.Fatalf("expected strongest governable signal to drive control-first remediation, got %+v", paths[0])
	}
	if paths[0].RiskTier != RiskTierHigh && paths[0].RiskTier != RiskTierCritical {
		t.Fatalf("expected high or critical risk tier, got %+v", paths[0])
	}
}

func TestBuildActionPathsUsesHiddenIdentityDimensionsForUniquePathIDs(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:compiled_action:acme",
				AgentInstanceID:        "workflow-release",
				ToolID:                 "compiled_action:.github/workflows/release.yml#release",
				Framework:              "compiled_action",
				Symbol:                 "release",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               ".github/workflows/release.yml",
				LocationRange:          &model.LocationRange{StartLine: 1, EndLine: 18},
				RiskScore:              8.9,
				WriteCapable:           true,
				PullRequestWrite:       true,
				MergeExecute:           true,
				DeployWrite:            true,
				DeliveryChainStatus:    "pr_merge_deploy",
				ProductionTargetStatus: agginventory.ProductionTargetsStatusConfigured,
				ProductionWrite:        true,
				ApprovalClassification: "approved",
			},
			{
				AgentID:                "wrkr:compiled_action:acme",
				AgentInstanceID:        "workflow-preview",
				ToolID:                 "compiled_action:.github/workflows/release.yml#preview",
				Framework:              "compiled_action",
				Symbol:                 "preview",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               ".github/workflows/release.yml",
				LocationRange:          &model.LocationRange{StartLine: 20, EndLine: 36},
				RiskScore:              7.1,
				WriteCapable:           true,
				PullRequestWrite:       true,
				MergeExecute:           true,
				DeployWrite:            true,
				DeliveryChainStatus:    "pr_merge_deploy",
				ProductionTargetStatus: agginventory.ProductionTargetsStatusConfigured,
				ProductionWrite:        true,
				ApprovalClassification: "approved",
			},
		},
	})

	if len(paths) != 2 {
		t.Fatalf("expected distinct workflow instances to stay separate, got %+v", paths)
	}
	if paths[0].PathID == paths[1].PathID {
		t.Fatalf("expected hidden identity dimensions to keep path_ids unique, got %+v", paths)
	}
}

func TestBuildActionPathsExercisesAllRecommendedActionClasses(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                  "wrkr:prod:acme",
				Framework:                "compiled_action",
				Org:                      "acme",
				Repos:                    []string{"acme/prod"},
				Location:                 ".github/workflows/release.yml",
				RiskScore:                9.2,
				WriteCapable:             true,
				PullRequestWrite:         true,
				MergeExecute:             true,
				DeployWrite:              true,
				ProductionWrite:          true,
				DeliveryChainStatus:      "pr_merge_deploy",
				ProductionTargetStatus:   agginventory.ProductionTargetsStatusConfigured,
				ApprovalClassification:   "approved",
				OwnershipStatus:          "explicit",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityApproved,
			},
			{
				AgentID:                  "wrkr:approval:acme",
				Framework:                "compiled_action",
				Org:                      "acme",
				Repos:                    []string{"acme/release"},
				Location:                 ".github/workflows/review.yml",
				RiskScore:                8.4,
				WriteCapable:             true,
				PullRequestWrite:         true,
				DeliveryChainStatus:      "pr_only",
				ApprovalClassification:   "unknown",
				ApprovalGapReasons:       []string{"approval_source_missing"},
				OwnershipStatus:          "explicit",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityApproved,
			},
			{
				AgentID:                  "wrkr:proof:acme",
				Framework:                "compiled_action",
				Org:                      "acme",
				Repos:                    []string{"acme/docs"},
				Location:                 ".github/workflows/docs.yml",
				RiskScore:                7.3,
				WriteCapable:             true,
				CredentialAccess:         true,
				PullRequestWrite:         true,
				DeliveryChainStatus:      "pr_only",
				ApprovalClassification:   "approved",
				OwnershipStatus:          "unresolved",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
			},
			{
				AgentID:                  "wrkr:inventory:acme",
				Framework:                "langchain",
				Org:                      "acme",
				Repos:                    []string{"acme/lab"},
				Location:                 "agents/lab.py",
				RiskScore:                5.1,
				WriteCapable:             true,
				ApprovalClassification:   "approved",
				OwnershipStatus:          "explicit",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityApproved,
			},
		},
		NonHumanIdentities: []agginventory.NonHumanIdentity{
			{IdentityID: "prod", IdentityType: "github_app", Subject: "prod-app", Source: "workflow_static_signal", Org: "acme", Repo: "acme/prod", Location: ".github/workflows/release.yml"},
			{IdentityID: "approval", IdentityType: "github_app", Subject: "approval-app", Source: "workflow_static_signal", Org: "acme", Repo: "acme/release", Location: ".github/workflows/review.yml"},
			{IdentityID: "inventory", IdentityType: "service_account", Subject: "inventory-sa", Source: "workflow_static_signal", Org: "acme", Repo: "acme/lab", Location: "agents/lab.py"},
		},
	})

	if len(paths) != 4 {
		t.Fatalf("expected four action paths, got %+v", paths)
	}
	got := sliceToSet([]string{
		paths[0].RecommendedAction,
		paths[1].RecommendedAction,
		paths[2].RecommendedAction,
		paths[3].RecommendedAction,
	})
	for _, want := range []string{"control", "approval", "proof", "inventory"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected recommended_action=%s to be reachable, got %+v", want, paths)
		}
	}
}

func TestBuildActionPathsCarriesWorkflowTriggerClass(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:scheduled:acme",
				Framework:              "compiled_action",
				Org:                    "acme",
				Repos:                  []string{"acme/nightly"},
				Location:               ".github/workflows/nightly.yml",
				RiskScore:              7.8,
				WriteCapable:           true,
				PullRequestWrite:       true,
				ApprovalClassification: "approved",
				WorkflowTriggerClass:   "scheduled",
			},
		},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].WorkflowTriggerClass != "scheduled" {
		t.Fatalf("expected workflow_trigger_class=scheduled, got %+v", paths[0])
	}
}

func TestConfidenceLaneConfirmedWorkflowCredentialPermission(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
			AgentID:                "wrkr:release:acme",
			Framework:              "compiled_action",
			ToolType:               "compiled_action",
			Org:                    "acme",
			Repos:                  []string{"acme/release"},
			Location:               ".github/workflows/release.yml",
			RiskScore:              8.7,
			WriteCapable:           true,
			CredentialAccess:       true,
			PullRequestWrite:       true,
			ApprovalClassification: "approved",
			CredentialProvenance: &agginventory.CredentialProvenance{
				Type:           agginventory.CredentialProvenanceStaticSecret,
				Scope:          agginventory.CredentialScopeWorkflow,
				Confidence:     "high",
				RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
			},
		}},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].ConfidenceLane != ConfidenceLaneConfirmedActionPath {
		t.Fatalf("expected confirmed action path lane, got %+v", paths[0])
	}
	for _, want := range []string{"execution_linkage:direct", "permission_or_target_signal:present", "authority_linkage:present"} {
		if !containsPathClass(paths[0].ConfidenceLaneReasons, want) {
			t.Fatalf("expected confidence lane reason %q, got %+v", want, paths[0].ConfidenceLaneReasons)
		}
	}
}

func TestSemanticInstructionFindingIsReviewCandidate(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
			AgentID:                "wrkr:prompt:acme",
			Framework:              "prompt_channel",
			ToolType:               "prompt_channel",
			Org:                    "acme",
			Repos:                  []string{"acme/platform"},
			Location:               "AGENTS.md",
			RiskScore:              4.6,
			ApprovalClassification: "unknown",
			ApprovalGapReasons:     []string{"approval_source_missing"},
		}},
	})

	if len(paths) != 1 {
		t.Fatalf("expected one semantic review candidate path, got %+v", paths)
	}
	if paths[0].ConfidenceLane != ConfidenceLaneSemanticReviewCandidate {
		t.Fatalf("expected semantic review candidate lane, got %+v", paths[0])
	}
	if paths[0].ControlPriority != ControlPriorityReviewQueue {
		t.Fatalf("expected semantic path to stay in review queue, got %+v", paths[0])
	}
	if paths[0].ControlState != ControlStateApprovalNeeded {
		t.Fatalf("expected semantic path to use review wording via approval/evidence state, got %+v", paths[0])
	}
}

func TestConfidenceLaneAffectsGovernFirstRanking(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:workflow:acme",
				Framework:              "compiled_action",
				ToolType:               "compiled_action",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               ".github/workflows/release.yml",
				RiskScore:              8.9,
				WriteCapable:           true,
				CredentialAccess:       true,
				PullRequestWrite:       true,
				ApprovalClassification: "approved",
			},
			{
				AgentID:                "wrkr:prompt:acme",
				Framework:              "prompt_channel",
				ToolType:               "prompt_channel",
				Org:                    "acme",
				Repos:                  []string{"acme/release"},
				Location:               "AGENTS.md",
				RiskScore:              8.9,
				ApprovalClassification: "unknown",
				ApprovalGapReasons:     []string{"approval_source_missing"},
			},
		},
	})

	if len(paths) != 2 {
		t.Fatalf("expected two action paths, got %+v", paths)
	}
	if paths[0].ConfidenceLane != ConfidenceLaneConfirmedActionPath || paths[0].Location != ".github/workflows/release.yml" {
		t.Fatalf("expected confirmed workflow path to outrank semantic review candidate, got %+v", paths)
	}
	if paths[1].ConfidenceLane != ConfidenceLaneSemanticReviewCandidate {
		t.Fatalf("expected second path to remain semantic review candidate, got %+v", paths[1])
	}
}

func TestControlResolutionStateVerifiedRequiresEvidenceRef(t *testing.T) {
	t.Parallel()

	withoutRefs := ProjectActionPaths([]ActionPath{{
		PathID:           "apc-proof-without-refs",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		CredentialAccess: true,
		GaitCoverage: &GaitCoverage{
			ProofVerification: GaitCoverageDetail{Status: GaitStatusPresent},
		},
	}})
	if len(withoutRefs) != 1 {
		t.Fatalf("expected one projected path, got %+v", withoutRefs)
	}
	if withoutRefs[0].ProofEvidenceState == EvidenceStateVerified {
		t.Fatalf("expected proof evidence without refs to stay below verified, got %+v", withoutRefs[0])
	}

	withRefs := ProjectActionPaths([]ActionPath{{
		PathID:           "apc-proof-with-refs",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		CredentialAccess: true,
		GaitCoverage: &GaitCoverage{
			ProofVerification: GaitCoverageDetail{
				Status:       GaitStatusPresent,
				EvidenceRefs: []string{"proof_record:rec-123"},
			},
		},
	}})
	if len(withRefs) != 1 {
		t.Fatalf("expected one projected path, got %+v", withRefs)
	}
	if withRefs[0].ProofEvidenceState != EvidenceStateVerified {
		t.Fatalf("expected proof evidence with refs to be verified, got %+v", withRefs[0])
	}
}

func TestEvidenceStateContradictoryOwnerSignals(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:               "apc-owner-contradiction",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		CredentialAccess:     true,
		OperationalOwner:     "@acme/release",
		OwnershipStatus:      "unresolved",
		OwnershipState:       "conflicting_owner",
		OwnershipEvidence:    []string{"codeowners:CODEOWNERS:*"},
		OwnershipConflicts:   []string{"@acme/release", "@acme/security"},
		ApprovalGap:          true,
		ApprovalGapReasons:   []string{"approval_source_missing"},
		PolicyCoverageStatus: PolicyCoverageStatusNone,
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].OwnerEvidenceState != EvidenceStateContradictory {
		t.Fatalf("expected contradictory owner evidence state, got %+v", paths[0])
	}
	if paths[0].ControlResolutionState != ControlResolutionStateContradictoryControl {
		t.Fatalf("expected contradictory control resolution state, got %+v", paths[0])
	}
}

func TestRuntimeEvidenceConflictOverridesEarlierVerifiedDetail(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:           "apc-runtime-contradiction",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		CredentialAccess: true,
		GaitCoverage: &GaitCoverage{
			PolicyDecision: GaitCoverageDetail{
				Status:       GaitStatusPresent,
				EvidenceRefs: []string{"runtime:policy"},
			},
			Approval: GaitCoverageDetail{
				Status:       GaitStatusConflict,
				EvidenceRefs: []string{"runtime:approval"},
			},
		},
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].RuntimeEvidenceState != EvidenceStateContradictory {
		t.Fatalf("expected runtime evidence conflict to win, got %+v", paths[0])
	}
}

func TestRuntimeEvidenceAbsenceStatusNotCollected(t *testing.T) {
	t.Parallel()

	path := ActionPath{
		PathID:   "apc-runtime-not-collected",
		Org:      "acme",
		Repo:     "acme/release",
		ToolType: "compiled_action",
		Location: ".github/workflows/release.yml",
		GaitCoverage: &GaitCoverage{
			PolicyDecision: GaitCoverageDetail{
				Status:  GaitStatusMissing,
				Reasons: []string{"runtime_evidence_not_collected:policy_decision", "runtime_absence_status:not_collected"},
			},
			Approval: GaitCoverageDetail{
				Status:  GaitStatusMissing,
				Reasons: []string{"runtime_evidence_not_collected:approval", "runtime_absence_status:not_collected"},
			},
		},
	}

	if got := RuntimeEvidenceAbsenceStatus(path); got != RuntimeEvidenceAbsenceNotCollected {
		t.Fatalf("expected not_collected runtime absence status, got %q", got)
	}
}

func TestRuntimeEvidenceControlClaimGapOverridesLinkedEvidence(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:   "apc-runtime-claim-gap",
		Org:      "acme",
		Repo:     "acme/release",
		ToolType: "compiled_action",
		Location: ".github/workflows/release.yml",
		GaitCoverage: &GaitCoverage{
			PolicyDecision: GaitCoverageDetail{
				Status:       GaitStatusPresent,
				EvidenceRefs: []string{"runtime:policy"},
			},
			Approval: GaitCoverageDetail{
				Status:  GaitStatusMissing,
				Reasons: []string{"runtime_control_claim_missing:approval", "runtime_absence_status:missing_for_control_claim"},
			},
		},
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].RuntimeEvidenceState != EvidenceStateUnknown {
		t.Fatalf("expected missing control-claim runtime evidence to prevent verified state, got %+v", paths[0])
	}
}

func TestMissingApprovalAliasDerivedFromApprovalEvidenceState(t *testing.T) {
	t.Parallel()

	summary := SummarizeActionPaths([]ActionPath{{
		PathID:             "apc-approval-unknown",
		Org:                "acme",
		Repo:               "acme/release",
		ToolType:           "compiled_action",
		Location:           ".github/workflows/release.yml",
		WriteCapable:       true,
		CredentialAccess:   true,
		ApprovalGap:        true,
		ApprovalGapReasons: []string{"approval_source_missing"},
	}}, ActionPathSummaryOptions{})

	if summary.ApprovalEvidenceUnknownPaths != 1 {
		t.Fatalf("expected canonical approval evidence counter, got %+v", summary)
	}
	if summary.MissingApprovalPaths != summary.ApprovalEvidenceUnknownPaths {
		t.Fatalf("expected legacy missing approval alias to derive from approval evidence state, got %+v", summary)
	}
}

func TestTargetClassInternalToolingDoesNotRankAsProduction(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{
		{
			PathID:                 "internal-tool",
			Org:                    "acme",
			Repo:                   "acme/platform",
			ToolType:               "compiled_action",
			Location:               "tools/release_helper.py",
			WriteCapable:           true,
			ActionClasses:          []string{"write"},
			ActionReasons:          []string{"permission:repo.write"},
			PathContext:            &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
			ControlResolutionState: ControlResolutionStateDetectedControl,
		},
		{
			PathID:                 "prod-release",
			Org:                    "acme",
			Repo:                   "acme/platform",
			ToolType:               "compiled_action",
			Location:               ".github/workflows/release.yml",
			WriteCapable:           true,
			DeployWrite:            true,
			ProductionWrite:        true,
			ProductionTargetStatus: agginventory.ProductionTargetsStatusConfigured,
			MatchedProductionTargets: []string{
				"built_in:deploy_workflow",
			},
			ActionClasses:          []string{"deploy", "write"},
			ActionReasons:          []string{"matched_target:built_in:deploy_workflow"},
			PathContext:            &agginventory.PathContext{Kind: agginventory.PathContextDeployableSource, Confidence: "high"},
			ControlResolutionState: ControlResolutionStateDetectedControl,
		},
	})

	if len(paths) != 2 {
		t.Fatalf("expected two projected paths, got %+v", paths)
	}
	if paths[0].PathID != "prod-release" {
		t.Fatalf("expected production path to outrank internal tooling, got %+v", paths)
	}
	if paths[0].TargetClass != TargetClassProductionImpacting {
		t.Fatalf("expected production target class, got %+v", paths[0])
	}
	if paths[1].TargetClass != TargetClassInternalTooling {
		t.Fatalf("expected internal tooling target class, got %+v", paths[1])
	}
}

func TestOpenAPITargetClassCustomerDataAdjacent(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:       "payments-openapi",
		Org:          "acme",
		Repo:         "acme/payments",
		ToolType:     "openapi",
		Location:     "openapi/payments.yaml",
		WriteCapable: true,
		ActionClasses: []string{
			"write",
		},
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
			Semantic:     agginventory.EndpointSemanticPayment,
			Confidence:   "high",
			Surface:      "openapi",
			Operation:    "POST /v1/payments",
			EvidenceRefs: []string{"POST /v1/payments"},
		}},
		PathContext: &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].TargetClass != TargetClassCustomerDataAdjacent {
		t.Fatalf("expected customer-data-adjacent target class, got %+v", paths[0])
	}
	if paths[0].TargetEvidenceState != EvidenceStateVerified {
		t.Fatalf("expected target evidence to be verified from mutable endpoint refs, got %+v", paths[0])
	}
}

func TestTargetClassProductionSignalOverridesCustomerDataSurface(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:          "deploy-payment",
		Org:             "acme",
		Repo:            "acme/payments",
		ToolType:        "compiled_action",
		Location:        ".github/workflows/release.yml",
		WriteCapable:    true,
		DeployWrite:     true,
		ProductionWrite: true,
		ActionClasses: []string{
			"deploy", "write",
		},
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
			Semantic:     agginventory.EndpointSemanticPayment,
			Confidence:   "high",
			Surface:      "openapi",
			Operation:    "POST /v1/payments",
			EvidenceRefs: []string{"POST /v1/payments"},
		}},
		PathContext: &agginventory.PathContext{Kind: agginventory.PathContextDeployableSource, Confidence: "high"},
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].TargetClass != TargetClassProductionImpacting {
		t.Fatalf("expected explicit production signal to outrank customer-data classification, got %+v", paths[0])
	}
}

func TestDependencyOnlyFindingIsNotAgenticActionPath(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{{
		PathID:                 "dependency-only",
		Org:                    "acme",
		Repo:                   "acme/app",
		ToolType:               "dependency",
		Location:               "package.json",
		ControlResolutionState: ControlResolutionStateNoVisibleControl,
	}})

	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if paths[0].ActionPathType != ActionPathTypeUnknownExecutablePath {
		t.Fatalf("expected dependency-only path to stay non-agentic, got %+v", paths[0])
	}
}

func TestCredentialProvenanceUnknownIsRiskWeighted(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
			AgentID:                "wrkr:ci:acme",
			Framework:              "compiled_action",
			Org:                    "acme",
			Repos:                  []string{"acme/release"},
			Location:               ".github/workflows/release.yml",
			RiskScore:              5.0,
			WriteCapable:           true,
			CredentialAccess:       true,
			ApprovalClassification: "approved",
			CredentialProvenance: &agginventory.CredentialProvenance{
				Type:           agginventory.CredentialProvenanceUnknown,
				Scope:          agginventory.CredentialScopeUnknown,
				Confidence:     "low",
				RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceUnknown),
			},
		}},
	})
	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].RiskScore <= 5.0 {
		t.Fatalf("expected unknown provenance to amplify risk score, got %+v", paths[0])
	}
}

func TestActionPathCarriesCredentialProvenance(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
			AgentID:                "wrkr:agent:acme",
			Framework:              "langchain",
			Org:                    "acme",
			Repos:                  []string{"acme/app"},
			Location:               "agents/app.py",
			RiskScore:              4.2,
			WriteCapable:           true,
			CredentialAccess:       true,
			ApprovalClassification: "approved",
			CredentialProvenance: &agginventory.CredentialProvenance{
				Type:           agginventory.CredentialProvenanceStaticSecret,
				Subject:        "OPENAI_API_KEY",
				Scope:          agginventory.CredentialScopeTool,
				Confidence:     "high",
				EvidenceBasis:  []string{"auth_surface:OPENAI_API_KEY"},
				RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
			},
		}},
	})
	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if paths[0].CredentialProvenance == nil || paths[0].CredentialProvenance.Type != agginventory.CredentialProvenanceStaticSecret {
		t.Fatalf("expected action path provenance to carry through, got %+v", paths[0].CredentialProvenance)
	}
}

func TestActionPathCarriesCredentialArrayPathContextAndToolInstance(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:agent:acme",
				ToolFamilyID:           "wrkr:family-langchain:acme",
				ToolInstanceID:         "langchain-tool-inst-release",
				ToolID:                 "langchain-release",
				Framework:              "langchain",
				Org:                    "acme",
				Repos:                  []string{"acme/app"},
				Location:               "functional_tests/conftest.py",
				RiskScore:              4.2,
				WriteCapable:           true,
				CredentialAccess:       true,
				ApprovalClassification: "approved",
				Credentials: []*agginventory.CredentialProvenance{
					{
						Type:             agginventory.CredentialProvenanceStaticSecret,
						Subject:          "GPG_PRIVATE_KEY",
						Scope:            agginventory.CredentialScopeWorkflow,
						Confidence:       "high",
						CredentialKind:   agginventory.CredentialKindStaticSecret,
						AccessType:       agginventory.CredentialAccessTypeStanding,
						StandingAccess:   true,
						EvidenceLocation: ".github/workflows/release.yml",
						RiskMultiplier:   agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
					},
					{
						Type:           agginventory.CredentialProvenanceOAuthDelegation,
						Subject:        "github_app",
						Scope:          agginventory.CredentialScopeRepository,
						Confidence:     "medium",
						CredentialKind: agginventory.CredentialKindDelegatedOAuth,
						AccessType:     agginventory.CredentialAccessTypeDelegated,
						RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceOAuthDelegation),
					},
				},
			},
		},
	})
	if len(paths) != 1 {
		t.Fatalf("expected one action path, got %+v", paths)
	}
	if len(paths[0].Credentials) != 2 {
		t.Fatalf("expected distinct credentials array, got %+v", paths[0].Credentials)
	}
	if paths[0].CredentialProvenance == nil || paths[0].CredentialProvenance.Subject != "GPG_PRIVATE_KEY" {
		t.Fatalf("expected highest-risk credential rollup, got %+v", paths[0].CredentialProvenance)
	}
	if paths[0].PathContext == nil || paths[0].PathContext.Kind != agginventory.PathContextFunctionalTest {
		t.Fatalf("expected functional test path context, got %+v", paths[0].PathContext)
	}
	if paths[0].ToolFamilyID != "wrkr:family-langchain:acme" || paths[0].ToolInstanceID != "langchain-tool-inst-release" {
		t.Fatalf("expected tool family/instance ids, got %+v", paths[0])
	}
}

func TestDecoratePolicyCoverageMatchesDeclaredRefsToGaitPolicyFiles(t *testing.T) {
	t.Parallel()

	paths, _ := BuildActionPaths(nil, &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
			AgentID:                "wrkr:agent:acme",
			Framework:              "mcp_server",
			Org:                    "local",
			Repos:                  []string{"policy-target"},
			Location:               ".github/workflows/release.yml",
			RiskScore:              7.0,
			WriteCapable:           true,
			CredentialAccess:       true,
			ActionClasses:          []string{"deploy", "write"},
			ApprovalClassification: "approved",
			TrustDepth: &agginventory.TrustDepth{
				Surface:         agginventory.TrustSurfaceMCP,
				AuthStrength:    agginventory.TrustAuthStaticSecret,
				DelegationModel: agginventory.TrustDelegationAgent,
				Exposure:        agginventory.TrustExposurePrivate,
				PolicyRefs:      []string{"gait://release"},
			},
		}},
	})

	decorated := DecoratePolicyCoverage(paths, []model.Finding{
		{
			FindingType: "tool_config",
			ToolType:    "gait_policy",
			Org:         "local",
			Repo:        "policy-target",
			Location:    ".gait/policy.yaml",
		},
		{
			FindingType: "mcp_server",
			ToolType:    "mcp_server",
			Org:         "local",
			Repo:        "policy-target",
			Location:    ".github/workflows/release.yml",
			Evidence: []model.Evidence{
				{Key: "policy_refs", Value: "gait://release"},
			},
		},
	})
	if len(decorated) != 1 {
		t.Fatalf("expected one decorated path, got %+v", decorated)
	}
	if decorated[0].PolicyCoverageStatus != PolicyCoverageStatusMatched {
		t.Fatalf("expected matched policy coverage, got %+v", decorated[0])
	}
	if !containsPathClass(decorated[0].PolicyRefs, "gait://release") {
		t.Fatalf("expected policy ref to carry through, got %+v", decorated[0].PolicyRefs)
	}
	if decorated[0].PolicyConfidence != "high" {
		t.Fatalf("expected high policy confidence, got %+v", decorated[0])
	}
}

func TestApplyGovernFirstProfileAssessmentSuppressesAllCandidates(t *testing.T) {
	t.Parallel()

	paths := []ActionPath{
		{PathID: "one", Repo: "acme/example-repo", Location: "examples/demo-agent/config.yaml", RecommendedAction: "proof"},
		{PathID: "two", Repo: "acme/vendor-tools", Location: "vendor/agent/config.yaml", RecommendedAction: "inventory"},
	}

	filtered, choice := ApplyGovernFirstProfile("assessment", paths)

	if len(filtered) != 0 {
		t.Fatalf("expected assessment profile to suppress all candidates, got %+v", filtered)
	}
	if choice != nil {
		t.Fatalf("expected no control-first choice when all assessment candidates are suppressed, got %+v", choice)
	}
}

func TestAssessmentSuppressesPathMatchesSegmentsOnly(t *testing.T) {
	t.Parallel()

	if assessmentSuppressesPath(ActionPath{
		Repo:     "acme/latest-service",
		Location: "services/contest-runner/main.go",
	}) {
		t.Fatal("expected segment-aware suppression to ignore substring-only matches like latest/contest")
	}

	if !assessmentSuppressesPath(ActionPath{
		Repo:     "acme/platform",
		Location: "services/demo-runner/generated.go",
	}) {
		t.Fatal("expected assessment suppression to match demo/generated path segments")
	}
}

func TestDecorateActionLineageLinksGraphNodes(t *testing.T) {
	t.Parallel()

	paths := []ActionPath{{
		PathID:                   "apc-lineage",
		Org:                      "acme",
		Repo:                     "acme/release",
		AgentID:                  "wrkr:compiled_action:acme",
		ToolType:                 "compiled_action",
		Location:                 ".github/workflows/release.yml",
		Purpose:                  "Release pipeline",
		PurposeSource:            "workflow_name",
		PurposeConfidence:        "high",
		Version:                  "1.2.3",
		VersionSource:            "command_or_arg",
		ConfigFingerprint:        "cfg-abc123",
		ConfigSource:             ".github/workflows/release.yml",
		WriteCapable:             true,
		CredentialAccess:         true,
		CredentialAuthority:      &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		CredentialProvenance:     &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		ActionClasses:            []string{"deploy", "write"},
		MatchedProductionTargets: []string{"cluster/prod"},
		OperationalOwner:         "@acme/release",
		OwnershipStatus:          "explicit",
		ApprovalGap:              true,
		ApprovalGapReasons:       []string{"approval_evidence_missing"},
		PolicyCoverageStatus:     PolicyCoverageStatusNone,
	}}

	graph := BuildControlPathGraph(paths)
	decorated := DecorateActionLineage(paths, graph)
	if len(decorated) != 1 || decorated[0].ActionLineage == nil {
		t.Fatalf("expected decorated action lineage, got %+v", decorated)
	}

	segments := map[string]ActionLineageSegment{}
	for _, segment := range decorated[0].ActionLineage.Segments {
		segments[segment.Kind] = segment
	}
	for _, kind := range []string{"repo", "workflow", "action", "credential", "target", "approval", "proof"} {
		if _, ok := segments[kind]; !ok {
			t.Fatalf("expected lineage segment %q, got %+v", kind, decorated[0].ActionLineage)
		}
	}
	if len(segments["credential"].NodeIDs) == 0 || len(segments["target"].NodeIDs) == 0 {
		t.Fatalf("expected graph-linked credential/target nodes, got %+v", decorated[0].ActionLineage)
	}
	if segments["approval"].Status != "missing" || segments["proof"].Status != "missing" {
		t.Fatalf("expected approval/proof lineage gaps, got %+v", decorated[0].ActionLineage)
	}
}

func TestDecorateActionLineageFiltersGovernanceEdgesPerSegment(t *testing.T) {
	t.Parallel()

	paths := []ActionPath{{
		PathID:               "apc-governance-lineage",
		Org:                  "acme",
		Repo:                 "acme/release",
		AgentID:              "wrkr:compiled_action:acme",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		ApprovalGap:          false,
		PolicyCoverageStatus: PolicyCoverageStatusMatched,
		GovernanceControls: []agginventory.GovernanceControlMapping{
			{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusSatisfied},
			{Control: agginventory.GovernanceControlProof, Status: agginventory.ControlStatusSatisfied},
		},
	}}

	graph := BuildControlPathGraph(paths)
	decorated := DecorateActionLineage(paths, graph)
	if len(decorated) != 1 || decorated[0].ActionLineage == nil {
		t.Fatalf("expected decorated action lineage, got %+v", decorated)
	}

	segments := map[string]ActionLineageSegment{}
	for _, segment := range decorated[0].ActionLineage.Segments {
		segments[segment.Kind] = segment
	}

	approval := segments["approval"]
	proof := segments["proof"]
	if len(approval.NodeIDs) != 1 || len(proof.NodeIDs) != 1 {
		t.Fatalf("expected one governance node per segment, got approval=%+v proof=%+v", approval, proof)
	}
	if len(approval.EdgeIDs) != 1 || len(proof.EdgeIDs) != 1 {
		t.Fatalf("expected one governance edge per segment, got approval=%+v proof=%+v", approval, proof)
	}
	if approval.NodeIDs[0] == proof.NodeIDs[0] {
		t.Fatalf("expected approval and proof node IDs to differ, got approval=%+v proof=%+v", approval, proof)
	}
	if approval.EdgeIDs[0] == proof.EdgeIDs[0] {
		t.Fatalf("expected approval and proof edge IDs to differ, got approval=%+v proof=%+v", approval, proof)
	}
}

func sliceToSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func containsPathClass(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
