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
	}
	if firstChoice.Path.PathID != firstPaths[0].PathID {
		t.Fatalf("expected control-first choice to reference deduped path row, choice=%+v paths=%+v", firstChoice.Path, firstPaths)
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
	if secondChoice == nil || secondChoice.Path.PathID != secondPaths[0].PathID {
		t.Fatalf("expected repeat run control-first choice to reference deduped path, choice=%+v paths=%+v", secondChoice, secondPaths)
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
