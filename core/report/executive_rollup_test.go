package report

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildAgentActionBOMCarriesExecutiveRollupAndGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	pathOne := risk.ProjectActionPath(risk.ActionPath{
		PathID:                   "apc-prod-1",
		Org:                      "acme",
		Repo:                     "acme/payments",
		ToolType:                 "ci_agent",
		Location:                 ".github/workflows/release.yml",
		ActionClasses:            []string{"deploy", "write"},
		ActionPathType:           risk.ActionPathTypeAIAssistedWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		ProductionWrite:          true,
		MatchedProductionTargets: []string{"cluster/prod"},
		CredentialAccess:         true,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			StandingAccess:         true,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
		OperationalOwner:        "@acme/payments",
		OwnershipStatus:         "explicit",
		OwnershipState:          "verified",
		OwnerEvidenceState:      risk.EvidenceStateVerified,
		ApprovalEvidenceState:   risk.EvidenceStateUnknown,
		ProofEvidenceState:      risk.EvidenceStateVerified,
		RuntimeEvidenceState:    risk.EvidenceStateVerified,
		TargetEvidenceState:     risk.EvidenceStateVerified,
		CredentialEvidenceState: risk.EvidenceStateVerified,
		ControlResolutionState:  risk.ControlResolutionStateDetectedControl,
		ConfidenceLane:          risk.ConfidenceLaneConfirmedActionPath,
		ControlPriority:         risk.ControlPriorityControlFirst,
		RiskTier:                risk.RiskTierCritical,
		RiskZone:                "production_change",
		ExecutionIdentity:       "deploy-bot",
		ExecutionIdentityType:   "github_actions",
		SharedExecutionIdentity: true,
	})
	pathOne.ApprovalEvidenceState = risk.EvidenceStateUnknown
	pathOne.OwnerEvidenceState = risk.EvidenceStateVerified
	pathOne.ProofEvidenceState = risk.EvidenceStateVerified
	pathOne.RuntimeEvidenceState = risk.EvidenceStateVerified
	pathOne.TargetEvidenceState = risk.EvidenceStateVerified
	pathOne.CredentialEvidenceState = risk.EvidenceStateVerified
	pathOne.ControlResolutionState = risk.ControlResolutionStateDetectedControl
	pathOne.ControlPriority = risk.ControlPriorityControlFirst
	pathOne.RiskTier = risk.RiskTierCritical
	pathOne.ConfidenceLane = risk.ConfidenceLaneConfirmedActionPath
	pathTwo := pathOne
	pathTwo.PathID = "apc-prod-2"
	pathTwo.Repo = "acme/billing"
	pathTwo.Location = ".github/workflows/deploy.yml"
	pathTwo.MatchedProductionTargets = []string{"cluster/prod"}

	pathThree := risk.ProjectActionPath(risk.ActionPath{
		PathID:                  "apc-unknown-1",
		Org:                     "acme",
		Repo:                    "acme/internal-tools",
		ToolType:                "codex",
		Location:                "AGENTS.md",
		ActionClasses:           []string{"write"},
		ActionPathType:          risk.ActionPathTypeAgentFramework,
		TargetClass:             "internal_tooling",
		CredentialAccess:        true,
		OperationalOwner:        "@acme/platform",
		OwnershipStatus:         "explicit",
		OwnershipState:          "verified",
		OwnerEvidenceState:      risk.EvidenceStateVerified,
		ApprovalEvidenceState:   risk.EvidenceStateDeclared,
		ProofEvidenceState:      risk.EvidenceStateUnknown,
		RuntimeEvidenceState:    risk.EvidenceStateUnknown,
		TargetEvidenceState:     risk.EvidenceStateDeclared,
		CredentialEvidenceState: risk.EvidenceStateUnknown,
		ControlResolutionState:  risk.ControlResolutionStateNoVisibleControl,
		ConfidenceLane:          risk.ConfidenceLaneConfirmedActionPath,
		ControlPriority:         risk.ControlPriorityReviewQueue,
		RiskTier:                risk.RiskTierHigh,
		RiskZone:                "internal_change",
		ExecutionIdentity:       "codex-review",
		ExecutionIdentityType:   "local_agent",
	})
	pathThree.ApprovalEvidenceState = risk.EvidenceStateDeclared
	pathThree.OwnerEvidenceState = risk.EvidenceStateVerified
	pathThree.ProofEvidenceState = risk.EvidenceStateUnknown
	pathThree.RuntimeEvidenceState = risk.EvidenceStateUnknown
	pathThree.TargetEvidenceState = risk.EvidenceStateDeclared
	pathThree.CredentialEvidenceState = risk.EvidenceStateUnknown
	pathThree.ControlResolutionState = risk.ControlResolutionStateNoVisibleControl
	pathThree.ControlPriority = risk.ControlPriorityReviewQueue
	pathThree.RiskTier = "high"
	pathThree.ConfidenceLane = risk.ConfidenceLaneConfirmedActionPath

	pathFour := risk.ProjectActionPath(risk.ActionPath{
		PathID:                   "apc-contradict-1",
		Org:                      "acme",
		Repo:                     "acme/payments",
		ToolType:                 "ci_agent",
		Location:                 ".github/workflows/prod-hotfix.yml",
		ActionClasses:            []string{"deploy", "write"},
		ActionPathType:           risk.ActionPathTypeAIAssistedWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		ProductionWrite:          true,
		MatchedProductionTargets: []string{"cluster/prod"},
		CredentialAccess:         true,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			StandingAccess:         true,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
		OperationalOwner:        "@acme/payments",
		OwnershipStatus:         "explicit",
		OwnershipState:          "verified",
		OwnerEvidenceState:      risk.EvidenceStateVerified,
		ApprovalEvidenceState:   risk.EvidenceStateContradictory,
		ProofEvidenceState:      risk.EvidenceStateContradictory,
		RuntimeEvidenceState:    risk.EvidenceStateVerified,
		TargetEvidenceState:     risk.EvidenceStateVerified,
		CredentialEvidenceState: risk.EvidenceStateVerified,
		ControlResolutionState:  risk.ControlResolutionStateContradictoryControl,
		ConfidenceLane:          risk.ConfidenceLaneConfirmedActionPath,
		ControlPriority:         risk.ControlPriorityControlFirst,
		RiskTier:                risk.RiskTierCritical,
		RiskZone:                "production_change",
		ExecutionIdentity:       "deploy-bot",
		ExecutionIdentityType:   "github_actions",
		SharedExecutionIdentity: true,
	})
	pathFour.ApprovalEvidenceState = risk.EvidenceStateContradictory
	pathFour.OwnerEvidenceState = risk.EvidenceStateVerified
	pathFour.ProofEvidenceState = risk.EvidenceStateContradictory
	pathFour.RuntimeEvidenceState = risk.EvidenceStateVerified
	pathFour.TargetEvidenceState = risk.EvidenceStateVerified
	pathFour.CredentialEvidenceState = risk.EvidenceStateVerified
	pathFour.ControlResolutionState = risk.ControlResolutionStateContradictoryControl
	pathFour.ControlPriority = risk.ControlPriorityControlFirst
	pathFour.RiskTier = risk.RiskTierCritical
	pathFour.ConfidenceLane = risk.ConfidenceLaneConfirmedActionPath

	summary := Summary{
		GeneratedAt:  "2026-05-31T18:30:13Z",
		ShareProfile: string(ShareProfileInternal),
		ActionPaths:  []risk.ActionPath{pathOne, pathTwo, pathThree, pathFour},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{
				{
					ID:                 "cb-prod-1",
					Repo:               pathOne.Repo,
					Path:               pathOne.Location,
					RecommendedAction:  controlbacklog.ActionRemediate,
					LinkedActionPathID: pathOne.PathID,
					Queue:              controlbacklog.QueueControlFirst,
				},
				{
					ID:                 "cb-prod-2",
					Repo:               pathTwo.Repo,
					Path:               pathTwo.Location,
					RecommendedAction:  controlbacklog.ActionRemediate,
					LinkedActionPathID: pathTwo.PathID,
					Queue:              controlbacklog.QueueControlFirst,
				},
				{
					ID:                 "cb-unknown-1",
					Repo:               pathThree.Repo,
					Path:               pathThree.Location,
					RecommendedAction:  controlbacklog.ActionAttachEvidence,
					LinkedActionPathID: pathThree.PathID,
					Queue:              controlbacklog.QueueReviewQueue,
				},
				{
					ID:                 "cb-contradict-1",
					Repo:               pathFour.Repo,
					Path:               pathFour.Location,
					RecommendedAction:  controlbacklog.ActionAttachEvidence,
					LinkedActionPathID: pathFour.PathID,
					Queue:              controlbacklog.QueueControlFirst,
				},
			},
		},
		RuntimeSessions: &ingest.SessionSummary{
			MatchedSessions: 1,
			Correlations: []ingest.SessionCorrelation{
				{PathID: pathOne.PathID, Status: ingest.CorrelationStatusMatched},
			},
		},
		RuntimeEvidence: &ingest.Summary{
			MatchedRecords: 1,
			Correlations: []ingest.Correlation{
				{PathID: pathFour.PathID, Status: ingest.CorrelationStatusMatched},
			},
		},
		EvidencePackets: &ingest.EvidencePacketSummary{
			TotalPackets:   2,
			MatchedPackets: 1,
			Correlations: []ingest.EvidencePacketCorrelation{
				{PathID: pathFour.PathID, Status: ingest.CorrelationStatusMatched},
			},
		},
	}

	first := BuildAgentActionBOM(summary)
	second := BuildAgentActionBOM(summary)
	if first == nil || second == nil {
		t.Fatalf("expected BOM output, got first=%+v second=%+v", first, second)
	}
	if !reflect.DeepEqual(first.Summary.ExecutiveRollup, second.Summary.ExecutiveRollup) {
		t.Fatalf("expected deterministic executive rollup\nfirst=%+v\nsecond=%+v", first.Summary.ExecutiveRollup, second.Summary.ExecutiveRollup)
	}

	rollup := first.Summary.ExecutiveRollup
	if rollup == nil {
		t.Fatal("expected executive rollup on BOM summary")
	}
	if rollup.TotalGroups != 3 || rollup.TotalPaths != 4 {
		t.Fatalf("unexpected rollup totals: %+v", rollup)
	}
	var groupedProductionPaths *controlbacklog.ExecutiveRollupGroup
	for idx := range rollup.Groups {
		if rollup.Groups[idx].Count == 2 && rollup.Groups[idx].Dimensions.ClosureAction == controlbacklog.ActionRemediate {
			groupedProductionPaths = &rollup.Groups[idx]
			break
		}
	}
	if groupedProductionPaths == nil {
		t.Fatalf("expected grouped production rollup, got %+v", rollup.Groups)
	}
	if groupedProductionPaths.Dimensions.ActionClass != "deploy" ||
		groupedProductionPaths.Dimensions.TargetClass != risk.TargetClassProductionImpacting ||
		groupedProductionPaths.Dimensions.CredentialAuthority != "standing" ||
		groupedProductionPaths.Dimensions.RepoCluster != "cross_repo_shared_identity" ||
		groupedProductionPaths.Dimensions.ClosureAction != controlbacklog.ActionRemediate {
		t.Fatalf("unexpected grouped production dimensions: %+v", groupedProductionPaths.Dimensions)
	}
	if !reflect.DeepEqual(groupedProductionPaths.TopExampleRefs, []string{"apc-prod-1", "apc-prod-2"}) {
		t.Fatalf("expected stable redaction-safe example refs, got %+v", groupedProductionPaths.TopExampleRefs)
	}

	metrics := first.Summary.GovernedUsageMetrics
	if metrics == nil {
		t.Fatal("expected governed usage metrics on BOM summary")
	}
	if metrics.ActiveMonitoredActionPaths != 4 ||
		metrics.GovernedPaths != 4 ||
		metrics.EvidencePacks != 2 ||
		metrics.AuditExports != 4 ||
		metrics.ApprovalDecisions != 1 ||
		metrics.ConnectedRuntimes != 2 ||
		metrics.GovernedAgentsWorkflows != 4 ||
		metrics.VerifiedControlPaths != 2 ||
		metrics.UnknownControlPaths != 1 ||
		metrics.ContradictoryPaths != 1 {
		t.Fatalf("unexpected governed usage metrics: %+v", metrics)
	}
}

func TestRenderMarkdownPlacesExecutiveRollupBeforeControlBacklog(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-05-31T18:30:13Z",
		Template:     string(TemplateCISO),
		ShareProfile: string(ShareProfileInternal),
		ExecutiveRollup: &controlbacklog.ExecutiveRollup{
			TotalGroups: 1,
			TotalPaths:  2,
			Groups: []controlbacklog.ExecutiveRollupGroup{
				{
					GroupID:               "xrg-prod-remediate",
					Count:                 2,
					HighestSeverity:       risk.RiskTierCritical,
					HighestPriority:       risk.ControlPriorityControlFirst,
					ClosureRecommendation: "remediate standing production deploy paths first",
					TopExampleRefs:        []string{"apc-prod-1", "apc-prod-2"},
					Dimensions: controlbacklog.ExecutiveRollupDimensions{
						ActionClass:         "deploy",
						TargetClass:         risk.TargetClassProductionImpacting,
						RiskZone:            "production_change",
						CredentialAuthority: "standing",
						ProductionTarget:    "production_targeted",
						EvidenceState:       risk.EvidenceStateUnknown,
						OwnerState:          "verified",
						RepoCluster:         "cross_repo_shared_identity",
						DetectorConfidence:  risk.ConfidenceLaneConfirmedActionPath,
						ContradictionState:  "consistent",
						ClosureAction:       controlbacklog.ActionRemediate,
					},
				},
			},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{{
				ID:                 "cb-prod-1",
				Repo:               "acme/payments",
				Path:               ".github/workflows/release.yml",
				RecommendedAction:  controlbacklog.ActionRemediate,
				LinkedActionPathID: "apc-prod-1",
				Queue:              controlbacklog.QueueControlFirst,
			}},
		},
	}

	markdown := RenderMarkdown(summary)
	rollupAt := strings.Index(markdown, "## Executive Rollup")
	backlogAt := strings.Index(markdown, "## Control Backlog")
	if rollupAt == -1 || backlogAt == -1 {
		t.Fatalf("expected markdown sections, got:\n%s", markdown)
	}
	if rollupAt > backlogAt {
		t.Fatalf("expected executive rollup ahead of backlog detail, got:\n%s", markdown)
	}
}

func TestCompareExecutiveRollupGroupsHonorsPriorityChain(t *testing.T) {
	t.Parallel()

	groups := []controlbacklog.ExecutiveRollupGroup{
		{
			GroupID:         "z-id-last",
			Count:           3,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "standing",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
		{
			GroupID:         "a-id-first",
			Count:           3,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "standing",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
		{
			GroupID:         "count-heavy",
			Count:           5,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "standing",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
		{
			GroupID:         "contradictory",
			Count:           2,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "standing",
				ContradictionState:  "contradictory",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
		{
			GroupID:         "jit-authority",
			Count:           8,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "jit",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
		{
			GroupID:         "non-production",
			Count:           9,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "non_production_or_unknown",
				CredentialAuthority: "standing",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
		{
			GroupID:         "monitor-only",
			Count:           10,
			HighestSeverity: risk.RiskTierCritical,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "standing",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionMonitor,
			},
		},
		{
			GroupID:         "high-severity",
			Count:           11,
			HighestSeverity: risk.RiskTierHigh,
			Dimensions: controlbacklog.ExecutiveRollupDimensions{
				ProductionTarget:    "production_targeted",
				CredentialAuthority: "standing",
				ContradictionState:  "consistent",
				ClosureAction:       controlbacklog.ActionRemediate,
			},
		},
	}

	sort.Slice(groups, func(i, j int) bool {
		return compareExecutiveRollupGroups(groups[i], groups[j])
	})

	orderedIDs := make([]string, 0, len(groups))
	for _, group := range groups {
		orderedIDs = append(orderedIDs, group.GroupID)
	}

	want := []string{
		"contradictory",
		"count-heavy",
		"a-id-first",
		"z-id-last",
		"jit-authority",
		"non-production",
		"monitor-only",
		"high-severity",
	}
	if !reflect.DeepEqual(orderedIDs, want) {
		t.Fatalf("unexpected executive rollup order\nwant=%v\ngot=%v", want, orderedIDs)
	}
}

func TestResolveExecutiveRollupAndMetricsHandleEmptyState(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-05-31T18:30:13Z",
		ShareProfile: string(ShareProfileInternal),
	}

	rollup := resolveExecutiveRollup(summary)
	if rollup == nil {
		t.Fatal("expected empty executive rollup, got nil")
	}
	if rollup.TotalGroups != 0 || rollup.TotalPaths != 0 || len(rollup.Groups) != 0 {
		t.Fatalf("expected empty executive rollup, got %+v", rollup)
	}

	metrics := resolveGovernedUsageMetrics(summary)
	if metrics == nil {
		t.Fatal("expected empty governed usage metrics, got nil")
	}
	if metrics.ActiveMonitoredActionPaths != 0 ||
		metrics.GovernedPaths != 0 ||
		metrics.EvidencePacks != 0 ||
		metrics.AuditExports != 2 ||
		metrics.ApprovalDecisions != 0 ||
		metrics.ConnectedRuntimes != 0 ||
		metrics.GovernedAgentsWorkflows != 0 ||
		metrics.VerifiedControlPaths != 0 ||
		metrics.UnknownControlPaths != 0 ||
		metrics.ContradictoryPaths != 0 {
		t.Fatalf("unexpected empty-state governed usage metrics: %+v", metrics)
	}
}

func TestBuildSummaryCustomerRedactedExecutiveRollupPreservesCounts(t *testing.T) {
	t.Parallel()

	path := risk.ProjectActionPath(risk.ActionPath{
		PathID:                   "apc-private-1",
		AgentID:                  "wrkr:ci_agent:acme",
		Org:                      "acme",
		Repo:                     "acme/payments",
		ToolType:                 "ci_agent",
		Location:                 ".github/workflows/release.yml",
		ActionClasses:            []string{"deploy", "write"},
		ActionPathType:           risk.ActionPathTypeAIAssistedWorkflow,
		TargetClass:              risk.TargetClassProductionImpacting,
		ProductionWrite:          true,
		MatchedProductionTargets: []string{"cluster/prod"},
		CredentialAccess:         true,
		CredentialAuthority: &agginventory.CredentialAuthority{
			CredentialPresent:      true,
			CredentialUsableByPath: true,
			StandingAccess:         true,
			AccessType:             agginventory.CredentialAccessTypeStanding,
		},
		OperationalOwner:        "@acme/payments",
		OwnershipStatus:         "explicit",
		OwnershipState:          "verified",
		OwnerEvidenceState:      risk.EvidenceStateVerified,
		ApprovalEvidenceState:   risk.EvidenceStateDeclared,
		ProofEvidenceState:      risk.EvidenceStateVerified,
		RuntimeEvidenceState:    risk.EvidenceStateVerified,
		TargetEvidenceState:     risk.EvidenceStateVerified,
		CredentialEvidenceState: risk.EvidenceStateVerified,
		ControlResolutionState:  risk.ControlResolutionStateDetectedControl,
		ConfidenceLane:          risk.ConfidenceLaneConfirmedActionPath,
		ControlPriority:         risk.ControlPriorityControlFirst,
		RiskTier:                risk.RiskTierCritical,
		RiskZone:                "production_change",
		ExecutionIdentity:       "deploy-bot",
		ExecutionIdentityType:   "github_actions",
	})

	input := BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{path},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 31, 18, 30, 13, 0, time.UTC),
	}

	internal, err := BuildSummary(input)
	if err != nil {
		t.Fatalf("build internal summary: %v", err)
	}
	input.ShareProfile = ShareProfileCustomerRedacted
	redacted, err := BuildSummary(input)
	if err != nil {
		t.Fatalf("build redacted summary: %v", err)
	}

	if internal.ExecutiveRollup == nil || redacted.ExecutiveRollup == nil {
		t.Fatalf("expected executive rollups for both summaries, internal=%+v redacted=%+v", internal.ExecutiveRollup, redacted.ExecutiveRollup)
	}
	if internal.GovernedUsageMetrics == nil || redacted.GovernedUsageMetrics == nil {
		t.Fatalf("expected governed usage metrics for both summaries, internal=%+v redacted=%+v", internal.GovernedUsageMetrics, redacted.GovernedUsageMetrics)
	}
	if internal.ExecutiveRollup.TotalGroups != redacted.ExecutiveRollup.TotalGroups ||
		internal.ExecutiveRollup.TotalPaths != redacted.ExecutiveRollup.TotalPaths {
		t.Fatalf("expected redaction to preserve executive rollup totals, internal=%+v redacted=%+v", internal.ExecutiveRollup, redacted.ExecutiveRollup)
	}
	if !reflect.DeepEqual(internal.GovernedUsageMetrics, redacted.GovernedUsageMetrics) {
		t.Fatalf("expected redaction to preserve governed usage metrics, internal=%+v redacted=%+v", internal.GovernedUsageMetrics, redacted.GovernedUsageMetrics)
	}

	internalExamples := internal.ExecutiveRollup.Groups[0].TopExampleRefs
	redactedExamples := redacted.ExecutiveRollup.Groups[0].TopExampleRefs
	if !reflect.DeepEqual(internalExamples, []string{"apc-private-1"}) {
		t.Fatalf("unexpected internal example refs: %+v", internalExamples)
	}
	if len(redactedExamples) != 1 || !strings.HasPrefix(redactedExamples[0], "path-") {
		t.Fatalf("expected redacted example refs, got %+v", redactedExamples)
	}
	if redactedExamples[0] == internalExamples[0] {
		t.Fatalf("expected redacted example ref to differ from internal ref, got %q", redactedExamples[0])
	}
	if redacted.ControlBacklog == nil || redacted.ControlBacklog.ExecutiveRollup == nil {
		t.Fatalf("expected redacted control backlog rollup, got %+v", redacted.ControlBacklog)
	}
	if !reflect.DeepEqual(redacted.ControlBacklog.ExecutiveRollup, redacted.ExecutiveRollup) {
		t.Fatalf("expected control backlog rollup to mirror top-level summary, backlog=%+v summary=%+v", redacted.ControlBacklog.ExecutiveRollup, redacted.ExecutiveRollup)
	}
}
