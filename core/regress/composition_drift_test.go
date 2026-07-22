package regress

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestCompositionDriftIgnoresPathIDChurnAndDetectsNewExternalSink(t *testing.T) {
	baselineComposition := regressTestComposition("cap-old", "rk-egress-old", "prod:checkout", "production_deploy")
	baselineComposition.PathIDs = []string{"apc-old-source", "apc-old-sink"}
	currentComposition := regressTestComposition("cap-new", "rk-egress-new", "prod:checkout", "production_deploy")
	currentComposition.PathIDs = []string{"apc-new-source", "apc-new-sink"}

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if !result.Drift {
		t.Fatalf("expected composition drift, got %+v", result)
	}
	if hasDriftCategory(result.DriftCategories, DriftCategoryIntroducedCompositions) || hasDriftCategory(result.DriftCategories, DriftCategoryRemovedCompositions) {
		t.Fatalf("path-id churn and member replacement within a family should not emit removed+introduced, got %+v", result.DriftCategories)
	}
	if !hasDriftCategory(result.DriftCategories, DriftCategoryChangedCompositionMembers) || !hasDriftCategory(result.DriftCategories, DriftCategoryNewCompositionSinks) {
		t.Fatalf("expected changed members and new sink drift, got %+v", result.DriftCategories)
	}
}

func TestCompositionDriftClassifiesOutcomeChangeByFamilyKey(t *testing.T) {
	baselineComposition := regressTestComposition("cap-deploy-staging", "rk-deploy", "prod:checkout", "staging_deploy")
	baselineComposition.OutcomeKey = "asset=prod:checkout|target_class=production_impacting|outcome=staging_deploy|environment=staging"
	currentComposition := regressTestComposition("cap-deploy-prod", "rk-deploy", "prod:checkout", "production_deploy")
	currentComposition.OutcomeKey = "asset=prod:checkout|target_class=production_impacting|outcome=production_deploy|environment=production"

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if !hasDriftCategory(result.DriftCategories, DriftCategoryCompositionOutcomeChanged) {
		t.Fatalf("expected outcome changed category, got %+v", result.DriftCategories)
	}
	if hasDriftCategory(result.DriftCategories, DriftCategoryIntroducedCompositions) || hasDriftCategory(result.DriftCategories, DriftCategoryRemovedCompositions) {
		t.Fatalf("outcome changes should pair by family key, got %+v", result.DriftCategories)
	}
}

func TestCompositionDriftReportsMissingBaselineCompositionData(t *testing.T) {
	baseline := BuildBaseline(state.Snapshot{Version: state.SnapshotVersion}, time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC))
	currentComposition := regressTestComposition("cap-current", "rk-egress", "prod:checkout", "production_deploy")

	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if result.ComparisonStatus != DriftComparisonStatusBaselineCompositionsMissing {
		t.Fatalf("expected missing baseline composition status, got %+v", result)
	}
	if !result.Drift {
		t.Fatalf("missing required composition baseline data should fail closed as drift, got %+v", result)
	}
}

func TestCompositionDriftReportsMissingCurrentCompositionDataWhenSnapshotOmitsComparableSurfaces(t *testing.T) {
	baselineComposition := regressTestComposition("cap-baseline", "rk-egress", "prod:checkout", "production_deploy")
	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC))

	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{}})

	if result.ComparisonStatus != DriftComparisonStatusCurrentCompositionsMissing {
		t.Fatalf("expected missing current composition status, got %+v", result)
	}
	if hasDriftCategory(result.DriftCategories, DriftCategoryRemovedCompositions) {
		t.Fatalf("missing comparable current composition data should fail closed, not report removed compositions: %+v", result.DriftCategories)
	}
}

func TestCompositionDriftTreatsMissingGaitCoverageAsDegraded(t *testing.T) {
	baselineComposition := regressTestComposition("cap-baseline", "rk-deploy", "prod:checkout", "production_deploy")
	currentComposition := regressTestComposition("cap-baseline", "rk-deploy", "prod:checkout", "production_deploy")
	currentComposition.GaitCoverage = nil

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 18, 1, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if !hasDriftCategory(result.DriftCategories, DriftCategoryCompositionCoverageDegraded) {
		t.Fatalf("expected missing gait coverage to degrade composition coverage, got %+v", result.DriftCategories)
	}
}

func TestCompositionDriftTracksMultiStageReachabilityWithoutRekeyingFamily(t *testing.T) {
	t.Parallel()

	baselineComposition := regressTestComposition("cap-observed", "rk-deploy", "prod:checkout", "production_deploy")
	baselineComposition.PatternID = risk.CompositionPatternCodeToDeployMultiStage
	baselineComposition.ReachabilityState = risk.CompositionReachabilityObserved
	baselineComposition.ObservedExecution = true
	baselineComposition.Stages = append(baselineComposition.Stages[:1], risk.CompositionStage{
		StageID: "stage-ci", Role: risk.CompositionStageRoleTransform, ResolutionKey: "rk-ci", SystemClass: risk.CompositionSystemClassCI, TrustBoundary: "ci:acme/checkout", CorrelationRefs: []string{"workflow_chain:wfc-deploy"},
	}, baselineComposition.Stages[1])
	baselineComposition.Stages[0].SystemClass = risk.CompositionSystemClassRepo
	baselineComposition.Stages[0].TrustBoundary = "repo:acme/checkout"
	baselineComposition.Stages[2].SystemClass = risk.CompositionSystemClassCloud
	baselineComposition.Stages[2].TrustBoundary = "cloud:deploy"

	currentComposition := baselineComposition
	currentComposition.CompositionID = "cap-possible"
	currentComposition.ReachabilityState = risk.CompositionReachabilityPossible
	currentComposition.ObservedExecution = false

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if !hasDriftCategory(result.DriftCategories, DriftCategoryCompositionReachabilityChanged) {
		t.Fatalf("expected possible-versus-observed reachability drift, got %+v", result.DriftCategories)
	}
	if hasDriftCategory(result.DriftCategories, DriftCategoryIntroducedCompositions) || hasDriftCategory(result.DriftCategories, DriftCategoryRemovedCompositions) {
		t.Fatalf("reachability evidence movement must remain within the same route family, got %+v", result.DriftCategories)
	}
}

func TestCompositionDriftTreatsRemovedMultiStageCorrelationAsEvidenceDegraded(t *testing.T) {
	t.Parallel()

	baselineComposition := regressTestComposition("cap-correlated", "rk-deploy", "prod:checkout", "production_deploy")
	baselineComposition.PatternID = risk.CompositionPatternCodeToDeployMultiStage
	baselineComposition.ReachabilityState = risk.CompositionReachabilityPossible
	baselineComposition.Stages = append(baselineComposition.Stages[:1], risk.CompositionStage{
		StageID: "stage-ci", Role: risk.CompositionStageRoleTransform, ResolutionKey: "rk-ci", SystemClass: risk.CompositionSystemClassCI, TrustBoundary: "ci:acme/checkout", CorrelationRefs: []string{"workflow_chain:wfc-deploy"},
	}, baselineComposition.Stages[1])
	baselineComposition.Stages[0].SystemClass = risk.CompositionSystemClassRepo
	baselineComposition.Stages[0].TrustBoundary = "repo:acme/checkout"
	baselineComposition.Stages[2].SystemClass = risk.CompositionSystemClassCloud
	baselineComposition.Stages[2].TrustBoundary = "cloud:deploy"

	currentComposition := baselineComposition
	currentComposition.Stages = append([]risk.CompositionStage(nil), baselineComposition.Stages...)
	currentComposition.Stages[1].CorrelationRefs = nil

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if !hasDriftCategory(result.DriftCategories, DriftCategoryCompositionEvidenceDegraded) {
		t.Fatalf("expected removed transition correlation to degrade evidence, got %+v", result.DriftCategories)
	}
}

func TestCompositionDriftPairsMultiStageMemberChurnWithinRouteFamily(t *testing.T) {
	t.Parallel()

	baselineComposition := regressTestComposition("cap-baseline", "rk-deploy", "prod:checkout", "production_deploy")
	baselineComposition.PatternID = risk.CompositionPatternCodeToDeployMultiStage
	baselineComposition.ReachabilityState = risk.CompositionReachabilityPossible
	baselineComposition.Stages = append(baselineComposition.Stages[:1], risk.CompositionStage{
		StageID: "stage-ci", Role: risk.CompositionStageRoleTransform, ResolutionKey: "rk-ci-old", ToolType: "github_actions", Location: ".github/workflows/deploy.yml", SystemClass: risk.CompositionSystemClassCI, TrustBoundary: "ci:acme/checkout",
	}, baselineComposition.Stages[1])
	baselineComposition.Stages[0].SystemClass = risk.CompositionSystemClassRepo
	baselineComposition.Stages[0].TrustBoundary = "repo:acme/checkout"
	baselineComposition.Stages[2].SystemClass = risk.CompositionSystemClassCloud
	baselineComposition.Stages[2].TrustBoundary = "cloud:deploy"

	currentComposition := baselineComposition
	currentComposition.CompositionID = "cap-current"
	currentComposition.Stages = append([]risk.CompositionStage(nil), baselineComposition.Stages...)
	currentComposition.Stages[1].ResolutionKey = "rk-ci-new"

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})

	if !hasDriftCategory(result.DriftCategories, DriftCategoryChangedCompositionMembers) {
		t.Fatalf("expected durable member churn to stay in the route family, got %+v", result.DriftCategories)
	}
	if hasDriftCategory(result.DriftCategories, DriftCategoryIntroducedCompositions) || hasDriftCategory(result.DriftCategories, DriftCategoryRemovedCompositions) {
		t.Fatalf("member churn must not become removed-plus-introduced noise: %+v", result.DriftCategories)
	}
}

func TestActionContractLifecycleDriftClassifiesRevisionAndDownstreamEvidence(t *testing.T) {
	baselineComposition := regressTestComposition("cap-contract", "rk-deploy", "prod:checkout", "production_deploy")
	baselineComposition.ProposedActionContract = risk.BuildProposedActionContract(baselineComposition)
	currentComposition := baselineComposition
	currentComposition.ProposedActionContract = risk.CloneProposedActionContract(baselineComposition.ProposedActionContract)
	currentComposition.ProposedActionContract.Revision = 2
	currentComposition.ProposedActionContract.SupersedesRef = baselineComposition.ProposedActionContract.ContractID
	risk.RefreshProposedActionContractIdentity(currentComposition.ProposedActionContract)
	currentComposition.ProposedActionContract.LifecycleObservations = risk.NormalizeProposedActionLifecycleObservations([]risk.ProposedActionLifecycleObservation{
		{Kind: risk.LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh", EvidenceRefs: []string{"gait:receipt"}},
		{Kind: risk.LifecycleObservationRejection, Producer: "gait", EvidenceState: risk.EvidenceStateContradictory, FreshnessState: "fresh", EvidenceRefs: []string{"gait:rejection"}},
		{Kind: risk.LifecycleObservationExecution, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh", EvidenceRefs: []string{"gait:execution"}},
		{Kind: risk.LifecycleObservationEffect, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh", EvidenceRefs: []string{"gait:effect"}},
		{Kind: risk.LifecycleObservationAxymVerification, Producer: "axym", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh", EvidenceRefs: []string{"axym:bundle"}},
	})

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})
	for _, category := range []string{
		DriftCategoryActionContractRevisionChanged,
		DriftCategoryActionContractActivationChanged,
		DriftCategoryActionContractRejectionChanged,
		DriftCategoryActionContractExecutionEffectChanged,
		DriftCategoryActionContractVerificationChanged,
	} {
		if !hasDriftCategory(result.DriftCategories, category) {
			t.Fatalf("expected %s classification, got %+v", category, result.DriftCategories)
		}
	}
}

func TestActionContractLifecycleArtifactRefsParticipateInDrift(t *testing.T) {
	baselineComposition := regressTestComposition("cap-contract-artifact", "rk-deploy", "prod:checkout", "production_deploy")
	baselineComposition.ProposedActionContract = risk.BuildProposedActionContract(baselineComposition)
	baselineComposition.ProposedActionContract.LifecycleObservations = risk.NormalizeProposedActionLifecycleObservations([]risk.ProposedActionLifecycleObservation{{
		Kind: risk.LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh",
		EvidenceRefs: []string{"gait:receipt"}, ProofRefs: []string{"proof:gait"}, ActionContractArtifactRefs: []string{"paca-old"},
	}})
	currentComposition := baselineComposition
	currentComposition.ProposedActionContract = risk.CloneProposedActionContract(baselineComposition.ProposedActionContract)
	currentComposition.ProposedActionContract.LifecycleObservations = risk.NormalizeProposedActionLifecycleObservations([]risk.ProposedActionLifecycleObservation{{
		Kind: risk.LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, FreshnessState: "fresh",
		EvidenceRefs: []string{"gait:receipt"}, ProofRefs: []string{"proof:gait"}, ActionContractArtifactRefs: []string{"paca-new"},
	}})

	baseline := BuildBaseline(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{baselineComposition}}}, time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{currentComposition}}})
	category, ok := driftCategoryByName(result.DriftCategories, DriftCategoryActionContractActivationChanged)
	if !ok {
		t.Fatalf("expected lifecycle artifact-ref drift category, got %+v", result.DriftCategories)
	}
	if !containsStringValue(category.EvidenceRefs, "paca-old") || !containsStringValue(category.EvidenceRefs, "paca-new") {
		t.Fatalf("expected artifact refs in lifecycle drift evidence refs, got %+v", category.EvidenceRefs)
	}
}

func regressTestComposition(compositionID, sinkResolutionKey, targetIdentity, outcomeClass string) risk.ComposedActionPath {
	return risk.ComposedActionPath{
		CompositionID:        compositionID,
		PatternID:            risk.CompositionPatternCodeToDeploy,
		TargetIdentity:       targetIdentity,
		OutcomeKey:           "asset=" + targetIdentity + "|target_class=production_impacting|outcome=" + outcomeClass + "|environment=production",
		OutcomeClass:         outcomeClass,
		Environment:          "production",
		TargetClass:          risk.TargetClassProductionImpacting,
		RiskTier:             risk.RiskTierHigh,
		RecommendedControl:   risk.RecommendedControlApprovalRequired,
		EvidenceState:        risk.EvidenceStateDeclared,
		FreshnessState:       "fresh",
		PolicyCoverageStatus: risk.PolicyCoverageStatusMatched,
		GaitCoverage: &risk.GaitCoverage{
			PolicyDecision:    risk.GaitCoverageDetail{Status: risk.GaitStatusPresent},
			Approval:          risk.GaitCoverageDetail{Status: risk.GaitStatusPresent},
			JITCredential:     risk.GaitCoverageDetail{Status: risk.GaitStatusNotApplicable},
			FreezeWindow:      risk.GaitCoverageDetail{Status: risk.GaitStatusNotApplicable},
			KillSwitch:        risk.GaitCoverageDetail{Status: risk.GaitStatusNotApplicable},
			ActionOutcome:     risk.GaitCoverageDetail{Status: risk.GaitStatusPresent},
			ProofVerification: risk.GaitCoverageDetail{Status: risk.GaitStatusPresent},
		},
		Stages: []risk.CompositionStage{
			{
				StageID:       "stage-source",
				Role:          risk.CompositionStageRoleSource,
				ResolutionKey: "rk-source",
				ToolType:      "ci_agent",
				Location:      ".github/workflows/release.yml",
				TargetClass:   risk.TargetClassReleaseAdjacent,
			},
			{
				StageID:       "stage-sink",
				Role:          risk.CompositionStageRoleExternalSink,
				ResolutionKey: sinkResolutionKey,
				ToolType:      "ci_agent",
				Location:      ".github/workflows/release.yml",
				TargetClass:   risk.TargetClassProductionImpacting,
			},
		},
	}
}

func hasDriftCategory(categories []DriftCategorySummary, want string) bool {
	_, ok := driftCategoryByName(categories, want)
	return ok
}

func driftCategoryByName(categories []DriftCategorySummary, want string) (DriftCategorySummary, bool) {
	for _, category := range categories {
		if category.Category == want {
			return category, true
		}
	}
	return DriftCategorySummary{}, false
}
