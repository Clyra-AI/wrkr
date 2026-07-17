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
	for _, category := range categories {
		if category.Category == want {
			return true
		}
	}
	return false
}
