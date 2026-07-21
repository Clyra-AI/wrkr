package risk

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
)

func TestBuildComposedActionPathsMultiStageSupportsThreeToFiveStages(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		intermediates []ActionPath
		wantStages    int
	}{
		{name: "three", intermediates: []ActionPath{multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")}, wantStages: 3},
		{name: "four", intermediates: []ActionPath{
			multiStageCompositionTestPath("apc-ci", "rk-ci", "ci"),
			multiStageCompositionTestPath("apc-cloud", "rk-cloud", "cloud"),
		}, wantStages: 4},
		{name: "five", intermediates: []ActionPath{
			multiStageCompositionTestPath("apc-ci", "rk-ci", "ci"),
			multiStageCompositionTestPath("apc-cloud", "rk-cloud", "cloud"),
			multiStageCompositionTestPath("apc-saas", "rk-saas", "saas"),
		}, wantStages: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := multiStageCompositionEndpoint("apc-read", "rk-read", "repo", []string{"read"}, TargetClassCustomerDataAdjacent)
			sink := multiStageCompositionEndpoint("apc-send", "rk-send", "communications", []string{"egress"}, TargetClassUnknown)
			paths := append([]ActionPath{source}, tc.intermediates...)
			paths = append(paths, sink)

			compositions, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-customer-egress", paths))
			got := findCompositionByPatternAndStageCount(compositions, CompositionPatternSensitiveReadToEgressMultiStage, tc.wantStages)
			if got == nil {
				t.Fatalf("expected %d-stage composition, got %+v", tc.wantStages, compositions)
			}
			if got.Pattern.MinStages != 3 || got.Pattern.MaxStages != 5 {
				t.Fatalf("expected explicit 3-5 stage template, got %+v", got.Pattern)
			}
			if got.ReachabilityState != CompositionReachabilityPossible || got.ObservedExecution {
				t.Fatalf("static path must remain possible rather than observed, got %+v", got)
			}
			for index, stage := range got.Stages {
				if stage.SystemClass == "" || stage.TrustBoundary == "" || len(stage.CorrelationRefs) == 0 {
					t.Fatalf("stage %d missing system/trust/correlation evidence: %+v", index, stage)
				}
			}
			for index, transition := range got.Transitions {
				if transition.TrustBoundary == "" || len(transition.CorrelationRefs) == 0 || transition.ReachabilityState != CompositionReachabilityPossible {
					t.Fatalf("transition %d missing bounded reachability evidence: %+v", index, transition)
				}
			}
		})
	}
}

func TestBuildComposedActionPathsMultiStageRequiresExplicitCorrelationAcrossRepos(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	bridge := multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	bridge.Repo = "platform"
	sink := multiStageCompositionEndpoint("apc-deploy", "rk-deploy", "cloud", []string{"deploy"}, TargetClassProductionImpacting)
	sink.Repo = "delivery"
	paths := []ActionPath{source, bridge, sink}

	withoutCorrelation, _ := BuildComposedActionPaths(paths, nil)
	if got := findCompositionByPatternAndStageCount(withoutCorrelation, CompositionPatternCodeToDeployMultiStage, 3); got != nil {
		t.Fatalf("cross-repo path must not guess a join: %+v", got)
	}

	withCorrelation, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-cross-repo-deploy", paths))
	got := findCompositionByPatternAndStageCount(withCorrelation, CompositionPatternCodeToDeployMultiStage, 3)
	if got == nil {
		t.Fatalf("expected explicit cross-repo correlation to produce a composition, got %+v", withCorrelation)
	}
	if got.Stages[0].TrustBoundary == got.Stages[1].TrustBoundary || got.Stages[1].TrustBoundary == got.Stages[2].TrustBoundary {
		t.Fatalf("expected explicit trust-boundary crossings, got %+v", got.Stages)
	}
}

func TestBuildComposedActionPathsCrossSystemAcceptsImportedEvidenceJoin(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	bridge := multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	sink := multiStageCompositionEndpoint("apc-deploy", "rk-deploy", "cloud", []string{"deploy"}, TargetClassProductionImpacting)
	for _, path := range []*ActionPath{&source, &bridge, &sink} {
		path.EvidencePacketRefs = []string{"packet:verified-deploy-route"}
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, bridge, sink}, nil)
	got := findCompositionByPatternAndStageCount(compositions, CompositionPatternCodeToDeployMultiStage, 3)
	if got == nil {
		t.Fatalf("expected imported evidence to provide an explicit cross-system join, got %+v", compositions)
	}
	for _, transition := range got.Transitions {
		if !containsMultiStageString(transition.CorrelationRefs, "imported_evidence:packet:verified-deploy-route") {
			t.Fatalf("transition lost imported evidence correlation: %+v", transition)
		}
	}
}

func TestBuildComposedActionPathsCrossSystemAcceptsPriorCompositionJoin(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	bridge := multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	sink := multiStageCompositionEndpoint("apc-deploy", "rk-deploy", "cloud", []string{"deploy"}, TargetClassProductionImpacting)
	for _, path := range []*ActionPath{&source, &bridge, &sink} {
		path.CompositionIDs = []string{"cap-prior-route"}
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, bridge, sink}, nil)
	got := findCompositionByPatternAndStageCount(compositions, CompositionPatternCodeToDeployMultiStage, 3)
	if got == nil {
		t.Fatalf("expected a prior composition ref to provide an explicit cross-system join, got %+v", compositions)
	}
	for _, transition := range got.Transitions {
		if !containsMultiStageString(transition.CorrelationRefs, "composition:cap-prior-route") {
			t.Fatalf("transition lost prior-composition correlation: %+v", transition)
		}
	}
}

func TestBuildComposedActionPathsMultiStageRejectsUnknownTrustBoundaryAndWeakRefs(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	bridge := multiStageCompositionTestPath("apc-unknown", "rk-unknown", "ci")
	bridge.Repo = ""
	bridge.Org = ""
	sink := multiStageCompositionEndpoint("apc-deploy", "rk-deploy", "cloud", []string{"deploy"}, TargetClassProductionImpacting)
	paths := []ActionPath{source, bridge, sink}

	compositions, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-unknown-boundary", paths))
	if got := findCompositionByPatternAndStageCount(compositions, CompositionPatternCodeToDeployMultiStage, 3); got != nil {
		t.Fatalf("unknown trust boundaries must fail closed even with a shared workflow ref: %+v", got)
	}

	bridge = multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	bridge.EndpointRefGroupID = "shared-endpoint"
	source.EndpointRefGroupID = "shared-endpoint"
	sink.EndpointRefGroupID = "shared-endpoint"
	compositions, _ = BuildComposedActionPaths([]ActionPath{source, bridge, sink}, nil)
	if got := findCompositionByPatternAndStageCount(compositions, CompositionPatternCodeToDeployMultiStage, 3); got != nil {
		t.Fatalf("unknown boundaries and endpoint-only refs must not create a guessed join: %+v", got)
	}
}

func TestBuildComposedActionPathsMultiStageRejectsMalformedCorrelationRefs(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	bridge := multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	sink := multiStageCompositionEndpoint("apc-deploy", "rk-deploy", "cloud", []string{"deploy"}, TargetClassProductionImpacting)
	for _, path := range []*ActionPath{&source, &bridge, &sink} {
		path.WorkflowChainRefs = []string{"../../private/customer-path"}
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, bridge, sink}, nil)
	if got := findCompositionByPatternAndStageCount(compositions, CompositionPatternCodeToDeployMultiStage, 3); got != nil {
		t.Fatalf("malformed correlation refs must fail closed: %+v", got)
	}
}

func TestBuildComposedActionPathsMultiStageRepeatedTrustBoundariesStayDeduplicated(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"read_sensitive"}, TargetClassCustomerDataAdjacent)
	bridgeA := multiStageCompositionTestPath("apc-ci-a", "rk-ci-a", "ci")
	bridgeB := multiStageCompositionTestPath("apc-ci-b", "rk-ci-b", "ci")
	sink := multiStageCompositionEndpoint("apc-send", "rk-send", "communications", []string{"external_write", "egress"}, TargetClassProductionImpacting)
	paths := []ActionPath{source, bridgeA, bridgeB, sink}

	compositions, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-repeated-boundary", paths))
	for _, composition := range compositions {
		if composition.PatternID != CompositionPatternSensitiveReadToEgressMultiStage {
			continue
		}
		for index := 1; index < len(composition.Stages); index++ {
			if composition.Stages[index-1].TrustBoundary == composition.Stages[index].TrustBoundary {
				t.Fatalf("repeated boundary aliases must not expand into a cycle: %+v", composition.Stages)
			}
		}
	}

	codeSource := multiStageCompositionEndpoint("apc-code", "rk-code", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	ciTransform := multiStageCompositionTestPath("apc-ci-transform", "rk-ci-transform", "ci")
	ciSink := multiStageCompositionEndpoint("apc-ci-deploy", "rk-ci-deploy", "ci", []string{"deploy"}, TargetClassProductionImpacting)
	sameBoundaryPaths := []ActionPath{codeSource, ciTransform, ciSink}
	sameBoundary, _ := BuildComposedActionPaths(sameBoundaryPaths, multiStageWorkflowArtifact("wfc-repeated-ci-boundary", sameBoundaryPaths))
	if got := findCompositionByPatternAndStageCount(sameBoundary, CompositionPatternCodeToDeployMultiStage, 3); got != nil {
		t.Fatalf("a repeated system/trust boundary must not be inflated into a cross-system route: %+v", got)
	}
}

func TestBuildComposedActionPathsMultiStageCorrelationRefsAreBounded(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"write"}, TargetClassReleaseAdjacent)
	bridge := multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	sink := multiStageCompositionEndpoint("apc-deploy", "rk-deploy", "cloud", []string{"deploy"}, TargetClassProductionImpacting)
	for index := 0; index < maxMultiStageCorrelationRefs+4; index++ {
		ref := fmt.Sprintf("policy:shared-route-%02d", index)
		for _, path := range []*ActionPath{&source, &bridge, &sink} {
			path.PolicyRefs = append(path.PolicyRefs, ref)
		}
	}
	for _, path := range []*ActionPath{&source, &bridge, &sink} {
		path.WorkflowChainRefs = []string{"zz-strong-route"}
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, bridge, sink}, nil)
	got := findCompositionByPatternAndStageCount(compositions, CompositionPatternCodeToDeployMultiStage, 3)
	if got == nil {
		t.Fatalf("expected bounded correlated route, got %+v", compositions)
	}
	for _, transition := range got.Transitions {
		if len(transition.CorrelationRefs) > maxMultiStageCorrelationRefs {
			t.Fatalf("transition correlation refs exceeded cap: %+v", transition)
		}
		if !containsMultiStageString(transition.CorrelationRefs, "workflow_chain:zz-strong-route") {
			t.Fatalf("reference capping must preserve a strong transition join: %+v", transition)
		}
	}
	if !compositionHasTruncationReason(*got, CompositionTruncationReferenceCap) {
		t.Fatalf("expected explicit reference-cap truncation metadata: %+v", got.Truncations)
	}
}

func TestBuildComposedActionPathsMultiStageMissingMiddleEvidenceAndCyclesFailClosed(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-read", "rk-read", "repo", []string{"read"}, TargetClassCustomerDataAdjacent)
	bridge := multiStageCompositionTestPath("apc-ci", "rk-ci", "ci")
	duplicateBridge := multiStageCompositionTestPath("apc-ci-duplicate", "rk-ci", "ci")
	sink := multiStageCompositionEndpoint("apc-send", "rk-send", "communications", []string{"egress"}, TargetClassUnknown)

	chains := &agentresolver.WorkflowChainArtifact{Chains: []agentresolver.WorkflowChain{
		{ChainID: "wfc-left", PathIDs: []string{source.PathID, bridge.PathID, duplicateBridge.PathID}},
		{ChainID: "wfc-right", PathIDs: []string{sink.PathID}},
	}}
	compositions, _ := BuildComposedActionPaths([]ActionPath{source, bridge, duplicateBridge, sink}, chains)
	if got := findCompositionByPatternAndStageCount(compositions, CompositionPatternSensitiveReadToEgressMultiStage, 3); got != nil {
		t.Fatalf("missing middle-to-sink evidence must not be guessed, got %+v", got)
	}

	correlated := multiStageWorkflowArtifact("wfc-cycle-safe", []ActionPath{source, bridge, duplicateBridge, sink})
	compositions, _ = BuildComposedActionPaths([]ActionPath{duplicateBridge, sink, bridge, source}, correlated)
	for _, composition := range compositions {
		if composition.PatternID != CompositionPatternSensitiveReadToEgressMultiStage {
			continue
		}
		seen := map[string]struct{}{}
		for _, stage := range composition.Stages {
			if _, ok := seen[stage.ResolutionKey]; ok {
				t.Fatalf("duplicate/cycle candidate appeared twice in one path: %+v", composition.Stages)
			}
			seen[stage.ResolutionKey] = struct{}{}
		}
		if len(composition.Stages) > maxMultiStageCompositionDepth {
			t.Fatalf("composition exceeded depth cap: %+v", composition)
		}
	}
}

func TestBuildComposedActionPathsMultiStageStableIdentityAlternatesAndObservation(t *testing.T) {
	t.Parallel()

	source := multiStageCompositionEndpoint("apc-read", "rk-read", "repo", []string{"read"}, TargetClassCustomerDataAdjacent)
	ciA := multiStageCompositionTestPath("apc-ci-a", "rk-ci-a", "ci")
	ciB := multiStageCompositionTestPath("apc-ci-b", "rk-ci-b", "ci")
	sink := multiStageCompositionEndpoint("apc-send", "rk-send", "communications", []string{"egress"}, TargetClassUnknown)
	paths := []ActionPath{source, ciA, ciB, sink}
	chains := multiStageWorkflowArtifact("wfc-alternates", paths)

	first, _ := BuildComposedActionPaths(paths, chains)
	permuted := []ActionPath{sink, ciB, source, ciA}
	second, _ := BuildComposedActionPaths(permuted, chains)
	firstIDs := multiStageCompositionIDs(first, CompositionPatternSensitiveReadToEgressMultiStage)
	secondIDs := multiStageCompositionIDs(second, CompositionPatternSensitiveReadToEgressMultiStage)
	if !reflect.DeepEqual(firstIDs, secondIDs) {
		t.Fatalf("multi-stage ids changed under input permutation: %v != %v", firstIDs, secondIDs)
	}
	volatileIDChurn := append([]ActionPath(nil), paths...)
	for index := range volatileIDChurn {
		volatileIDChurn[index].PathID = "apc-rerun-" + string(rune('a'+index))
	}
	churned, _ := BuildComposedActionPaths(volatileIDChurn, multiStageWorkflowArtifact("wfc-alternates", volatileIDChurn))
	churnedIDs := multiStageCompositionIDs(churned, CompositionPatternSensitiveReadToEgressMultiStage)
	if !reflect.DeepEqual(firstIDs, churnedIDs) {
		t.Fatalf("volatile path-id churn changed stable composition ids: %v != %v", firstIDs, churnedIDs)
	}
	if !reflect.DeepEqual(multiStageCompositionStageIDs(first, CompositionPatternSensitiveReadToEgressMultiStage), multiStageCompositionStageIDs(churned, CompositionPatternSensitiveReadToEgressMultiStage)) {
		t.Fatalf("volatile path-id churn changed ordered stage ids")
	}
	if len(firstIDs) < 2 {
		t.Fatalf("expected alternate routes, got %v", firstIDs)
	}
	for _, composition := range first {
		if composition.PatternID == CompositionPatternSensitiveReadToEgressMultiStage && len(composition.AlternateRouteRefs) == 0 {
			t.Fatalf("expected alternate route refs, got %+v", composition)
		}
	}
	decorated := DecorateActionPathCompositionRefs(paths, first)
	for _, path := range decorated {
		if len(path.CompositionIDs) == 0 || len(path.ProposedActionContractRefs) == 0 {
			t.Fatalf("every bounded route member must carry proof/evidence join refs, got %+v", path)
		}
	}

	observedPaths := append([]ActionPath(nil), paths...)
	for index := range observedPaths {
		observedPaths[index].RuntimeEvidenceState = EvidenceStateVerified
		observedPaths[index].GaitCoverage.ActionOutcome = GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:" + observedPaths[index].ResolutionKey}}
	}
	observed, _ := BuildComposedActionPaths(observedPaths, chains)
	got := findCompositionByPatternAndStageCount(observed, CompositionPatternSensitiveReadToEgressMultiStage, 3)
	if got == nil || !got.ObservedExecution || got.ReachabilityState != CompositionReachabilityObserved || got.ClaimState != CompositionClaimObservedExecution {
		t.Fatalf("all-stage runtime proof must be required for observed execution, got %+v", got)
	}
	if got.ProposedActionContract == nil || got.ProposedActionContract.ContractVersion != ProposedActionContractVersionV3 {
		t.Fatalf("multi-stage paths must use the version 3 proposed Action Contract, got %+v", got.ProposedActionContract)
	}
	for _, want := range []ProposedActionTargetConstraint{
		{Key: "reachability_state", Value: CompositionReachabilityObserved},
		{Key: "observed_execution", Value: "true"},
		{Key: "system_class_sequence", Value: "repo->ci->communications"},
	} {
		if !containsProposedTargetConstraint(got.ProposedActionContract.TargetConstraints, want) {
			t.Fatalf("multi-stage contract missing target constraint %+v: %+v", want, got.ProposedActionContract.TargetConstraints)
		}
	}
	for _, want := range []string{"transition_correlation", "trust_boundary_evidence"} {
		if !containsMultiStageString(got.ProposedActionContract.EvidenceRequirements, want) {
			t.Fatalf("multi-stage contract missing evidence requirement %q: %v", want, got.ProposedActionContract.EvidenceRequirements)
		}
	}
	partiallyObservedPaths := append([]ActionPath(nil), observedPaths...)
	partiallyObservedPaths[1].RuntimeEvidenceState = EvidenceStateUnknown
	partiallyObservedPaths[1].GaitCoverage = CloneGaitCoverage(partiallyObservedPaths[1].GaitCoverage)
	partiallyObservedPaths[1].GaitCoverage.ActionOutcome = GaitCoverageDetail{Status: GaitStatusMissing}
	partiallyObserved, _ := BuildComposedActionPaths(partiallyObservedPaths, chains)
	partial := findCompositionByPatternAndStageCount(partiallyObserved, CompositionPatternSensitiveReadToEgressMultiStage, 3)
	if partial == nil || partial.ObservedExecution || partial.ReachabilityState != CompositionReachabilityPossible || partial.ClaimState == CompositionClaimObservedExecution {
		t.Fatalf("partial stage runtime evidence must remain possible rather than observed: %+v", partial)
	}

	changed := append([]ActionPath(nil), paths...)
	changed[1].ActionClasses = append(changed[1].ActionClasses, "material_effect_change")
	changedCompositions, _ := BuildComposedActionPaths(changed, chains)
	changedIDs := multiStageCompositionIDs(changedCompositions, CompositionPatternSensitiveReadToEgressMultiStage)
	if reflect.DeepEqual(firstIDs, changedIDs) {
		t.Fatalf("material stage semantics must change stable ids: %v", firstIDs)
	}
}

func TestBuildComposedActionPathsMultiStageDepthAndCandidateCapsAreExplicit(t *testing.T) {
	t.Parallel()

	paths := []ActionPath{multiStageCompositionEndpoint("apc-read", "rk-read", "repo", []string{"read"}, TargetClassCustomerDataAdjacent)}
	for index := 0; index < maxMultiStageCompositionDepth+3; index++ {
		systemClass := "ci"
		if index > 1 {
			systemClass = "cloud"
		}
		path := multiStageCompositionTestPath("apc-bridge-"+string(rune('a'+index)), "rk-bridge-"+string(rune('a'+index)), systemClass)
		paths = append(paths, path)
	}
	paths = append(paths, multiStageCompositionEndpoint("apc-send", "rk-send", "communications", []string{"egress"}, TargetClassUnknown))

	compositions, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-depth-cap", paths))
	var sawTruncation bool
	for _, composition := range compositions {
		if composition.PatternID != CompositionPatternSensitiveReadToEgressMultiStage {
			continue
		}
		if len(composition.Stages) > maxMultiStageCompositionDepth {
			t.Fatalf("composition exceeded depth cap: %+v", composition)
		}
		for _, truncation := range composition.Truncations {
			if truncation.Reason == CompositionTruncationDepthCap || truncation.Reason == CompositionTruncationCandidateCap {
				sawTruncation = true
			}
		}
	}
	if !sawTruncation {
		t.Fatalf("expected explicit deterministic depth/candidate truncation metadata, got %+v", compositions)
	}
	permuted := append([]ActionPath(nil), paths...)
	for left, right := 0, len(permuted)-1; left < right; left, right = left+1, right-1 {
		permuted[left], permuted[right] = permuted[right], permuted[left]
	}
	permutedCompositions, _ := BuildComposedActionPaths(permuted, multiStageWorkflowArtifact("wfc-depth-cap", permuted))
	if !reflect.DeepEqual(compositions, permutedCompositions) {
		t.Fatalf("capped multi-stage output changed under input permutation\nfirst=%+v\nsecond=%+v", compositions, permutedCompositions)
	}
}

func TestBuildComposedActionPathsMultiStageOverDepthRouteTruncatesExplicitly(t *testing.T) {
	t.Parallel()

	paths := []ActionPath{
		multiStageCompositionEndpoint("apc-read", "rk-read", "repo", []string{"read_sensitive"}, TargetClassCustomerDataAdjacent),
		multiStageCompositionTestPath("apc-ci", "rk-ci", "ci"),
		multiStageCompositionTestPath("apc-package", "rk-package", "package"),
		multiStageCompositionTestPath("apc-cloud", "rk-cloud", "cloud"),
		multiStageCompositionTestPath("apc-saas", "rk-saas", "saas"),
		multiStageCompositionEndpoint("apc-send", "rk-send", "communications", []string{"external_write", "egress"}, TargetClassProductionImpacting),
	}
	compositions, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-over-depth", paths))
	for _, composition := range compositions {
		if composition.PatternID == CompositionPatternSensitiveReadToEgressMultiStage && len(composition.Stages) > maxMultiStageCompositionDepth {
			t.Fatalf("over-depth route must not be emitted: %+v", composition)
		}
	}
	if !compositionsHaveTruncationReason(compositions, CompositionPatternSensitiveReadToEgressMultiStage, CompositionTruncationDepthCap) {
		t.Fatalf("over-depth route must emit depth-cap metadata: %+v", compositions)
	}
}

func TestBuildComposedActionPathsMultiStageDefaultProjectionSizeAndNoiseBudget(t *testing.T) {
	t.Parallel()

	paths := []ActionPath{multiStageCompositionEndpoint("apc-source", "rk-source", "repo", []string{"read_sensitive"}, TargetClassCustomerDataAdjacent)}
	for _, systemClass := range []string{"ci", "cloud", "saas"} {
		for index := 0; index < 12; index++ {
			paths = append(paths, multiStageCompositionTestPath(
				fmt.Sprintf("apc-%s-%02d", systemClass, index),
				fmt.Sprintf("rk-%s-%02d", systemClass, index),
				systemClass,
			))
		}
	}
	paths = append(paths, multiStageCompositionEndpoint("apc-sink", "rk-sink", "communications", []string{"external_write", "egress"}, TargetClassProductionImpacting))

	compositions, _ := BuildComposedActionPaths(paths, multiStageWorkflowArtifact("wfc-high-fanout", paths))
	summary := SummarizeComposedActionPaths(compositions)
	if summary.MultiStageCompositions > len(multiStageCompositionPatternSpecs())*maxMultiStageCompositionPathsPerPattern {
		t.Fatalf("multi-stage projection exceeded the configured per-pattern output cap: %+v", summary)
	}
	if summary.TruncatedCandidatePatterns == 0 {
		t.Fatalf("high-fan-out projection must expose cap truncation in the summary: %+v", summary)
	}
	if !compositionsHaveTruncationReason(compositions, CompositionPatternSensitiveReadToEgressMultiStage, CompositionTruncationPathCap) {
		t.Fatalf("high-fan-out projection must expose the per-pattern path cap: %+v", compositions)
	}
	payload, err := json.Marshal(compositions)
	if err != nil {
		t.Fatalf("marshal bounded multi-stage projection: %v", err)
	}
	const projectionBudget = 4 * 1024 * 1024
	if len(payload) > projectionBudget {
		t.Fatalf("bounded multi-stage projection exceeded default-output byte budget: bytes=%d budget=%d", len(payload), projectionBudget)
	}
	pairwise := make([]ComposedActionPath, 0, len(compositions)-summary.MultiStageCompositions)
	for _, composition := range compositions {
		if composition.ReachabilityState == "" {
			pairwise = append(pairwise, composition)
		}
	}
	pairwisePayload, err := json.Marshal(pairwise)
	if err != nil {
		t.Fatalf("marshal pairwise comparison projection: %v", err)
	}
	delta := len(payload) - len(pairwisePayload)
	const multiStageDeltaBudget = 512 * 1024
	if delta > multiStageDeltaBudget {
		t.Fatalf("multi-stage default projection delta exceeded budget: delta=%d budget=%d", delta, multiStageDeltaBudget)
	}
	t.Logf("bounded-multi-stage-projection measured_bytes=%d pairwise_bytes=%d delta_bytes=%d total_compositions=%d multi_stage_compositions=%d", len(payload), len(pairwisePayload), delta, summary.TotalCompositions, summary.MultiStageCompositions)
}

func TestBuildComposedActionPathsReachabilityStatesRemainDistinct(t *testing.T) {
	t.Parallel()

	static := ComposedActionPath{
		CompositionID: "cap-static", PatternID: CompositionPatternCodeToDeployMultiStage,
		Stages:     []CompositionStage{{StageID: "source", Role: CompositionStageRoleSource}, {StageID: "middle", Role: CompositionStageRoleTransform}, {StageID: "sink", Role: CompositionStageRolePrivilegedSink}},
		ClaimState: CompositionClaimStaticOnly, ReachabilityState: CompositionReachabilityPossible,
	}
	incomplete := static
	incomplete.CompositionID = "cap-incomplete"
	incomplete.ReachabilityState = CompositionReachabilityIncomplete
	observed := static
	observed.CompositionID = "cap-observed"
	observed.ClaimState = CompositionClaimObservedExecution
	observed.ReachabilityState = CompositionReachabilityObserved
	observed.ObservedExecution = true

	if static.ClaimState == static.ReachabilityState || incomplete.ReachabilityState == static.ReachabilityState || observed.ReachabilityState == static.ReachabilityState {
		t.Fatalf("static claim and possible/incomplete/observed reachability must remain distinct: static=%+v incomplete=%+v observed=%+v", static, incomplete, observed)
	}
	contract := BuildProposedActionContract(incomplete)
	if contract == nil || !containsMultiStageString(contract.ReasonCodes, "readiness:needs_composition_correlation") {
		t.Fatalf("incomplete reachability must remain a visible contract evidence gap: %+v", contract)
	}
}

func multiStageCompositionTestPath(pathID, resolutionKey, systemClass string) ActionPath {
	return multiStageCompositionEndpoint(pathID, resolutionKey, systemClass, []string{"write", "transform"}, TargetClassReleaseAdjacent)
}

func multiStageCompositionEndpoint(pathID, resolutionKey, systemClass string, actionClasses []string, targetClass string) ActionPath {
	path := compositionTestPath(pathID, resolutionKey, actionClasses, targetClass)
	switch systemClass {
	case "repo":
		path.ToolType = "codex"
		path.Location = ".codex/config.toml"
		path.WriteCapable = true
	case "ci":
		path.ToolType = "github_actions"
		path.Location = ".github/workflows/build.yml"
	case "package":
		path.ToolType = "package_registry"
		path.Location = "registry://package"
	case "cloud":
		path.ToolType = "mcp_aws_lambda"
		path.Location = "cloud://lambda/deploy"
	case "saas":
		path.ToolType = "mcp_saas_connector"
		path.Location = "saas://change-management"
	case "communications":
		path.ToolType = "mcp_webhook"
		path.Location = "https://notifications.example.invalid/hook"
		path.WriteCapable = true
	}
	return path
}

func multiStageWorkflowArtifact(chainID string, paths []ActionPath) *agentresolver.WorkflowChainArtifact {
	pathIDs := make([]string, 0, len(paths))
	for _, path := range paths {
		pathIDs = append(pathIDs, path.PathID)
	}
	sort.Strings(pathIDs)
	return &agentresolver.WorkflowChainArtifact{Chains: []agentresolver.WorkflowChain{{ChainID: chainID, PathIDs: pathIDs}}}
}

func findCompositionByPatternAndStageCount(paths []ComposedActionPath, patternID string, stageCount int) *ComposedActionPath {
	for index := range paths {
		if paths[index].PatternID == patternID && len(paths[index].Stages) == stageCount {
			return &paths[index]
		}
	}
	return nil
}

func multiStageCompositionIDs(paths []ComposedActionPath, patternID string) []string {
	ids := []string{}
	for _, path := range paths {
		if path.PatternID == patternID {
			ids = append(ids, path.CompositionID)
		}
	}
	sort.Strings(ids)
	return ids
}

func multiStageCompositionStageIDs(paths []ComposedActionPath, patternID string) [][]string {
	out := [][]string{}
	for _, path := range paths {
		if path.PatternID != patternID {
			continue
		}
		stageIDs := make([]string, 0, len(path.Stages))
		for _, stage := range path.Stages {
			stageIDs = append(stageIDs, stage.StageID)
		}
		out = append(out, stageIDs)
	}
	return out
}

func containsProposedTargetConstraint(values []ProposedActionTargetConstraint, want ProposedActionTargetConstraint) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsMultiStageString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func compositionHasTruncationReason(composition ComposedActionPath, reason string) bool {
	for _, truncation := range composition.Truncations {
		if truncation.Reason == reason {
			return true
		}
	}
	return false
}

func compositionsHaveTruncationReason(compositions []ComposedActionPath, patternID, reason string) bool {
	for _, composition := range compositions {
		if composition.PatternID == patternID && compositionHasTruncationReason(composition, reason) {
			return true
		}
	}
	return false
}
