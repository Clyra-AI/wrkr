package regress

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

type CompositionState struct {
	CompositionID             string   `json:"composition_id,omitempty"`
	CompositionFamilyKey      string   `json:"composition_family_key,omitempty"`
	PatternID                 string   `json:"pattern_id,omitempty"`
	StageRoles                []string `json:"stage_roles,omitempty"`
	MemberResolutionKeys      []string `json:"member_resolution_keys,omitempty"`
	StableRouteSourceIdentity string   `json:"stable_route_source_identity,omitempty"`
	TargetIdentity            string   `json:"target_identity,omitempty"`
	OutcomeKey                string   `json:"outcome_key,omitempty"`
	OutcomeClass              string   `json:"outcome_class,omitempty"`
	Environment               string   `json:"environment,omitempty"`
	RiskTier                  string   `json:"risk_tier,omitempty"`
	RecommendedControl        string   `json:"recommended_control,omitempty"`
	EvidenceState             string   `json:"evidence_state,omitempty"`
	FreshnessState            string   `json:"freshness_state,omitempty"`
	PolicyCoverageStatus      string   `json:"policy_coverage_status,omitempty"`
	GaitCoverageSummary       []string `json:"gait_coverage_summary,omitempty"`
	DelegationRelationships   []string `json:"delegation_relationships,omitempty"`
	EquivalentOutcomeRefs     []string `json:"equivalent_outcome_refs,omitempty"`
	SinkStageKeys             []string `json:"sink_stage_keys,omitempty"`
	PathIDs                   []string `json:"path_ids,omitempty"`
	EvidenceRefs              []string `json:"evidence_refs,omitempty"`
	OrderedStageSemantics     []string `json:"ordered_stage_semantics,omitempty"`
	ReachabilityState         string   `json:"reachability_state,omitempty"`
	ObservedExecution         bool     `json:"observed_execution,omitempty"`
	CorrelationRefs           []string `json:"correlation_refs,omitempty"`
	AlternateRouteRefs        []string `json:"alternate_route_refs,omitempty"`
	ActionContractID          string   `json:"action_contract_id,omitempty"`
	ActionContractFamilyID    string   `json:"action_contract_family_id,omitempty"`
	ActionContractRevision    int      `json:"action_contract_revision,omitempty"`
	ActionContractSupersedes  string   `json:"action_contract_supersedes,omitempty"`
	ActionContractDigest      string   `json:"action_contract_digest,omitempty"`
	ContractActivation        []string `json:"action_contract_activation,omitempty"`
	ContractRejection         []string `json:"action_contract_rejection,omitempty"`
	ContractExecutionEffect   []string `json:"action_contract_execution_effect,omitempty"`
	ContractVerification      []string `json:"action_contract_verification,omitempty"`
}

type compositionPair struct {
	Baseline CompositionState
	Current  CompositionState
}

func snapshotCompositionStates(snapshot state.Snapshot) ([]CompositionState, bool) {
	compositions, ok := snapshotComparableCompositions(snapshot)
	if !ok {
		return nil, false
	}
	states := make([]CompositionState, 0, len(compositions))
	for _, composition := range compositions {
		states = append(states, newCompositionState(composition))
	}
	sortCompositionStates(states)
	return states, true
}

func snapshotComparableCompositions(snapshot state.Snapshot) ([]risk.ComposedActionPath, bool) {
	if snapshot.RiskReport != nil {
		if len(snapshot.RiskReport.ComposedActionPaths) > 0 {
			return append([]risk.ComposedActionPath(nil), snapshot.RiskReport.ComposedActionPaths...), true
		}
		if len(snapshot.RiskReport.ActionPaths) > 0 {
			compositions, _ := risk.BuildComposedActionPaths(snapshot.RiskReport.ActionPaths, snapshot.RiskReport.WorkflowChains)
			return compositions, true
		}
		if snapshot.Inventory != nil {
			paths, _ := risk.BuildActionPaths(snapshot.RiskReport.AttackPaths, snapshot.Inventory)
			compositions, _ := risk.BuildComposedActionPaths(paths, snapshot.RiskReport.WorkflowChains)
			return compositions, true
		}
		// Older saved states can carry a risk report while omitting comparable
		// composition material entirely. Treat that as unavailable so drift
		// review fails closed instead of comparing against a synthetic empty set.
		return nil, false
	}
	if snapshot.Inventory != nil {
		paths, _ := risk.BuildActionPaths(nil, snapshot.Inventory)
		compositions, _ := risk.BuildComposedActionPaths(paths, nil)
		return compositions, true
	}
	return nil, false
}

func newCompositionState(composition risk.ComposedActionPath) CompositionState {
	out := CompositionState{
		CompositionID:             strings.TrimSpace(composition.CompositionID),
		PatternID:                 strings.TrimSpace(composition.PatternID),
		StageRoles:                compositionStageRoles(composition),
		MemberResolutionKeys:      compositionMemberResolutionKeys(composition),
		StableRouteSourceIdentity: compositionRouteSourceIdentity(composition),
		TargetIdentity:            strings.TrimSpace(composition.TargetIdentity),
		OutcomeKey:                firstNonEmptyString(strings.TrimSpace(composition.OutcomeKey), strings.TrimSpace(composition.DurableOutcomeKey)),
		OutcomeClass:              strings.TrimSpace(composition.OutcomeClass),
		Environment:               strings.TrimSpace(composition.Environment),
		RiskTier:                  strings.TrimSpace(composition.RiskTier),
		RecommendedControl:        strings.TrimSpace(composition.RecommendedControl),
		EvidenceState:             strings.TrimSpace(composition.EvidenceState),
		FreshnessState:            strings.TrimSpace(composition.FreshnessState),
		PolicyCoverageStatus:      strings.TrimSpace(composition.PolicyCoverageStatus),
		GaitCoverageSummary:       compositionGaitCoverageSummary(composition.GaitCoverage),
		DelegationRelationships:   compositionDelegationRelationships(composition),
		EquivalentOutcomeRefs:     mergeSortedStrings(composition.EquivalentOutcomeRefs, nil),
		SinkStageKeys:             compositionSinkStageKeys(composition),
		PathIDs:                   mergeSortedStrings(composition.PathIDs, nil),
		EvidenceRefs:              mergeSortedStrings(append(append([]string(nil), composition.EvidenceRefs...), composition.ProofRefs...), nil),
		OrderedStageSemantics:     compositionOrderedStageSemantics(composition),
		ReachabilityState:         strings.TrimSpace(composition.ReachabilityState),
		ObservedExecution:         composition.ObservedExecution,
		CorrelationRefs:           compositionCorrelationRefs(composition),
		AlternateRouteRefs:        mergeSortedStrings(composition.AlternateRouteRefs, nil),
	}
	if contract := composition.ProposedActionContract; contract != nil {
		out.ActionContractID = strings.TrimSpace(contract.ContractID)
		out.ActionContractFamilyID = strings.TrimSpace(contract.ContractFamilyID)
		out.ActionContractRevision = contract.Revision
		out.ActionContractSupersedes = strings.TrimSpace(contract.SupersedesRef)
		out.ActionContractDigest = strings.TrimSpace(contract.ContractContentDigest)
		for _, observation := range contract.LifecycleObservations {
			value := lifecycleObservationDriftValue(observation)
			switch observation.Kind {
			case risk.LifecycleObservationActivationRequest, risk.LifecycleObservationActivationReceipt:
				out.ContractActivation = append(out.ContractActivation, value)
			case risk.LifecycleObservationRejection:
				out.ContractRejection = append(out.ContractRejection, value)
			case risk.LifecycleObservationExecution, risk.LifecycleObservationEffect:
				out.ContractExecutionEffect = append(out.ContractExecutionEffect, value)
			case risk.LifecycleObservationAxymVerification:
				out.ContractVerification = append(out.ContractVerification, value)
			}
			out.EvidenceRefs = append(out.EvidenceRefs, observation.EvidenceRefs...)
			out.EvidenceRefs = append(out.EvidenceRefs, observation.ActionContractArtifactRefs...)
			out.EvidenceRefs = append(out.EvidenceRefs, observation.ProofRefs...)
		}
	}
	out.CompositionFamilyKey = compositionFamilyKey(out)
	return normalizeCompositionState(out)
}

func normalizeCompositionState(in CompositionState) CompositionState {
	in.CompositionID = strings.TrimSpace(in.CompositionID)
	in.CompositionFamilyKey = strings.TrimSpace(in.CompositionFamilyKey)
	in.PatternID = strings.TrimSpace(in.PatternID)
	in.StageRoles = mergeSortedStrings(in.StageRoles, nil)
	in.MemberResolutionKeys = mergeSortedStrings(in.MemberResolutionKeys, nil)
	in.StableRouteSourceIdentity = strings.TrimSpace(in.StableRouteSourceIdentity)
	in.TargetIdentity = strings.TrimSpace(in.TargetIdentity)
	in.OutcomeKey = strings.TrimSpace(in.OutcomeKey)
	in.OutcomeClass = strings.TrimSpace(in.OutcomeClass)
	in.Environment = strings.TrimSpace(in.Environment)
	in.RiskTier = strings.TrimSpace(in.RiskTier)
	in.RecommendedControl = strings.TrimSpace(in.RecommendedControl)
	in.EvidenceState = strings.TrimSpace(in.EvidenceState)
	in.FreshnessState = strings.TrimSpace(in.FreshnessState)
	in.PolicyCoverageStatus = strings.TrimSpace(in.PolicyCoverageStatus)
	in.GaitCoverageSummary = mergeSortedStrings(in.GaitCoverageSummary, nil)
	in.DelegationRelationships = mergeSortedStrings(in.DelegationRelationships, nil)
	in.EquivalentOutcomeRefs = mergeSortedStrings(in.EquivalentOutcomeRefs, nil)
	in.SinkStageKeys = mergeSortedStrings(in.SinkStageKeys, nil)
	in.PathIDs = mergeSortedStrings(in.PathIDs, nil)
	in.EvidenceRefs = mergeSortedStrings(in.EvidenceRefs, nil)
	in.OrderedStageSemantics = append([]string(nil), in.OrderedStageSemantics...)
	in.ReachabilityState = strings.TrimSpace(in.ReachabilityState)
	in.CorrelationRefs = mergeSortedStrings(in.CorrelationRefs, nil)
	in.AlternateRouteRefs = mergeSortedStrings(in.AlternateRouteRefs, nil)
	in.ActionContractID = strings.TrimSpace(in.ActionContractID)
	in.ActionContractFamilyID = strings.TrimSpace(in.ActionContractFamilyID)
	in.ActionContractSupersedes = strings.TrimSpace(in.ActionContractSupersedes)
	in.ActionContractDigest = strings.TrimSpace(in.ActionContractDigest)
	in.ContractActivation = mergeSortedStrings(in.ContractActivation, nil)
	in.ContractRejection = mergeSortedStrings(in.ContractRejection, nil)
	in.ContractExecutionEffect = mergeSortedStrings(in.ContractExecutionEffect, nil)
	in.ContractVerification = mergeSortedStrings(in.ContractVerification, nil)
	if in.CompositionFamilyKey == "" {
		in.CompositionFamilyKey = compositionFamilyKey(in)
	}
	return in
}

func compositionFamilyKey(state CompositionState) string {
	parts := []string{
		"pattern=" + strings.TrimSpace(state.PatternID),
		"roles=" + strings.Join(mergeSortedStrings(state.StageRoles, nil), ","),
		"target=" + strings.TrimSpace(state.TargetIdentity),
		"route=" + strings.TrimSpace(state.StableRouteSourceIdentity),
	}
	if len(state.OrderedStageSemantics) > 0 {
		parts = append(parts, "ordered="+strings.Join(state.OrderedStageSemantics, ","))
	}
	return strings.Join(parts, "|")
}

func sortCompositionStates(values []CompositionState) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].CompositionFamilyKey != values[j].CompositionFamilyKey {
			return values[i].CompositionFamilyKey < values[j].CompositionFamilyKey
		}
		if values[i].CompositionID != values[j].CompositionID {
			return values[i].CompositionID < values[j].CompositionID
		}
		return values[i].OutcomeKey < values[j].OutcomeKey
	})
}

func compareCompositionDrift(baseline Baseline, current state.Snapshot) ([]DriftCategorySummary, string, []string) {
	currentStates, currentCaptured := snapshotCompositionStates(current)
	if !baseline.CompositionsCaptured {
		if !currentCaptured || len(currentStates) == 0 {
			return nil, "", nil
		}
		return nil, DriftComparisonStatusBaselineCompositionsMissing, []string{
			"baseline composition comparison data is unavailable; regenerate the regress baseline from a current Wrkr scan snapshot",
		}
	}
	if !currentCaptured {
		return nil, DriftComparisonStatusCurrentCompositionsMissing, []string{
			"current scan state does not carry comparable composition data; rerun scan before drift review",
		}
	}

	baseStates := make([]CompositionState, 0, len(baseline.Compositions))
	for _, item := range baseline.Compositions {
		baseStates = append(baseStates, normalizeCompositionState(item))
	}
	sortCompositionStates(baseStates)

	pairs, unmatchedCurrent, unmatchedBaseline, issues := matchCompositionStates(baseStates, currentStates)
	buckets := makeDriftBuckets()
	for _, currentState := range unmatchedCurrent {
		addCompositionDriftCategoryExample(buckets[DriftCategoryIntroducedCompositions], currentState, CompositionState{}, "new composed authority path appeared since baseline")
		if compositionAlternateOutcomeExists(currentState, baseStates) {
			addCompositionDriftCategoryExample(buckets[DriftCategoryAlternateRouteAppeared], currentState, CompositionState{}, "alternate route to an existing outcome appeared since baseline")
		}
	}
	for _, baselineState := range unmatchedBaseline {
		addCompositionDriftCategoryExample(buckets[DriftCategoryRemovedCompositions], CompositionState{}, baselineState, "baseline composition is no longer present in the current scan")
	}
	for _, pair := range pairs {
		addMatchedCompositionDriftExamples(buckets, pair)
	}

	status := DriftComparisonStatusOK
	if len(issues) > 0 {
		status = DriftComparisonStatusIncomplete
	}
	return finalizeDriftBuckets(buckets), status, uniqueSortedStrings(issues)
}

func matchCompositionStates(baseline []CompositionState, current []CompositionState) ([]compositionPair, []CompositionState, []CompositionState, []string) {
	issues := []string{}
	pairs := []compositionPair{}
	baselineMatched := make([]bool, len(baseline))
	currentMatched := make([]bool, len(current))

	currentByFamily := map[string][]int{}
	for idx, item := range current {
		currentByFamily[strings.TrimSpace(item.CompositionFamilyKey)] = append(currentByFamily[strings.TrimSpace(item.CompositionFamilyKey)], idx)
	}
	for baseIdx, base := range baseline {
		family := strings.TrimSpace(base.CompositionFamilyKey)
		if family == "" {
			issues = append(issues, "baseline composition missing normalized family key:"+strings.TrimSpace(base.CompositionID))
			continue
		}
		bestScore := -1
		bestIndexes := []int{}
		for _, currentIdx := range currentByFamily[family] {
			if currentMatched[currentIdx] {
				continue
			}
			score := compositionPairScore(base, current[currentIdx])
			if score > bestScore {
				bestScore = score
				bestIndexes = []int{currentIdx}
			} else if score == bestScore {
				bestIndexes = append(bestIndexes, currentIdx)
			}
		}
		if len(bestIndexes) == 0 {
			continue
		}
		if len(bestIndexes) > 1 {
			issues = append(issues, "ambiguous composition family pairing:"+family)
			continue
		}
		currentIdx := bestIndexes[0]
		baselineMatched[baseIdx] = true
		currentMatched[currentIdx] = true
		pairs = append(pairs, compositionPair{Baseline: base, Current: current[currentIdx]})
	}

	unmatchedCurrent := []CompositionState{}
	for idx, item := range current {
		if !currentMatched[idx] {
			unmatchedCurrent = append(unmatchedCurrent, item)
		}
	}
	unmatchedBaseline := []CompositionState{}
	for idx, item := range baseline {
		if !baselineMatched[idx] {
			unmatchedBaseline = append(unmatchedBaseline, item)
		}
	}
	sortCompositionStates(unmatchedCurrent)
	sortCompositionStates(unmatchedBaseline)
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Current.CompositionFamilyKey != pairs[j].Current.CompositionFamilyKey {
			return pairs[i].Current.CompositionFamilyKey < pairs[j].Current.CompositionFamilyKey
		}
		return pairs[i].Current.CompositionID < pairs[j].Current.CompositionID
	})
	return pairs, unmatchedCurrent, unmatchedBaseline, uniqueSortedStrings(issues)
}

func compositionPairScore(baseline, current CompositionState) int {
	score := 0
	if baseline.StableRouteSourceIdentity == current.StableRouteSourceIdentity {
		score += 100
	}
	if strings.Join(baseline.StageRoles, ",") == strings.Join(current.StageRoles, ",") {
		score += 20
	}
	if baseline.TargetIdentity == current.TargetIdentity {
		score += 20
	}
	score += len(stringIntersection(baseline.MemberResolutionKeys, current.MemberResolutionKeys))
	if baseline.CompositionID == current.CompositionID {
		score += 5
	}
	return score
}

func addMatchedCompositionDriftExamples(buckets map[string]*driftBucket, pair compositionPair) {
	if strings.Join(pair.Baseline.MemberResolutionKeys, ",") != strings.Join(pair.Current.MemberResolutionKeys, ",") {
		addCompositionDriftCategoryExample(buckets[DriftCategoryChangedCompositionMembers], pair.Current, pair.Baseline, "composition member set changed since baseline")
	}
	if len(stringDelta(pair.Baseline.SinkStageKeys, pair.Current.SinkStageKeys)) > 0 {
		addCompositionDriftCategoryExample(buckets[DriftCategoryNewCompositionSinks], pair.Current, pair.Baseline, "composition introduced a new sink stage since baseline")
	}
	if compositionCoverageDegraded(pair.Baseline, pair.Current) {
		addCompositionDriftCategoryExample(buckets[DriftCategoryCompositionCoverageDegraded], pair.Current, pair.Baseline, "composition policy or Gait coverage degraded since baseline")
	}
	if compositionEvidenceDegraded(pair.Baseline, pair.Current) {
		addCompositionDriftCategoryExample(buckets[DriftCategoryCompositionEvidenceDegraded], pair.Current, pair.Baseline, "composition evidence posture degraded since baseline")
	}
	if len(stringDelta(pair.Current.CorrelationRefs, pair.Baseline.CorrelationRefs)) > 0 {
		addCompositionDriftCategoryExample(buckets[DriftCategoryCompositionEvidenceDegraded], pair.Current, pair.Baseline, "bounded multi-stage transition correlation evidence was removed since baseline")
	}
	if compositionNewlyUngoverned(pair.Baseline, pair.Current) {
		addCompositionDriftCategoryExample(buckets[DriftCategoryNewlyUngovernedCompositions], pair.Current, pair.Baseline, "composition became newly ungoverned since baseline")
	}
	if compositionRecommendationWorsened(pair.Baseline, pair.Current) {
		addCompositionDriftCategoryExample(buckets[DriftCategoryWorsenedCompositionRecommendation], pair.Current, pair.Baseline, "composition recommendation became more restrictive since baseline")
	}
	if strings.TrimSpace(pair.Baseline.OutcomeKey) != strings.TrimSpace(pair.Current.OutcomeKey) {
		addCompositionDriftCategoryExample(buckets[DriftCategoryCompositionOutcomeChanged], pair.Current, pair.Baseline, "composition outcome key changed since baseline")
	}
	if len(stringDelta(pair.Baseline.EquivalentOutcomeRefs, pair.Current.EquivalentOutcomeRefs)) > 0 {
		addCompositionDriftCategoryExample(buckets[DriftCategoryAlternateRouteAppeared], pair.Current, pair.Baseline, "composition equivalent-outcome alternatives changed since baseline")
	}
	if len(stringDelta(pair.Baseline.AlternateRouteRefs, pair.Current.AlternateRouteRefs)) > 0 {
		addCompositionDriftCategoryExample(buckets[DriftCategoryAlternateRouteAppeared], pair.Current, pair.Baseline, "bounded multi-stage alternate routes changed since baseline")
	}
	if strings.TrimSpace(pair.Baseline.ReachabilityState) != strings.TrimSpace(pair.Current.ReachabilityState) || pair.Baseline.ObservedExecution != pair.Current.ObservedExecution {
		addCompositionDriftCategoryExample(buckets[DriftCategoryCompositionReachabilityChanged], pair.Current, pair.Baseline, "composition possible/incomplete/observed reachability changed since baseline")
	}
	if pair.Baseline.ActionContractID != pair.Current.ActionContractID || pair.Baseline.ActionContractFamilyID != pair.Current.ActionContractFamilyID || pair.Baseline.ActionContractRevision != pair.Current.ActionContractRevision || pair.Baseline.ActionContractSupersedes != pair.Current.ActionContractSupersedes || pair.Baseline.ActionContractDigest != pair.Current.ActionContractDigest {
		addCompositionDriftCategoryExample(buckets[DriftCategoryActionContractRevisionChanged], pair.Current, pair.Baseline, "proposed Action Contract immutable revision identity changed since baseline")
	}
	if strings.Join(pair.Baseline.ContractActivation, ",") != strings.Join(pair.Current.ContractActivation, ",") {
		addCompositionDriftCategoryExample(buckets[DriftCategoryActionContractActivationChanged], pair.Current, pair.Baseline, "imported Gait activation evidence changed since baseline")
	}
	if strings.Join(pair.Baseline.ContractRejection, ",") != strings.Join(pair.Current.ContractRejection, ",") {
		addCompositionDriftCategoryExample(buckets[DriftCategoryActionContractRejectionChanged], pair.Current, pair.Baseline, "imported Gait rejection evidence changed since baseline")
	}
	if strings.Join(pair.Baseline.ContractExecutionEffect, ",") != strings.Join(pair.Current.ContractExecutionEffect, ",") {
		addCompositionDriftCategoryExample(buckets[DriftCategoryActionContractExecutionEffectChanged], pair.Current, pair.Baseline, "imported Gait execution or effect evidence changed since baseline")
	}
	if strings.Join(pair.Baseline.ContractVerification, ",") != strings.Join(pair.Current.ContractVerification, ",") {
		addCompositionDriftCategoryExample(buckets[DriftCategoryActionContractVerificationChanged], pair.Current, pair.Baseline, "imported Axym verification references changed since baseline")
	}
}

func lifecycleObservationDriftValue(observation risk.ProposedActionLifecycleObservation) string {
	return strings.Join([]string{
		strings.TrimSpace(observation.Kind),
		strings.TrimSpace(observation.Producer),
		strings.TrimSpace(observation.EvidenceState),
		strings.TrimSpace(observation.FreshnessState),
		strings.Join(mergeSortedStrings(observation.EvidenceRefs, nil), ","),
		strings.Join(mergeSortedStrings(observation.ActionContractArtifactRefs, nil), ","),
		strings.Join(mergeSortedStrings(observation.ProofRefs, nil), ","),
	}, "|")
}

func addCompositionDriftCategoryExample(bucket *driftBucket, current CompositionState, baseline CompositionState, detail string) {
	if bucket == nil {
		return
	}
	exampleKey := strings.Join([]string{bucket.category, current.CompositionID, baseline.CompositionID, current.CompositionFamilyKey, baseline.CompositionFamilyKey, detail}, "|")
	if _, exists := bucket.exampleKeys[exampleKey]; exists {
		return
	}
	bucket.exampleKeys[exampleKey] = struct{}{}
	bucket.count++

	if currentRef := driftCompositionRef("current", current); currentRef != "" {
		bucket.affectedPathSet[currentRef] = struct{}{}
	}
	if baselineRef := driftCompositionRef("baseline", baseline); baselineRef != "" {
		bucket.affectedPathSet[baselineRef] = struct{}{}
	}
	for _, ref := range current.EvidenceRefs {
		if strings.TrimSpace(ref) != "" {
			bucket.evidenceRefSet[ref] = struct{}{}
		}
	}
	for _, ref := range baseline.EvidenceRefs {
		if strings.TrimSpace(ref) != "" {
			bucket.evidenceRefSet[ref] = struct{}{}
		}
	}
	if len(bucket.examples) >= driftExampleLimit {
		return
	}
	bucket.examples = append(bucket.examples, DriftExample{
		CompositionID:           current.CompositionID,
		BaselineCompositionID:   baseline.CompositionID,
		CurrentCompositionRef:   driftCompositionRef("current", current),
		BaselineCompositionRef:  driftCompositionRef("baseline", baseline),
		CurrentOutcomeKey:       current.OutcomeKey,
		BaselineOutcomeKey:      baseline.OutcomeKey,
		CurrentTargetClass:      firstNonEmptyString(current.TargetIdentity, current.OutcomeClass),
		BaselineTargetClass:     firstNonEmptyString(baseline.TargetIdentity, baseline.OutcomeClass),
		CurrentRecommendation:   current.RecommendedControl,
		BaselineRecommendation:  baseline.RecommendedControl,
		CurrentEvidenceSummary:  compositionEvidenceSummary(current),
		BaselineEvidenceSummary: compositionEvidenceSummary(baseline),
		CurrentEvidenceRefs:     append([]string(nil), current.EvidenceRefs...),
		BaselineEvidenceRefs:    append([]string(nil), baseline.EvidenceRefs...),
		Detail:                  detail,
		RecommendedNextAction:   firstCategoryAction(bucket.recommended),
	})
}

func driftCompositionRef(prefix string, state CompositionState) string {
	id := strings.TrimSpace(state.CompositionID)
	if id == "" {
		id = strings.TrimSpace(state.CompositionFamilyKey)
	}
	if id == "" {
		return ""
	}
	return strings.TrimSpace(prefix) + ":composition:" + id
}

func compositionEvidenceSummary(state CompositionState) []string {
	out := []string{}
	for _, item := range []struct {
		label string
		value string
	}{
		{label: "evidence", value: state.EvidenceState},
		{label: "freshness", value: state.FreshnessState},
		{label: "policy", value: state.PolicyCoverageStatus},
		{label: "recommendation", value: state.RecommendedControl},
		{label: "reachability", value: state.ReachabilityState},
	} {
		if strings.TrimSpace(item.value) != "" {
			out = append(out, item.label+":"+strings.TrimSpace(item.value))
		}
	}
	out = append(out, state.GaitCoverageSummary...)
	out = append(out, state.DelegationRelationships...)
	return mergeSortedStrings(out, nil)
}

func compositionOrderedStageSemantics(composition risk.ComposedActionPath) []string {
	if strings.TrimSpace(composition.ReachabilityState) == "" {
		return nil
	}
	out := make([]string, 0, len(composition.Stages))
	for _, stage := range composition.Stages {
		out = append(out, strings.Join([]string{
			strings.TrimSpace(stage.Role),
			strings.TrimSpace(stage.SystemClass),
			strings.TrimSpace(stage.TrustBoundary),
		}, ":"))
	}
	return out
}

func compositionCorrelationRefs(composition risk.ComposedActionPath) []string {
	refs := []string{}
	for _, stage := range composition.Stages {
		refs = append(refs, stage.CorrelationRefs...)
	}
	for _, transition := range composition.Transitions {
		refs = append(refs, transition.CorrelationRefs...)
	}
	return mergeSortedStrings(refs, nil)
}

func compositionStageRoles(composition risk.ComposedActionPath) []string {
	out := []string{}
	for _, stage := range composition.Stages {
		out = append(out, strings.TrimSpace(stage.Role))
	}
	return mergeSortedStrings(out, nil)
}

func compositionMemberResolutionKeys(composition risk.ComposedActionPath) []string {
	out := []string{}
	for _, stage := range composition.Stages {
		out = append(out, strings.TrimSpace(stage.Role)+":"+strings.TrimSpace(stage.ResolutionKey))
	}
	return mergeSortedStrings(out, nil)
}

func compositionRouteSourceIdentity(composition risk.ComposedActionPath) string {
	parts := []string{}
	for _, stage := range composition.Stages {
		role := strings.TrimSpace(stage.Role)
		if role == risk.CompositionStageRoleSource || role == risk.CompositionStageRoleTransform {
			parts = append(parts, strings.Join([]string{role, strings.TrimSpace(stage.ToolType), strings.TrimSpace(stage.Location)}, "|"))
		}
	}
	if len(parts) == 0 && len(composition.Stages) > 0 {
		stage := composition.Stages[0]
		parts = append(parts, strings.Join([]string{strings.TrimSpace(stage.Role), strings.TrimSpace(stage.ToolType), strings.TrimSpace(stage.Location)}, "|"))
	}
	return strings.Join(mergeSortedStrings(parts, nil), "+")
}

func compositionSinkStageKeys(composition risk.ComposedActionPath) []string {
	out := []string{}
	for _, stage := range composition.Stages {
		switch strings.TrimSpace(stage.Role) {
		case risk.CompositionStageRoleSink, risk.CompositionStageRoleInternalSink, risk.CompositionStageRoleExternalSink, risk.CompositionStageRolePrivilegedSink, risk.CompositionStageRoleDestructiveSink:
			out = append(out, strings.Join([]string{strings.TrimSpace(stage.Role), strings.TrimSpace(stage.TargetClass), strings.TrimSpace(stage.ResolutionKey)}, "|"))
		}
	}
	return mergeSortedStrings(out, nil)
}

func compositionDelegationRelationships(composition risk.ComposedActionPath) []string {
	out := []string{}
	for _, transition := range composition.Transitions {
		if strings.TrimSpace(transition.Relationship) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(transition.TransitionID)+":"+strings.TrimSpace(transition.Relationship))
	}
	return mergeSortedStrings(out, nil)
}

func compositionGaitCoverageSummary(coverage *risk.GaitCoverage) []string {
	if coverage == nil {
		return nil
	}
	values := []string{
		"policy_decision:" + strings.TrimSpace(coverage.PolicyDecision.Status),
		"approval:" + strings.TrimSpace(coverage.Approval.Status),
		"jit_credential:" + strings.TrimSpace(coverage.JITCredential.Status),
		"freeze_window:" + strings.TrimSpace(coverage.FreezeWindow.Status),
		"kill_switch:" + strings.TrimSpace(coverage.KillSwitch.Status),
		"action_outcome:" + strings.TrimSpace(coverage.ActionOutcome.Status),
		"proof_verification:" + strings.TrimSpace(coverage.ProofVerification.Status),
	}
	if coverage.Containment != nil {
		values = append(values, "containment:"+strings.TrimSpace(coverage.Containment.Status))
	}
	return mergeSortedStrings(values, nil)
}

func compositionCoverageDegraded(baseline, current CompositionState) bool {
	if compositionPolicyRank(current.PolicyCoverageStatus) > compositionPolicyRank(baseline.PolicyCoverageStatus) {
		return true
	}
	return compositionGaitCoverageRank(current.GaitCoverageSummary) > compositionGaitCoverageRank(baseline.GaitCoverageSummary)
}

func compositionEvidenceDegraded(baseline, current CompositionState) bool {
	if compositionEvidenceRank(current.EvidenceState) > compositionEvidenceRank(baseline.EvidenceState) {
		return true
	}
	return compositionFreshnessRank(current.FreshnessState) > compositionFreshnessRank(baseline.FreshnessState)
}

func compositionNewlyUngoverned(baseline, current CompositionState) bool {
	return compositionPolicyRank(baseline.PolicyCoverageStatus) <= compositionPolicyRank(risk.PolicyCoverageStatusMatched) &&
		compositionPolicyRank(current.PolicyCoverageStatus) >= compositionPolicyRank(risk.PolicyCoverageStatusStale)
}

func compositionRecommendationWorsened(baseline, current CompositionState) bool {
	return compositionRecommendedControlRank(current.RecommendedControl) < compositionRecommendedControlRank(baseline.RecommendedControl)
}

func compositionAlternateOutcomeExists(current CompositionState, baseline []CompositionState) bool {
	for _, item := range baseline {
		if strings.TrimSpace(item.OutcomeKey) != "" &&
			strings.TrimSpace(item.OutcomeKey) == strings.TrimSpace(current.OutcomeKey) &&
			strings.TrimSpace(item.CompositionFamilyKey) != strings.TrimSpace(current.CompositionFamilyKey) {
			return true
		}
	}
	return false
}

func compositionPolicyRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.PolicyCoverageStatusRuntimeProven:
		return 0
	case risk.PolicyCoverageStatusMatched:
		return 1
	case risk.PolicyCoverageStatusDeclared:
		return 2
	case risk.PolicyCoverageStatusStale:
		return 3
	case risk.PolicyCoverageStatusNone:
		return 4
	case risk.PolicyCoverageStatusConflict:
		return 5
	default:
		return 4
	}
}

func compositionGaitCoverageRank(values []string) int {
	rank := -1
	for _, value := range values {
		parts := strings.SplitN(value, ":", 2)
		if len(parts) != 2 {
			continue
		}
		switch strings.TrimSpace(parts[1]) {
		case risk.GaitStatusConflict:
			rank = maxInt(rank, 5)
		case risk.GaitStatusStale:
			rank = maxInt(rank, 4)
		case risk.GaitStatusMissing:
			rank = maxInt(rank, 4)
		case risk.GaitStatusNotApplicable:
			rank = maxInt(rank, 1)
		case risk.GaitStatusPresent:
			rank = maxInt(rank, 0)
		default:
			rank = maxInt(rank, 3)
		}
	}
	if rank < 0 {
		return 4
	}
	return rank
}

func compositionEvidenceRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.EvidenceStateVerified:
		return 0
	case risk.EvidenceStateDeclared:
		return 1
	case risk.EvidenceStateInferred:
		return 2
	case risk.EvidenceStateUnknown:
		return 3
	case risk.EvidenceStateContradictory:
		return 4
	default:
		return 3
	}
}

func compositionFreshnessRank(value string) int {
	switch strings.TrimSpace(value) {
	case "fresh":
		return 0
	case "unknown":
		return 1
	case "stale":
		return 2
	case "expired":
		return 3
	default:
		return 1
	}
}

func compositionRecommendedControlRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.RecommendedControlBlock:
		return 0
	case risk.RecommendedControlBlockStandingCredential:
		return 1
	case risk.RecommendedControlJITCredentialRequired:
		return 2
	case risk.RecommendedControlProofRequired:
		return 3
	case risk.RecommendedControlApprovalRequired:
		return 4
	case risk.RecommendedControlSecurityReview:
		return 5
	case risk.RecommendedControlOwnerReview:
		return 6
	case risk.RecommendedControlAllow:
		return 7
	default:
		return 8
	}
}

func stringIntersection(left, right []string) []string {
	rightSet := map[string]struct{}{}
	for _, value := range right {
		if strings.TrimSpace(value) != "" {
			rightSet[strings.TrimSpace(value)] = struct{}{}
		}
	}
	out := []string{}
	for _, value := range left {
		if _, ok := rightSet[strings.TrimSpace(value)]; ok {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return mergeSortedStrings(out, nil)
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
