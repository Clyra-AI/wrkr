package risk

import (
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
)

const (
	minMultiStageCompositionDepth                = 3
	maxMultiStageCompositionDepth                = 5
	maxMultiStageCompositionPathsPerPattern      = 16
	maxMultiStageCompositionCandidatesPerPattern = 64
	maxMultiStageCompositionNeighborsPerStage    = 6
	maxMultiStageAlternateRouteRefs              = 8
	maxMultiStageCorrelationRefs                 = 16

	multiStageTrustBoundaryConstraint = "explicit_correlation_required_across_boundaries"
)

var multiStageCorrelationRefKnownPrefixes = []string{
	"workflow_chain:",
	"attack_path:",
	"authority_binding:",
	"endpoint_group:",
	"policy:",
	"source_finding:",
	"imported_evidence:",
	"composition:",
	"graph_edge:",
}

type multiStageCompositionPatternSpec struct {
	id               string
	description      string
	sourceRole       string
	sinkRole         string
	outcome          string
	sourceSystems    []string
	transformSystems []string
	sinkSystems      []string
	sourceOK         func(ActionPath) bool
	sinkOK           func(ActionPath) bool
	minStages        int
	maxStages        int
}

type multiStageCompositionBuildState struct {
	candidateCount      int
	emittedCount        int
	truncatedCandidates []string
	truncations         []CompositionTruncation
}

func buildMultiStageComposedActionPaths(paths []ActionPath, workflowChains *agentresolver.WorkflowChainArtifact) []ComposedActionPath {
	if len(paths) < minMultiStageCompositionDepth {
		return nil
	}
	chainRefsByPath := agentresolver.WorkflowChainRefsByPath(workflowChains)
	ordered := append([]ActionPath(nil), paths...)
	sort.Slice(ordered, func(i, j int) bool {
		leftClass := multiStageSystemClass(ordered[i])
		rightClass := multiStageSystemClass(ordered[j])
		if multiStageSystemClassRank(leftClass) != multiStageSystemClassRank(rightClass) {
			return multiStageSystemClassRank(leftClass) < multiStageSystemClassRank(rightClass)
		}
		if compositionMemberKey(ordered[i]) != compositionMemberKey(ordered[j]) {
			return compositionMemberKey(ordered[i]) < compositionMemberKey(ordered[j])
		}
		return strings.TrimSpace(ordered[i].PathID) < strings.TrimSpace(ordered[j].PathID)
	})

	correlationRefsByMember := map[string][]string{}
	for _, path := range ordered {
		memberKey := compositionMemberKey(path)
		correlationRefsByMember[memberKey] = dedupeSortedStrings(append(
			correlationRefsByMember[memberKey],
			multiStageCorrelationRefs(path, chainRefsByPath)...,
		))
	}

	byID := map[string]ComposedActionPath{}
	for _, spec := range multiStageCompositionPatternSpecs() {
		state := &multiStageCompositionBuildState{}
		for _, source := range ordered {
			sourceClass := multiStageSystemClass(source)
			if !IsActionPathEligible(source) || !spec.sourceOK(source) || !stringInSet(sourceClass, spec.sourceSystems) || !knownMultiStageTrustBoundary(source, sourceClass) {
				continue
			}
			visited := map[string]struct{}{compositionMemberKey(source): {}}
			walkMultiStageComposition(spec, ordered, correlationRefsByMember, []ActionPath{source}, nil, visited, byID, state)
			if state.candidateCount >= maxMultiStageCompositionCandidatesPerPattern || state.emittedCount >= maxMultiStageCompositionPathsPerPattern {
				break
			}
		}
		attachMultiStageTruncation(byID, spec, state)
	}

	out := make([]ComposedActionPath, 0, len(byID))
	for _, composition := range byID {
		out = append(out, composition)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PatternID != out[j].PatternID {
			return out[i].PatternID < out[j].PatternID
		}
		return out[i].CompositionID < out[j].CompositionID
	})
	return out
}

func walkMultiStageComposition(
	spec multiStageCompositionPatternSpec,
	candidates []ActionPath,
	correlationRefsByMember map[string][]string,
	current []ActionPath,
	edgeCorrelationRefs [][]string,
	visited map[string]struct{},
	byID map[string]ComposedActionPath,
	state *multiStageCompositionBuildState,
) {
	if state == nil || state.candidateCount >= maxMultiStageCompositionCandidatesPerPattern || state.emittedCount >= maxMultiStageCompositionPathsPerPattern {
		return
	}
	last := current[len(current)-1]
	lastMember := compositionMemberKey(last)
	lastClass := multiStageSystemClass(last)
	type nextCandidate struct {
		path            ActionPath
		correlationRefs []string
		isSink          bool
		canTransform    bool
	}
	next := make([]nextCandidate, 0)
	for _, candidate := range candidates {
		memberKey := compositionMemberKey(candidate)
		if _, seen := visited[memberKey]; seen || !IsActionPathEligible(candidate) {
			continue
		}
		candidateClass := multiStageSystemClass(candidate)
		if candidateClass == CompositionSystemClassUnknown || !knownMultiStageTrustBoundary(candidate, candidateClass) || multiStageSystemClassRank(candidateClass) <= multiStageSystemClassRank(lastClass) {
			continue
		}
		correlationRefs := intersectSortedStrings(correlationRefsByMember[lastMember], correlationRefsByMember[memberKey])
		if !hasMultiStageTransitionEvidence(correlationRefs) {
			continue
		}
		isSink := spec.sinkOK(candidate) && stringInSet(candidateClass, spec.sinkSystems)
		canTransform := stringInSet(candidateClass, spec.transformSystems) && multiStageSystemClassRank(candidateClass) > multiStageSystemClassRank(lastClass)
		if !isSink && !canTransform {
			continue
		}
		next = append(next, nextCandidate{path: candidate, correlationRefs: correlationRefs, isSink: isSink, canTransform: canTransform})
	}
	sort.Slice(next, func(i, j int) bool {
		leftClass := multiStageSystemClass(next[i].path)
		rightClass := multiStageSystemClass(next[j].path)
		if multiStageSystemClassRank(leftClass) != multiStageSystemClassRank(rightClass) {
			return multiStageSystemClassRank(leftClass) < multiStageSystemClassRank(rightClass)
		}
		return compositionMemberKey(next[i].path) < compositionMemberKey(next[j].path)
	})
	if len(next) > maxMultiStageCompositionNeighborsPerStage {
		omitted := next[maxMultiStageCompositionNeighborsPerStage:]
		for _, candidate := range omitted {
			state.truncatedCandidates = append(state.truncatedCandidates, compositionCandidateKey(candidate.path))
		}
		state.truncations = append(state.truncations, CompositionTruncation{
			PatternID:          spec.id,
			Reason:             CompositionTruncationCandidateCap,
			Limit:              maxMultiStageCompositionNeighborsPerStage,
			ObservedCandidates: len(next),
			OmittedCandidates:  len(omitted),
		})
		next = next[:maxMultiStageCompositionNeighborsPerStage]
	}

	for _, candidate := range next {
		if state.candidateCount >= maxMultiStageCompositionCandidatesPerPattern {
			state.truncations = append(state.truncations, CompositionTruncation{
				PatternID:          spec.id,
				Reason:             CompositionTruncationCandidateCap,
				Limit:              maxMultiStageCompositionCandidatesPerPattern,
				ObservedCandidates: state.candidateCount + 1,
				OmittedCandidates:  1,
			})
			return
		}
		state.candidateCount++
		route := append(append([]ActionPath(nil), current...), candidate.path)
		routeEdgeRefs := append(append([][]string(nil), edgeCorrelationRefs...), candidate.correlationRefs)
		if len(route) > spec.maxStages {
			state.truncations = append(state.truncations, CompositionTruncation{
				PatternID:          spec.id,
				Reason:             CompositionTruncationDepthCap,
				Limit:              spec.maxStages,
				ObservedCandidates: len(route),
				OmittedCandidates:  1,
			})
			continue
		}
		if candidate.isSink && len(route) >= spec.minStages {
			if state.emittedCount >= maxMultiStageCompositionPathsPerPattern {
				state.truncations = append(state.truncations, CompositionTruncation{
					PatternID:          spec.id,
					Reason:             CompositionTruncationPathCap,
					Limit:              maxMultiStageCompositionPathsPerPattern,
					ObservedCandidates: state.emittedCount + 1,
					OmittedCandidates:  1,
				})
				return
			}
			composition := buildMultiStageComposedActionPath(spec, route, routeEdgeRefs)
			if strings.TrimSpace(composition.CompositionID) != "" {
				if currentValue, ok := byID[composition.CompositionID]; ok {
					byID[composition.CompositionID] = mergeMultiStageComposedActionPath(currentValue, composition)
				} else {
					byID[composition.CompositionID] = composition
					state.emittedCount++
				}
			}
		}
		if !candidate.canTransform {
			continue
		}
		if len(route) >= spec.maxStages {
			state.truncations = append(state.truncations, CompositionTruncation{
				PatternID:          spec.id,
				Reason:             CompositionTruncationDepthCap,
				Limit:              spec.maxStages,
				ObservedCandidates: len(route) + 1,
				OmittedCandidates:  1,
			})
			continue
		}
		memberKey := compositionMemberKey(candidate.path)
		visited[memberKey] = struct{}{}
		walkMultiStageComposition(spec, candidates, correlationRefsByMember, route, routeEdgeRefs, visited, byID, state)
		delete(visited, memberKey)
	}
}

func buildMultiStageComposedActionPath(spec multiStageCompositionPatternSpec, paths []ActionPath, edgeCorrelationRefs [][]string) ComposedActionPath {
	if len(paths) < spec.minStages || len(paths) > spec.maxStages || len(edgeCorrelationRefs) != len(paths)-1 {
		return ComposedActionPath{}
	}
	boundedEdgeRefs := make([][]string, len(edgeCorrelationRefs))
	truncations := []CompositionTruncation{}
	for index, refs := range edgeCorrelationRefs {
		boundedEdgeRefs[index], truncations = boundMultiStageCorrelationRefs(spec.id, refs, truncations)
	}
	stages := make([]CompositionStage, 0, len(paths))
	for index, path := range paths {
		role := CompositionStageRoleTransform
		if index == 0 {
			role = spec.sourceRole
		} else if index == len(paths)-1 {
			role = spec.sinkRole
		}
		stage := buildCompositionStage(role, path)
		stage.SystemClass = multiStageSystemClass(path)
		stage.TrustBoundary = multiStageTrustBoundary(path, stage.SystemClass)
		if index > 0 {
			stage.CorrelationRefs = append(stage.CorrelationRefs, boundedEdgeRefs[index-1]...)
		}
		if index < len(boundedEdgeRefs) {
			stage.CorrelationRefs = append(stage.CorrelationRefs, boundedEdgeRefs[index]...)
		}
		stage.CorrelationRefs = dedupeSortedStrings(stage.CorrelationRefs)
		stage.CorrelationRefs, truncations = boundMultiStageCorrelationRefs(spec.id, stage.CorrelationRefs, truncations)
		stage.ObservedExecution = multiStagePathObservedExecution(path)
		stage.ReachabilityState = CompositionReachabilityPossible
		if stage.ObservedExecution {
			stage.ReachabilityState = CompositionReachabilityObserved
		}
		stages = append(stages, stage)
	}

	targetIdentity := compositionTargetIdentity(compositionPatternSpec{}, paths)
	environment := compositionEnvironment(compositionPatternSpec{outcome: spec.outcome}, paths)
	targetClass := compositionTargetClass(paths)
	outcomeKey := strings.Join(dedupeSortedStrings([]string{
		"asset=" + targetIdentity,
		"target_class=" + targetClass,
		"outcome=" + spec.outcome,
		"environment=" + environment,
	}), "|")
	compositionID := multiStageCompositionID(spec.id, stages, targetIdentity, outcomeKey)
	for index := range stages {
		stages[index].StageID = multiStageCompositionStageID(compositionID, index, stages[index])
	}
	transitions := buildCompositionTransitions(compositionID, stages)
	for index := range transitions {
		transitions[index].FromSystemClass = stages[index].SystemClass
		transitions[index].ToSystemClass = stages[index+1].SystemClass
		transitions[index].TrustBoundary = stages[index].TrustBoundary + "->" + stages[index+1].TrustBoundary
		transitions[index].CorrelationRefs = dedupeSortedStrings(boundedEdgeRefs[index])
		transitions[index].FreshnessState = compositionFreshnessState(stages[index].FreshnessState, stages[index+1].FreshnessState)
		transitions[index].ReachabilityState = CompositionReachabilityPossible
	}

	evidenceState := compositionEvidenceStateFromStages(stages)
	freshnessState := compositionFreshnessStateFromStages(stages)
	policyCoverage := compositionPolicyCoverageStatusFromStages(stages)
	gaitCoverage := compositionGaitCoverageFromStages(stages)
	claimState := compositionClaimState(evidenceState, policyCoverage, freshnessState, gaitCoverage, stages, paths)
	observedExecution := claimState == CompositionClaimObservedExecution
	reachabilityState := CompositionReachabilityPossible
	if observedExecution {
		reachabilityState = CompositionReachabilityObserved
	}
	for index := range transitions {
		transitions[index].ObservedExecution = observedExecution
		transitions[index].ReachabilityState = reachabilityState
	}
	composition := ComposedActionPath{
		CompositionID:                compositionID,
		PatternID:                    spec.id,
		Pattern:                      multiStagePublicPattern(spec, stages),
		ResolutionKey:                multiStageCompositionResolutionKey(paths),
		PathIDs:                      compositionPathIDs(paths),
		WorkflowChainRefs:            compositionWorkflowRefs(paths, nil),
		Stages:                       stages,
		Transitions:                  transitions,
		TargetIdentity:               targetIdentity,
		DurableOutcomeKey:            outcomeKey,
		OutcomeKey:                   outcomeKey,
		AffectedAsset:                targetIdentity,
		OutcomeClass:                 spec.outcome,
		Environment:                  environment,
		TargetClass:                  targetClass,
		ClaimState:                   claimState,
		EvidenceState:                evidenceState,
		FreshnessState:               freshnessState,
		PolicyCoverageStatus:         policyCoverage,
		GaitCoverage:                 gaitCoverage,
		RuntimeEvidenceAbsenceStatus: compositionRuntimeAbsenceFromStages(stages),
		Contradictions:               compositionContradictions(paths),
		EvidenceRefs:                 compositionEvidenceRefs(paths),
		ProofRefs:                    compositionProofRefs(paths),
		SourceDecisionRefs:           compositionSourceDecisionRefs(paths),
		RiskTier:                     compositionRiskTier(paths),
		ClosureRequirements:          compositionClosureRequirements(paths),
		EvidenceCompleteness:         compositionEvidenceCompleteness(paths),
		ReachabilityState:            reachabilityState,
		ObservedExecution:            observedExecution,
		Truncations:                  normalizeCompositionTruncations(truncations),
	}
	composition.WorkflowChainRefs = multiStageWorkflowRefs(stages)
	applyCompositionDelegationRelationships(&composition, paths)
	applyCompositionRecommendedControl(&composition, paths)
	hydrateCompositionTransitions(&composition)
	composition.ProposedActionContract = BuildProposedActionContract(composition)
	if composition.ProposedActionContract != nil {
		composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	}
	return composition
}

func multiStageCompositionStageID(compositionID string, index int, stage CompositionStage) string {
	return "cas-" + stableCompositionHash(strings.Join([]string{
		strings.TrimSpace(compositionID),
		strconv.Itoa(index),
		strings.TrimSpace(stage.Role),
		strings.TrimSpace(stage.ResolutionKey),
	}, "|"))
}

func boundMultiStageCorrelationRefs(patternID string, refs []string, truncations []CompositionTruncation) ([]string, []CompositionTruncation) {
	bounded := dedupeSortedStrings(refs)
	sort.SliceStable(bounded, func(i, j int) bool {
		leftStrong := strongMultiStageCorrelationRef(bounded[i])
		rightStrong := strongMultiStageCorrelationRef(bounded[j])
		if leftStrong != rightStrong {
			return leftStrong
		}
		return bounded[i] < bounded[j]
	})
	if len(bounded) <= maxMultiStageCorrelationRefs {
		return bounded, truncations
	}
	observed := len(bounded)
	omitted := observed - maxMultiStageCorrelationRefs
	truncations = append(truncations, CompositionTruncation{
		PatternID:          patternID,
		Reason:             CompositionTruncationReferenceCap,
		Limit:              maxMultiStageCorrelationRefs,
		ObservedCandidates: observed,
		OmittedCandidates:  omitted,
	})
	return bounded[:maxMultiStageCorrelationRefs], truncations
}

func multiStageCompositionPatternSpecs() []multiStageCompositionPatternSpec {
	allTransforms := []string{
		CompositionSystemClassRepo,
		CompositionSystemClassCI,
		CompositionSystemClassPackage,
		CompositionSystemClassCloud,
		CompositionSystemClassSaaS,
		CompositionSystemClassCommunications,
	}
	return []multiStageCompositionPatternSpec{
		{
			id: CompositionPatternSensitiveReadToEgressMultiStage, description: "Sensitive data can cross bounded repo, CI, cloud, SaaS, or communications stages before egress.",
			sourceRole: CompositionStageRoleSource, sinkRole: CompositionStageRoleExternalSink, outcome: "data_egress",
			sourceSystems: []string{CompositionSystemClassRepo, CompositionSystemClassCI, CompositionSystemClassCloud, CompositionSystemClassSaaS}, transformSystems: allTransforms,
			sinkSystems: []string{CompositionSystemClassCloud, CompositionSystemClassSaaS, CompositionSystemClassCommunications}, sourceOK: pathHasSensitiveRead, sinkOK: pathHasExternalEgress,
			minStages: minMultiStageCompositionDepth, maxStages: maxMultiStageCompositionDepth,
		},
		{
			id: CompositionPatternSecretToNetworkMultiStage, description: "Credential authority can cross bounded execution systems before network egress.",
			sourceRole: CompositionStageRoleSource, sinkRole: CompositionStageRoleExternalSink, outcome: "network_egress",
			sourceSystems: []string{CompositionSystemClassRepo, CompositionSystemClassCI, CompositionSystemClassPackage, CompositionSystemClassCloud}, transformSystems: allTransforms,
			sinkSystems: []string{CompositionSystemClassCloud, CompositionSystemClassSaaS, CompositionSystemClassCommunications}, sourceOK: pathHasSecretAuthority, sinkOK: pathHasNetworkEgress,
			minStages: minMultiStageCompositionDepth, maxStages: maxMultiStageCompositionDepth,
		},
		{
			id: CompositionPatternCodeToDeployMultiStage, description: "Repository mutation can cross bounded CI and cloud stages before deployment.",
			sourceRole: CompositionStageRoleSource, sinkRole: CompositionStageRolePrivilegedSink, outcome: "production_deploy",
			sourceSystems: []string{CompositionSystemClassRepo, CompositionSystemClassCI}, transformSystems: allTransforms,
			sinkSystems: []string{CompositionSystemClassCI, CompositionSystemClassPackage, CompositionSystemClassCloud, CompositionSystemClassSaaS}, sourceOK: pathMutatesCode, sinkOK: pathDeploysProduction,
			minStages: minMultiStageCompositionDepth, maxStages: maxMultiStageCompositionDepth,
		},
		{
			id: CompositionPatternWorkflowMutationProductionMultiStage, description: "Workflow mutation can cross bounded CI and cloud stages before production impact.",
			sourceRole: CompositionStageRoleTransform, sinkRole: CompositionStageRolePrivilegedSink, outcome: "production_mutation",
			sourceSystems: []string{CompositionSystemClassRepo, CompositionSystemClassCI}, transformSystems: allTransforms,
			sinkSystems: []string{CompositionSystemClassCI, CompositionSystemClassCloud, CompositionSystemClassSaaS}, sourceOK: pathMutatesWorkflow, sinkOK: pathProductionImpact,
			minStages: minMultiStageCompositionDepth, maxStages: maxMultiStageCompositionDepth,
		},
		{
			id: CompositionPatternPackageChangeToReleaseMultiStage, description: "Package mutation can cross bounded CI, registry, and cloud stages before release.",
			sourceRole: CompositionStageRoleSource, sinkRole: CompositionStageRolePrivilegedSink, outcome: "release_publish",
			sourceSystems: []string{CompositionSystemClassRepo, CompositionSystemClassCI, CompositionSystemClassPackage}, transformSystems: allTransforms,
			sinkSystems: []string{CompositionSystemClassCI, CompositionSystemClassPackage, CompositionSystemClassCloud, CompositionSystemClassSaaS}, sourceOK: pathMutatesPackage, sinkOK: pathReleasesPackage,
			minStages: minMultiStageCompositionDepth, maxStages: maxMultiStageCompositionDepth,
		},
	}
}

func multiStagePublicPattern(spec multiStageCompositionPatternSpec, stages []CompositionStage) CompositionPattern {
	return CompositionPattern{
		PatternID:    spec.id,
		Description:  spec.description,
		StageRoles:   orderedCompositionStageRoles(stages),
		OutcomeClass: spec.outcome,
		MinStages:    spec.minStages,
		MaxStages:    spec.maxStages,
		StageTemplates: []CompositionPatternStageTemplate{
			{Role: spec.sourceRole, AllowedSystemClasses: dedupeSortedStrings(spec.sourceSystems)},
			{Role: CompositionStageRoleTransform, AllowedSystemClasses: dedupeSortedStrings(spec.transformSystems)},
			{Role: spec.sinkRole, AllowedSystemClasses: dedupeSortedStrings(spec.sinkSystems)},
		},
		RequiredTransitionEvidence: []string{"attack_path", "authority_binding", "composition", "graph_edge", "imported_evidence", "workflow_chain"},
		TrustBoundaryConstraint:    multiStageTrustBoundaryConstraint,
	}
}

func multiStageSystemClass(path ActionPath) string {
	tool := strings.ToLower(strings.TrimSpace(path.ToolType))
	location := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path.Location), "\\", "/"))
	actions := strings.ToLower(strings.Join(append(append([]string(nil), path.ActionClasses...), path.WritePathClasses...), " "))
	if containsAnyText(tool+" "+location+" "+actions, "webhook", "slack", "teams", "email", "message", "notification", "communications") {
		return CompositionSystemClassCommunications
	}
	if containsAnyText(tool+" "+location, "saas", "salesforce", "servicenow", "jira", "notion") {
		return CompositionSystemClassSaaS
	}
	if containsAnyText(tool+" "+location, "aws", "gcp", "azure", "cloud", "kubernetes", "k8s", "cluster") {
		return CompositionSystemClassCloud
	}
	if containsAnyText(tool+" "+location, "github_actions", "github-actions", ".github/workflows", "jenkins", "circleci", "buildkite", "ci_agent") || strings.TrimSpace(path.WorkflowTriggerClass) != "" {
		return CompositionSystemClassCI
	}
	if containsAnyText(tool+" "+location+" "+actions, "package", "registry", "artifact", "dependency", "publish", "release") {
		return CompositionSystemClassPackage
	}
	if strings.TrimSpace(path.Repo) != "" {
		return CompositionSystemClassRepo
	}
	return CompositionSystemClassUnknown
}

func multiStageTrustBoundary(path ActionPath, systemClass string) string {
	orgRepo := strings.Trim(strings.TrimSpace(path.Org)+"/"+strings.TrimSpace(path.Repo), "/")
	if orgRepo == "" {
		orgRepo = "unknown"
	}
	suffix := orgRepo
	switch systemClass {
	case CompositionSystemClassCloud, CompositionSystemClassSaaS, CompositionSystemClassCommunications:
		suffix = firstNonEmptyString(strings.TrimSpace(path.ToolType), orgRepo)
	}
	return strings.TrimSpace(systemClass) + ":" + suffix
}

func knownMultiStageTrustBoundary(path ActionPath, systemClass string) bool {
	boundary := multiStageTrustBoundary(path, systemClass)
	return strings.TrimSpace(boundary) != "" && len(boundary) <= 180 && !strings.HasSuffix(boundary, ":unknown")
}

func multiStageSystemClassRank(value string) int {
	switch strings.TrimSpace(value) {
	case CompositionSystemClassRepo:
		return 0
	case CompositionSystemClassCI:
		return 1
	case CompositionSystemClassPackage:
		return 2
	case CompositionSystemClassCloud:
		return 3
	case CompositionSystemClassSaaS:
		return 4
	case CompositionSystemClassCommunications:
		return 5
	default:
		return 99
	}
}

func multiStageCorrelationRefs(path ActionPath, chainRefsByPath map[string][]string) []string {
	refs := []string{}
	for _, value := range append(append([]string(nil), path.WorkflowChainRefs...), chainRefsByPath[strings.TrimSpace(path.PathID)]...) {
		refs = append(refs, prefixedCompositionRef("workflow_chain", value))
	}
	for _, value := range path.AttackPathRefs {
		refs = append(refs, prefixedCompositionRef("attack_path", value))
	}
	for _, value := range path.AuthorityBindingRefs {
		refs = append(refs, prefixedCompositionRef("authority_binding", value))
	}
	if strings.TrimSpace(path.EndpointRefGroupID) != "" {
		refs = append(refs, prefixedCompositionRef("endpoint_group", path.EndpointRefGroupID))
	}
	for _, value := range path.PolicyRefs {
		refs = append(refs, prefixedCompositionRef("policy", value))
	}
	for _, value := range path.SourceFindingKeys {
		refs = append(refs, prefixedCompositionRef("source_finding", value))
	}
	for _, value := range path.EvidencePacketRefs {
		refs = append(refs, prefixedCompositionRef("imported_evidence", value))
	}
	for _, value := range path.CompositionIDs {
		refs = append(refs, prefixedCompositionRef("composition", value))
	}
	if path.ActionLineage != nil {
		for _, segment := range path.ActionLineage.Segments {
			for _, value := range segment.EdgeIDs {
				refs = append(refs, prefixedCompositionRef("graph_edge", value))
			}
		}
	}
	return dedupeSortedStrings(refs)
}

func prefixedCompositionRef(kind, raw string) string {
	value := strings.TrimSpace(raw)
	if !validMultiStageCorrelationRef(value) {
		return ""
	}
	prefix := strings.TrimSpace(kind) + ":"
	if strings.HasPrefix(value, prefix) {
		return value
	}
	return prefix + value
}

func validMultiStageCorrelationRef(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > 512 {
		return false
	}
	for _, character := range trimmed {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	safetyValue := multiStageCorrelationRefSafetyValue(trimmed)
	if safetyValue == "" {
		return false
	}
	normalized := strings.ReplaceAll(safetyValue, "\\", "/")
	if unsafeMultiStageCorrelationPathRef(normalized) {
		return false
	}
	return true
}

func multiStageCorrelationRefSafetyValue(value string) string {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	for _, prefix := range multiStageCorrelationRefKnownPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return trimmed
}

func unsafeMultiStageCorrelationPathRef(normalized string) bool {
	if normalized == ".." || strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "../") || strings.Contains(normalized, "/../") || strings.HasSuffix(normalized, "/..") {
		return true
	}
	return containsWindowsDrivePathRef(normalized)
}

func containsWindowsDrivePathRef(normalized string) bool {
	for index := 0; index+2 < len(normalized); index++ {
		if !asciiAlpha(normalized[index]) || normalized[index+1] != ':' || normalized[index+2] != '/' {
			continue
		}
		if index == 0 || normalized[index-1] == ':' || normalized[index-1] == '/' {
			return true
		}
	}
	return false
}

func asciiAlpha(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
}

func intersectSortedStrings(left, right []string) []string {
	set := map[string]struct{}{}
	for _, value := range left {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	out := []string{}
	for _, value := range right {
		trimmed := strings.TrimSpace(value)
		if _, ok := set[trimmed]; ok {
			out = append(out, trimmed)
		}
	}
	return dedupeSortedStrings(out)
}

func hasMultiStageTransitionEvidence(refs []string) bool {
	for _, ref := range refs {
		if strongMultiStageCorrelationRef(ref) {
			return true
		}
	}
	return false
}

func strongMultiStageCorrelationRef(ref string) bool {
	if !validMultiStageCorrelationRef(ref) {
		return false
	}
	for _, prefix := range []string{
		"workflow_chain:",
		"attack_path:",
		"authority_binding:",
		"graph_edge:",
		"imported_evidence:",
		"composition:",
	} {
		if strings.HasPrefix(strings.TrimSpace(ref), prefix) {
			return true
		}
	}
	return false
}

func stringInSet(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.TrimSpace(candidate) == strings.TrimSpace(value) {
			return true
		}
	}
	return false
}

func containsAnyText(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, strings.ToLower(strings.TrimSpace(candidate))) {
			return true
		}
	}
	return false
}

func orderedCompositionStageRoles(stages []CompositionStage) []string {
	out := make([]string, 0, len(stages))
	for _, stage := range stages {
		out = append(out, strings.TrimSpace(stage.Role))
	}
	return out
}

func multiStageCompositionID(patternID string, stages []CompositionStage, targetIdentity, outcomeKey string) string {
	parts := []string{"pattern=" + strings.TrimSpace(patternID)}
	for _, stage := range stages {
		parts = append(parts, strings.Join([]string{
			"role=" + strings.TrimSpace(stage.Role),
			"member=" + strings.TrimSpace(stage.ResolutionKey),
			"system=" + strings.TrimSpace(stage.SystemClass),
			"boundary=" + strings.TrimSpace(stage.TrustBoundary),
			"actions=" + strings.Join(dedupeSortedStrings(stage.ActionClasses), ","),
			"target_class=" + strings.TrimSpace(stage.TargetClass),
		}, ";"))
	}
	parts = append(parts, "target="+strings.TrimSpace(targetIdentity), "outcome="+strings.TrimSpace(outcomeKey))
	return "cap-" + stableCompositionHash(strings.Join(parts, "\x1f"))
}

func multiStageCompositionResolutionKey(paths []ActionPath) string {
	keys := make([]string, 0, len(paths))
	for _, path := range paths {
		keys = append(keys, compositionMemberKey(path))
	}
	return strings.Join(keys, "->")
}

func multiStageWorkflowRefs(stages []CompositionStage) []string {
	refs := []string{}
	for _, stage := range stages {
		for _, ref := range stage.CorrelationRefs {
			if strings.HasPrefix(ref, "workflow_chain:") {
				refs = append(refs, ref)
			}
		}
	}
	return dedupeSortedStrings(refs)
}

func multiStagePathObservedExecution(path ActionPath) bool {
	return strings.TrimSpace(path.RuntimeEvidenceState) == EvidenceStateVerified &&
		path.GaitCoverage != nil &&
		strings.TrimSpace(path.GaitCoverage.ActionOutcome.Status) == GaitStatusPresent &&
		len(path.GaitCoverage.ActionOutcome.EvidenceRefs) > 0
}

func annotateMultiStageAlternateRoutes(compositions []ComposedActionPath) {
	groups := map[string][]int{}
	for index, composition := range compositions {
		if strings.TrimSpace(composition.ReachabilityState) == "" || len(composition.Stages) < minMultiStageCompositionDepth {
			continue
		}
		first := composition.Stages[0]
		last := composition.Stages[len(composition.Stages)-1]
		key := strings.Join([]string{
			strings.TrimSpace(composition.PatternID),
			strings.TrimSpace(composition.DurableOutcomeKey),
			strings.TrimSpace(first.ResolutionKey),
			strings.TrimSpace(last.ResolutionKey),
		}, "|")
		groups[key] = append(groups[key], index)
	}
	for _, indexes := range groups {
		if len(indexes) < 2 {
			continue
		}
		for _, index := range indexes {
			refs := []string{}
			for _, peerIndex := range indexes {
				if peerIndex != index {
					refs = append(refs, compositions[peerIndex].CompositionID)
				}
			}
			refs = dedupeSortedStrings(refs)
			if len(refs) > maxMultiStageAlternateRouteRefs {
				omitted := len(refs) - maxMultiStageAlternateRouteRefs
				refs = refs[:maxMultiStageAlternateRouteRefs]
				compositions[index].Truncations = append(compositions[index].Truncations, CompositionTruncation{
					PatternID:          compositions[index].PatternID,
					Reason:             CompositionTruncationCandidateCap,
					Limit:              maxMultiStageAlternateRouteRefs,
					ObservedCandidates: len(refs) + omitted,
					OmittedCandidates:  omitted,
				})
			}
			compositions[index].AlternateRouteRefs = refs
			for stageIndex := range compositions[index].Stages {
				compositions[index].Stages[stageIndex].AlternateRouteRefs = append([]string(nil), refs...)
			}
			for transitionIndex := range compositions[index].Transitions {
				compositions[index].Transitions[transitionIndex].AlternateRouteRefs = append([]string(nil), refs...)
			}
			compositions[index].Truncations = normalizeCompositionTruncations(compositions[index].Truncations)
			compositions[index].ProposedActionContract = BuildProposedActionContract(compositions[index])
			if compositions[index].ProposedActionContract != nil {
				compositions[index].ProposedActionContractRefs = []string{compositions[index].ProposedActionContract.ContractID}
			}
		}
	}
}

func mergeMultiStageComposedActionPath(current, incoming ComposedActionPath) ComposedActionPath {
	if strings.TrimSpace(current.CompositionID) == "" {
		return incoming
	}
	merged := current
	merged.PathIDs = dedupeSortedStrings(append(merged.PathIDs, incoming.PathIDs...))
	merged.WorkflowChainRefs = dedupeSortedStrings(append(merged.WorkflowChainRefs, incoming.WorkflowChainRefs...))
	merged.EvidenceRefs = dedupeSortedStrings(append(merged.EvidenceRefs, incoming.EvidenceRefs...))
	merged.ProofRefs = dedupeSortedStrings(append(merged.ProofRefs, incoming.ProofRefs...))
	merged.SourceDecisionRefs = dedupeSortedStrings(append(merged.SourceDecisionRefs, incoming.SourceDecisionRefs...))
	merged.TruncatedCandidates = dedupeSortedStrings(append(merged.TruncatedCandidates, incoming.TruncatedCandidates...))
	merged.Truncations = normalizeCompositionTruncations(append(merged.Truncations, incoming.Truncations...))
	merged.Contradictions = mergeContradictions(merged.Contradictions, incoming.Contradictions)
	merged.GaitCoverage = MergeGaitCoverage(merged.GaitCoverage, incoming.GaitCoverage)
	merged.EvidenceState = compositionEvidenceState(merged.EvidenceState, incoming.EvidenceState)
	merged.FreshnessState = compositionFreshnessState(merged.FreshnessState, incoming.FreshnessState)
	merged.PolicyCoverageStatus = compositionPolicyCoverageStatus(merged.PolicyCoverageStatus, incoming.PolicyCoverageStatus)
	merged.RuntimeEvidenceAbsenceStatus = compositionRuntimeAbsence(merged.RuntimeEvidenceAbsenceStatus, incoming.RuntimeEvidenceAbsenceStatus)
	merged.RiskTier = compositionRiskTierFromValues(merged.RiskTier, incoming.RiskTier)
	merged.RecommendedControl = compositionRecommendedControlFromValues(merged.RecommendedControl, incoming.RecommendedControl)
	merged.RecommendedControlReasons = dedupeSortedStrings(append(merged.RecommendedControlReasons, incoming.RecommendedControlReasons...))
	merged.EscalatingTransitionRefs = dedupeSortedStrings(append(merged.EscalatingTransitionRefs, incoming.EscalatingTransitionRefs...))
	merged.ClosureRequirements = CloneClosureRequirements(firstNonEmptyClosureRequirements(merged.ClosureRequirements, incoming.ClosureRequirements))
	merged.EvidenceCompleteness = mergeEvidenceCompletenessValues(merged.EvidenceCompleteness, incoming.EvidenceCompleteness)
	for index := range merged.Stages {
		if index >= len(incoming.Stages) || merged.Stages[index].ResolutionKey != incoming.Stages[index].ResolutionKey {
			continue
		}
		merged.Stages[index].ActionClasses = dedupeSortedStrings(append(merged.Stages[index].ActionClasses, incoming.Stages[index].ActionClasses...))
		merged.Stages[index].CorrelationRefs = dedupeSortedStrings(append(merged.Stages[index].CorrelationRefs, incoming.Stages[index].CorrelationRefs...))
		merged.Stages[index].EvidenceRefs = dedupeSortedStrings(append(merged.Stages[index].EvidenceRefs, incoming.Stages[index].EvidenceRefs...))
		merged.Stages[index].ProofRefs = dedupeSortedStrings(append(merged.Stages[index].ProofRefs, incoming.Stages[index].ProofRefs...))
		merged.Stages[index].SourceDecisionRefs = dedupeSortedStrings(append(merged.Stages[index].SourceDecisionRefs, incoming.Stages[index].SourceDecisionRefs...))
		merged.Stages[index].Contradictions = mergeContradictions(merged.Stages[index].Contradictions, incoming.Stages[index].Contradictions)
		merged.Stages[index].GaitCoverage = MergeGaitCoverage(merged.Stages[index].GaitCoverage, incoming.Stages[index].GaitCoverage)
		merged.Stages[index].EvidenceState = compositionEvidenceState(merged.Stages[index].EvidenceState, incoming.Stages[index].EvidenceState)
		merged.Stages[index].FreshnessState = compositionFreshnessState(merged.Stages[index].FreshnessState, incoming.Stages[index].FreshnessState)
		merged.Stages[index].PolicyCoverageStatus = compositionPolicyCoverageStatus(merged.Stages[index].PolicyCoverageStatus, incoming.Stages[index].PolicyCoverageStatus)
		merged.Stages[index].RuntimeEvidenceAbsenceStatus = compositionRuntimeAbsence(merged.Stages[index].RuntimeEvidenceAbsenceStatus, incoming.Stages[index].RuntimeEvidenceAbsenceStatus)
		merged.Stages[index].ObservedExecution = merged.Stages[index].ObservedExecution || incoming.Stages[index].ObservedExecution
		if merged.Stages[index].ObservedExecution {
			merged.Stages[index].ReachabilityState = CompositionReachabilityObserved
		} else {
			merged.Stages[index].ReachabilityState = CompositionReachabilityPossible
		}
	}
	for index := range merged.Transitions {
		if index >= len(incoming.Transitions) || merged.Transitions[index].FromStageID != incoming.Transitions[index].FromStageID || merged.Transitions[index].ToStageID != incoming.Transitions[index].ToStageID {
			continue
		}
		merged.Transitions[index].CorrelationRefs = dedupeSortedStrings(append(merged.Transitions[index].CorrelationRefs, incoming.Transitions[index].CorrelationRefs...))
	}
	merged.ClaimState = compositionClaimState(merged.EvidenceState, merged.PolicyCoverageStatus, merged.FreshnessState, merged.GaitCoverage, merged.Stages, nil)
	merged.ObservedExecution = merged.ClaimState == CompositionClaimObservedExecution
	merged.ReachabilityState = CompositionReachabilityPossible
	if merged.ObservedExecution {
		merged.ReachabilityState = CompositionReachabilityObserved
	}
	hydrateCompositionTransitions(&merged)
	refreshCompositionEscalatingTransitionRefs(&merged)
	merged.ProposedActionContract = BuildProposedActionContract(merged)
	if merged.ProposedActionContract != nil {
		merged.ProposedActionContractRefs = []string{merged.ProposedActionContract.ContractID}
	}
	return merged
}

func attachMultiStageTruncation(byID map[string]ComposedActionPath, spec multiStageCompositionPatternSpec, state *multiStageCompositionBuildState) {
	if state == nil || (len(state.truncatedCandidates) == 0 && len(state.truncations) == 0) {
		return
	}
	ids := []string{}
	for id, composition := range byID {
		if composition.PatternID == spec.id {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		receipt := multiStageTruncationReceipt(spec, state)
		if strings.TrimSpace(receipt.CompositionID) != "" {
			byID[receipt.CompositionID] = receipt
		}
		return
	}
	sort.Strings(ids)
	composition := byID[ids[0]]
	composition.TruncatedCandidates = dedupeSortedStrings(append(composition.TruncatedCandidates, state.truncatedCandidates...))
	composition.Truncations = normalizeCompositionTruncations(append(composition.Truncations, state.truncations...))
	byID[ids[0]] = composition
}

func multiStageTruncationReceipt(spec multiStageCompositionPatternSpec, state *multiStageCompositionBuildState) ComposedActionPath {
	if state == nil {
		return ComposedActionPath{}
	}
	truncatedCandidates := dedupeSortedStrings(state.truncatedCandidates)
	truncations := normalizeCompositionTruncations(state.truncations)
	if len(truncatedCandidates) == 0 && len(truncations) == 0 {
		return ComposedActionPath{}
	}
	return ComposedActionPath{
		CompositionID:          multiStageTruncationReceiptID(spec.id, truncatedCandidates, truncations),
		PatternID:              spec.id,
		Pattern:                multiStagePublicPattern(spec, nil),
		ResolutionKey:          "truncation:" + strings.TrimSpace(spec.id),
		OutcomeClass:           spec.outcome,
		RecommendedControl:     RecommendedControlAllow,
		ReachabilityState:      CompositionReachabilityIncomplete,
		TruncatedCandidates:    truncatedCandidates,
		Truncations:            truncations,
		ProposedActionContract: nil,
	}
}

func multiStageTruncationReceiptID(patternID string, truncatedCandidates []string, truncations []CompositionTruncation) string {
	parts := []string{"pattern=" + strings.TrimSpace(patternID), "kind=truncation_receipt"}
	for _, candidate := range truncatedCandidates {
		parts = append(parts, "candidate="+strings.TrimSpace(candidate))
	}
	for _, truncation := range truncations {
		parts = append(parts, strings.Join([]string{
			"truncation",
			strings.TrimSpace(truncation.PatternID),
			strings.TrimSpace(truncation.Reason),
			strconv.Itoa(truncation.Limit),
			strconv.Itoa(truncation.ObservedCandidates),
			strconv.Itoa(truncation.OmittedCandidates),
		}, "="))
	}
	return "cap-" + stableCompositionHash(strings.Join(parts, "\x1f"))
}

func normalizeCompositionTruncations(values []CompositionTruncation) []CompositionTruncation {
	byKey := map[string]CompositionTruncation{}
	for _, value := range values {
		if strings.TrimSpace(value.PatternID) == "" || strings.TrimSpace(value.Reason) == "" || value.Limit <= 0 {
			continue
		}
		key := strings.Join([]string{value.PatternID, value.Reason, strconv.Itoa(value.Limit)}, "|")
		current := byKey[key]
		if current.PatternID == "" {
			current = value
		} else {
			if value.ObservedCandidates > current.ObservedCandidates {
				current.ObservedCandidates = value.ObservedCandidates
			}
			current.OmittedCandidates += value.OmittedCandidates
		}
		byKey[key] = current
	}
	out := make([]CompositionTruncation, 0, len(byKey))
	for _, value := range byKey {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PatternID != out[j].PatternID {
			return out[i].PatternID < out[j].PatternID
		}
		if out[i].Reason != out[j].Reason {
			return out[i].Reason < out[j].Reason
		}
		return out[i].Limit < out[j].Limit
	})
	return out
}
