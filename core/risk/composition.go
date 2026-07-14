package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

const (
	CompositionStageRoleSource          = "source"
	CompositionStageRoleTransform       = "transform"
	CompositionStageRoleSink            = "sink"
	CompositionStageRoleInternalSink    = "internal_sink"
	CompositionStageRoleExternalSink    = "external_sink"
	CompositionStageRolePrivilegedSink  = "privileged_sink"
	CompositionStageRoleDestructiveSink = "destructive_sink"

	CompositionPatternSensitiveReadToEgress      = "sensitive_read_to_egress"
	CompositionPatternSecretToNetwork            = "secret_to_network"
	CompositionPatternCodeToDeploy               = "code_to_deploy"
	CompositionPatternWorkflowMutationProduction = "workflow_mutation_to_production"
	CompositionPatternPackageChangeToRelease     = "package_change_to_release"

	CompositionClaimStaticOnly         = "static_only"
	CompositionClaimPartiallyEvidenced = "partially_evidenced"
	CompositionClaimDeclaredPolicyOnly = "declared_policy_only"
	CompositionClaimRuntimeControlled  = "runtime_controlled"
	CompositionClaimObservedExecution  = "observed_execution"
	CompositionClaimContradictory      = "contradictory"
	CompositionClaimUnknown            = "unknown"

	maxComposedActionPathCandidates = 128
)

type CompositionPattern struct {
	PatternID    string   `json:"pattern_id"`
	Description  string   `json:"description,omitempty"`
	StageRoles   []string `json:"stage_roles,omitempty"`
	OutcomeClass string   `json:"outcome_class,omitempty"`
}

type CompositionStage struct {
	StageID                      string                         `json:"stage_id"`
	Role                         string                         `json:"role"`
	PathID                       string                         `json:"path_id,omitempty"`
	ResolutionKey                string                         `json:"resolution_key,omitempty"`
	ToolType                     string                         `json:"tool_type,omitempty"`
	Location                     string                         `json:"location,omitempty"`
	ActionClasses                []string                       `json:"action_classes,omitempty"`
	TargetClass                  string                         `json:"target_class,omitempty"`
	EvidenceState                string                         `json:"evidence_state,omitempty"`
	FreshnessState               string                         `json:"freshness_state,omitempty"`
	PolicyCoverageStatus         string                         `json:"policy_coverage_status,omitempty"`
	GaitCoverage                 *GaitCoverage                  `json:"gait_coverage,omitempty"`
	RuntimeEvidenceAbsenceStatus string                         `json:"runtime_evidence_absence_status,omitempty"`
	Contradictions               []evidencepolicy.Contradiction `json:"contradictions,omitempty"`
	EvidenceRefs                 []string                       `json:"evidence_refs,omitempty"`
	ProofRefs                    []string                       `json:"proof_refs,omitempty"`
	SourceDecisionRefs           []string                       `json:"source_decision_refs,omitempty"`
}

type CompositionTransition struct {
	TransitionID                 string        `json:"transition_id"`
	FromStageID                  string        `json:"from_stage_id"`
	ToStageID                    string        `json:"to_stage_id"`
	ClaimState                   string        `json:"claim_state,omitempty"`
	EvidenceState                string        `json:"evidence_state,omitempty"`
	PolicyCoverageStatus         string        `json:"policy_coverage_status,omitempty"`
	GaitCoverage                 *GaitCoverage `json:"gait_coverage,omitempty"`
	RuntimeEvidenceAbsenceStatus string        `json:"runtime_evidence_absence_status,omitempty"`
	EvidenceRefs                 []string      `json:"evidence_refs,omitempty"`
	ProofRefs                    []string      `json:"proof_refs,omitempty"`
	SourceDecisionRefs           []string      `json:"source_decision_refs,omitempty"`
	ReasonCodes                  []string      `json:"reason_codes,omitempty"`
}

type ComposedActionPath struct {
	CompositionID                string                         `json:"composition_id"`
	PatternID                    string                         `json:"pattern_id"`
	Pattern                      CompositionPattern             `json:"pattern"`
	ResolutionKey                string                         `json:"resolution_key,omitempty"`
	PathIDs                      []string                       `json:"path_ids,omitempty"`
	WorkflowChainRefs            []string                       `json:"workflow_chain_refs,omitempty"`
	Stages                       []CompositionStage             `json:"stages"`
	Transitions                  []CompositionTransition        `json:"transitions,omitempty"`
	TargetIdentity               string                         `json:"target_identity,omitempty"`
	DurableOutcomeKey            string                         `json:"durable_outcome_key,omitempty"`
	AffectedAsset                string                         `json:"affected_asset,omitempty"`
	OutcomeClass                 string                         `json:"outcome_class,omitempty"`
	Environment                  string                         `json:"environment,omitempty"`
	TargetClass                  string                         `json:"target_class,omitempty"`
	ClaimState                   string                         `json:"claim_state,omitempty"`
	EvidenceState                string                         `json:"evidence_state,omitempty"`
	FreshnessState               string                         `json:"freshness_state,omitempty"`
	PolicyCoverageStatus         string                         `json:"policy_coverage_status,omitempty"`
	GaitCoverage                 *GaitCoverage                  `json:"gait_coverage,omitempty"`
	RuntimeEvidenceAbsenceStatus string                         `json:"runtime_evidence_absence_status,omitempty"`
	Contradictions               []evidencepolicy.Contradiction `json:"contradictions,omitempty"`
	EvidenceRefs                 []string                       `json:"evidence_refs,omitempty"`
	ProofRefs                    []string                       `json:"proof_refs,omitempty"`
	SourceDecisionRefs           []string                       `json:"source_decision_refs,omitempty"`
	RiskTier                     string                         `json:"risk_tier,omitempty"`
	RecommendedControl           string                         `json:"recommended_control,omitempty"`
	ClosureRequirements          []ClosureRequirement           `json:"closure_requirements,omitempty"`
	EvidenceCompleteness         *EvidenceCompleteness          `json:"evidence_completeness,omitempty"`
	UnsupportedSurfaces          []string                       `json:"unsupported_surfaces,omitempty"`
	TruncatedCandidates          []string                       `json:"truncated_candidates,omitempty"`
	ProposedActionContract       *ProposedActionContract        `json:"proposed_action_contract,omitempty"`
	ProposedActionContractRefs   []string                       `json:"proposed_action_contract_refs,omitempty"`
}

type ComposedActionPathSummary struct {
	TotalCompositions          int `json:"total_compositions"`
	ControlFirstCompositions   int `json:"control_first_compositions"`
	StaticOnlyCompositions     int `json:"static_only_compositions"`
	RuntimeControlled          int `json:"runtime_controlled_compositions"`
	ObservedExecutions         int `json:"observed_execution_compositions"`
	ContradictoryCompositions  int `json:"contradictory_compositions"`
	TruncatedCandidatePatterns int `json:"truncated_candidate_patterns,omitempty"`
}

type ComposedActionPathToControlFirst struct {
	Summary ComposedActionPathSummary `json:"summary"`
	Path    ComposedActionPath        `json:"path"`
}

type compositionPatternSpec struct {
	id          string
	description string
	sourceRole  string
	sinkRole    string
	outcome     string
	sourceOK    func(ActionPath) bool
	sinkOK      func(ActionPath) bool
}

func BuildComposedActionPaths(paths []ActionPath, workflowChains *agentresolver.WorkflowChainArtifact) ([]ComposedActionPath, *ComposedActionPathToControlFirst) {
	if len(paths) == 0 {
		return nil, nil
	}
	projected := ProjectActionPaths(paths)
	chainRefsByPath := agentresolver.WorkflowChainRefsByPath(workflowChains)
	specs := compositionPatternSpecs()
	compositionsByKey := map[string]ComposedActionPath{}
	truncated := map[string][]string{}

	for _, spec := range specs {
		sources := filterCompositionCandidates(projected, spec.sourceOK)
		sinks := filterCompositionCandidates(projected, spec.sinkOK)
		count := 0
		for _, source := range sources {
			for _, sink := range sinks {
				if !compositionCandidatesCompatible(source, sink) {
					continue
				}
				count++
				if count > maxComposedActionPathCandidates {
					truncated[spec.id] = append(truncated[spec.id], compositionCandidateKey(source)+"->"+compositionCandidateKey(sink))
					continue
				}
				composition := buildComposedActionPath(spec, source, sink, chainRefsByPath)
				compositionsByKey[composition.CompositionID] = mergeComposedActionPath(compositionsByKey[composition.CompositionID], composition)
			}
		}
	}

	if len(compositionsByKey) == 0 {
		return nil, nil
	}
	compositions := make([]ComposedActionPath, 0, len(compositionsByKey))
	for _, composition := range compositionsByKey {
		composition.TruncatedCandidates = dedupeSortedStrings(composition.TruncatedCandidates)
		compositions = append(compositions, composition)
	}
	sort.Slice(compositions, func(i, j int) bool {
		return compareComposedActionPaths(compositions[i], compositions[j])
	})
	attachTruncatedCandidates(compositions, truncated)
	summary := SummarizeComposedActionPaths(compositions)
	return compositions, &ComposedActionPathToControlFirst{
		Summary: summary,
		Path:    compositions[0],
	}
}

func DecorateActionPathCompositionRefs(paths []ActionPath, compositions []ComposedActionPath) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	refsByPath := map[string][]string{}
	contractRefsByPath := map[string][]string{}
	for _, composition := range compositions {
		for _, pathID := range composition.PathIDs {
			trimmed := strings.TrimSpace(pathID)
			if trimmed == "" {
				continue
			}
			refsByPath[trimmed] = append(refsByPath[trimmed], strings.TrimSpace(composition.CompositionID))
			contractRefsByPath[trimmed] = append(contractRefsByPath[trimmed], composition.ProposedActionContractRefs...)
		}
	}
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		copyPath := path
		copyPath.CompositionIDs = dedupeSortedStrings(append(copyPath.CompositionIDs, refsByPath[strings.TrimSpace(path.PathID)]...))
		copyPath.ProposedActionContractRefs = dedupeSortedStrings(append(copyPath.ProposedActionContractRefs, contractRefsByPath[strings.TrimSpace(path.PathID)]...))
		out = append(out, copyPath)
	}
	return out
}

func SummarizeComposedActionPaths(paths []ComposedActionPath) ComposedActionPathSummary {
	summary := ComposedActionPathSummary{TotalCompositions: len(paths)}
	truncatedPatterns := map[string]struct{}{}
	for _, path := range paths {
		if strings.TrimSpace(path.RecommendedControl) != RecommendedControlAllow {
			summary.ControlFirstCompositions++
		}
		switch strings.TrimSpace(path.ClaimState) {
		case CompositionClaimStaticOnly:
			summary.StaticOnlyCompositions++
		case CompositionClaimRuntimeControlled:
			summary.RuntimeControlled++
		case CompositionClaimObservedExecution:
			summary.ObservedExecutions++
		case CompositionClaimContradictory:
			summary.ContradictoryCompositions++
		}
		if len(path.TruncatedCandidates) > 0 {
			patternID := strings.TrimSpace(path.PatternID)
			if patternID == "" {
				patternID = strings.TrimSpace(path.CompositionID)
			}
			if patternID != "" {
				truncatedPatterns[patternID] = struct{}{}
			}
		}
	}
	summary.TruncatedCandidatePatterns = len(truncatedPatterns)
	return summary
}

func compositionPatternSpecs() []compositionPatternSpec {
	return []compositionPatternSpec{
		{
			id:          CompositionPatternSensitiveReadToEgress,
			description: "Sensitive read capability can reach external egress or export.",
			sourceRole:  CompositionStageRoleSource,
			sinkRole:    CompositionStageRoleExternalSink,
			outcome:     "data_egress",
			sourceOK:    pathHasSensitiveRead,
			sinkOK:      pathHasExternalEgress,
		},
		{
			id:          CompositionPatternSecretToNetwork,
			description: "Secret or credential authority can reach network egress.",
			sourceRole:  CompositionStageRoleSource,
			sinkRole:    CompositionStageRoleExternalSink,
			outcome:     "network_egress",
			sourceOK:    pathHasSecretAuthority,
			sinkOK:      pathHasNetworkEgress,
		},
		{
			id:          CompositionPatternCodeToDeploy,
			description: "Code or repository mutation can reach deployment authority.",
			sourceRole:  CompositionStageRoleSource,
			sinkRole:    CompositionStageRolePrivilegedSink,
			outcome:     "production_deploy",
			sourceOK:    pathMutatesCode,
			sinkOK:      pathDeploysProduction,
		},
		{
			id:          CompositionPatternWorkflowMutationProduction,
			description: "Workflow mutation can reach production-impacting execution.",
			sourceRole:  CompositionStageRoleTransform,
			sinkRole:    CompositionStageRolePrivilegedSink,
			outcome:     "production_mutation",
			sourceOK:    pathMutatesWorkflow,
			sinkOK:      pathProductionImpact,
		},
		{
			id:          CompositionPatternPackageChangeToRelease,
			description: "Package or dependency change can reach release or publish authority.",
			sourceRole:  CompositionStageRoleSource,
			sinkRole:    CompositionStageRolePrivilegedSink,
			outcome:     "release_publish",
			sourceOK:    pathMutatesPackage,
			sinkOK:      pathReleasesPackage,
		},
	}
}

func filterCompositionCandidates(paths []ActionPath, predicate func(ActionPath) bool) []ActionPath {
	out := []ActionPath{}
	for _, path := range paths {
		if predicate(path) {
			out = append(out, path)
		}
	}
	return out
}

func compositionCandidatesCompatible(source, sink ActionPath) bool {
	if strings.TrimSpace(source.Org) != strings.TrimSpace(sink.Org) {
		return false
	}
	return strings.TrimSpace(source.Repo) == strings.TrimSpace(sink.Repo)
}

func buildComposedActionPath(spec compositionPatternSpec, source, sink ActionPath, chainRefsByPath map[string][]string) ComposedActionPath {
	stages := dedupeCompositionStages([]CompositionStage{
		buildCompositionStage(spec.sourceRole, source),
		buildCompositionStage(spec.sinkRole, sink),
	})
	targetIdentity := compositionTargetIdentity(spec, []ActionPath{source, sink})
	environment := compositionEnvironment(spec, []ActionPath{source, sink})
	targetClass := compositionTargetClass([]ActionPath{source, sink})
	outcomeKey := strings.Join(dedupeSortedStrings([]string{
		"asset=" + targetIdentity,
		"target_class=" + targetClass,
		"outcome=" + spec.outcome,
		"environment=" + environment,
	}), "|")
	compositionID := compositionID(spec.id, stages, targetIdentity, outcomeKey)
	transitions := buildCompositionTransitions(compositionID, stages)
	paths := []ActionPath{source, sink}
	workflowRefs := compositionWorkflowRefs(paths, chainRefsByPath)
	evidenceState := compositionEvidenceStateFromStages(stages)
	freshnessState := compositionFreshnessStateFromStages(stages)
	policyCoverage := compositionPolicyCoverageStatusFromStages(stages)
	gaitCoverage := compositionGaitCoverageFromStages(stages)
	runtimeAbsence := compositionRuntimeAbsenceFromStages(stages)
	claimState := compositionClaimState(evidenceState, policyCoverage, gaitCoverage, paths)
	recommended := compositionRecommendedControl(paths, claimState)
	composition := ComposedActionPath{
		CompositionID:                compositionID,
		PatternID:                    spec.id,
		Pattern:                      CompositionPattern{PatternID: spec.id, Description: spec.description, StageRoles: compositionStageRoles(stages), OutcomeClass: spec.outcome},
		ResolutionKey:                compositionResolutionKey(paths),
		PathIDs:                      compositionPathIDs(paths),
		WorkflowChainRefs:            workflowRefs,
		Stages:                       stages,
		Transitions:                  transitions,
		TargetIdentity:               targetIdentity,
		DurableOutcomeKey:            outcomeKey,
		AffectedAsset:                targetIdentity,
		OutcomeClass:                 spec.outcome,
		Environment:                  environment,
		TargetClass:                  targetClass,
		ClaimState:                   claimState,
		EvidenceState:                evidenceState,
		FreshnessState:               freshnessState,
		PolicyCoverageStatus:         policyCoverage,
		GaitCoverage:                 gaitCoverage,
		RuntimeEvidenceAbsenceStatus: runtimeAbsence,
		Contradictions:               compositionContradictions(paths),
		EvidenceRefs:                 compositionEvidenceRefs(paths),
		ProofRefs:                    compositionProofRefs(paths),
		SourceDecisionRefs:           compositionSourceDecisionRefs(paths),
		RiskTier:                     compositionRiskTier(paths),
		RecommendedControl:           recommended,
		ClosureRequirements:          compositionClosureRequirements(paths),
		EvidenceCompleteness:         compositionEvidenceCompleteness(paths),
	}
	for idx := range composition.Transitions {
		composition.Transitions[idx].ClaimState = claimState
		composition.Transitions[idx].EvidenceState = evidenceState
		composition.Transitions[idx].PolicyCoverageStatus = policyCoverage
		composition.Transitions[idx].GaitCoverage = CloneGaitCoverage(gaitCoverage)
		composition.Transitions[idx].RuntimeEvidenceAbsenceStatus = runtimeAbsence
		composition.Transitions[idx].EvidenceRefs = append([]string(nil), composition.EvidenceRefs...)
		composition.Transitions[idx].ProofRefs = append([]string(nil), composition.ProofRefs...)
		composition.Transitions[idx].SourceDecisionRefs = append([]string(nil), composition.SourceDecisionRefs...)
		composition.Transitions[idx].ReasonCodes = dedupeSortedStrings([]string{"pattern:" + spec.id, "claim_state:" + claimState})
	}
	composition.ProposedActionContract = BuildProposedActionContract(composition)
	if composition.ProposedActionContract != nil {
		composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	}
	return composition
}

func attachTruncatedCandidates(compositions []ComposedActionPath, truncated map[string][]string) {
	if len(compositions) == 0 || len(truncated) == 0 {
		return
	}
	firstByPattern := map[string]int{}
	for idx, composition := range compositions {
		patternID := strings.TrimSpace(composition.PatternID)
		if patternID == "" {
			continue
		}
		if _, ok := firstByPattern[patternID]; !ok {
			firstByPattern[patternID] = idx
		}
	}
	for patternID, candidates := range truncated {
		idx, ok := firstByPattern[strings.TrimSpace(patternID)]
		if !ok || len(candidates) == 0 {
			continue
		}
		compositions[idx].TruncatedCandidates = dedupeSortedStrings(append(compositions[idx].TruncatedCandidates, candidates...))
	}
}

func buildCompositionStage(role string, path ActionPath) CompositionStage {
	stage := CompositionStage{
		Role:                         strings.TrimSpace(role),
		PathID:                       strings.TrimSpace(path.PathID),
		ResolutionKey:                compositionMemberKey(path),
		ToolType:                     strings.TrimSpace(path.ToolType),
		Location:                     strings.TrimSpace(path.Location),
		ActionClasses:                dedupeSortedStrings(path.ActionClasses),
		TargetClass:                  strings.TrimSpace(path.TargetClass),
		EvidenceState:                pathConservativeEvidenceState(path),
		FreshnessState:               pathFreshnessState(path),
		PolicyCoverageStatus:         firstNonEmptyString(strings.TrimSpace(path.PolicyCoverageStatus), PolicyCoverageStatusNone),
		GaitCoverage:                 CloneGaitCoverage(path.GaitCoverage),
		RuntimeEvidenceAbsenceStatus: RuntimeEvidenceAbsenceStatus(path),
		Contradictions:               append([]evidencepolicy.Contradiction(nil), path.Contradictions...),
		EvidenceRefs:                 compositionEvidenceRefs([]ActionPath{path}),
		ProofRefs:                    compositionProofRefs([]ActionPath{path}),
		SourceDecisionRefs:           compositionSourceDecisionRefs([]ActionPath{path}),
	}
	stage.StageID = compositionStageID(role, stage.ResolutionKey, stage.TargetClass, stage.EvidenceState)
	return stage
}

func dedupeCompositionStages(stages []CompositionStage) []CompositionStage {
	byKey := map[string]CompositionStage{}
	for _, stage := range stages {
		key := strings.Join([]string{stage.Role, stage.ResolutionKey, stage.TargetClass}, "|")
		current, ok := byKey[key]
		if !ok {
			byKey[key] = stage
			continue
		}
		current.PathID = firstNonEmptyString(current.PathID, stage.PathID)
		current.ActionClasses = dedupeSortedStrings(append(current.ActionClasses, stage.ActionClasses...))
		current.EvidenceRefs = dedupeSortedStrings(append(current.EvidenceRefs, stage.EvidenceRefs...))
		current.ProofRefs = dedupeSortedStrings(append(current.ProofRefs, stage.ProofRefs...))
		current.SourceDecisionRefs = dedupeSortedStrings(append(current.SourceDecisionRefs, stage.SourceDecisionRefs...))
		current.Contradictions = append(current.Contradictions, stage.Contradictions...)
		current.GaitCoverage = MergeGaitCoverage(current.GaitCoverage, stage.GaitCoverage)
		current.EvidenceState = compositionEvidenceState(current.EvidenceState, stage.EvidenceState)
		current.FreshnessState = compositionFreshnessState(current.FreshnessState, stage.FreshnessState)
		current.PolicyCoverageStatus = choosePolicyCoverageStatus(current.PolicyCoverageStatus, stage.PolicyCoverageStatus)
		current.RuntimeEvidenceAbsenceStatus = compositionRuntimeAbsence(current.RuntimeEvidenceAbsenceStatus, stage.RuntimeEvidenceAbsenceStatus)
		byKey[key] = current
	}
	out := make([]CompositionStage, 0, len(byKey))
	for _, stage := range byKey {
		out = append(out, stage)
	}
	sort.Slice(out, func(i, j int) bool {
		if compositionStageRoleRank(out[i].Role) != compositionStageRoleRank(out[j].Role) {
			return compositionStageRoleRank(out[i].Role) < compositionStageRoleRank(out[j].Role)
		}
		if out[i].ResolutionKey != out[j].ResolutionKey {
			return out[i].ResolutionKey < out[j].ResolutionKey
		}
		return out[i].StageID < out[j].StageID
	})
	return out
}

func buildCompositionTransitions(compositionID string, stages []CompositionStage) []CompositionTransition {
	if len(stages) < 2 {
		return nil
	}
	out := make([]CompositionTransition, 0, len(stages)-1)
	for idx := 0; idx < len(stages)-1; idx++ {
		from := stages[idx]
		to := stages[idx+1]
		transitionID := "cat-" + stableCompositionHash(strings.Join([]string{compositionID, from.StageID, to.StageID}, "|"))
		out = append(out, CompositionTransition{
			TransitionID: transitionID,
			FromStageID:  from.StageID,
			ToStageID:    to.StageID,
		})
	}
	return out
}

func mergeComposedActionPath(current, incoming ComposedActionPath) ComposedActionPath {
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
	merged.ProposedActionContractRefs = dedupeSortedStrings(append(merged.ProposedActionContractRefs, incoming.ProposedActionContractRefs...))
	merged.GaitCoverage = MergeGaitCoverage(merged.GaitCoverage, incoming.GaitCoverage)
	merged.EvidenceState = compositionEvidenceState(merged.EvidenceState, incoming.EvidenceState)
	merged.FreshnessState = compositionFreshnessState(merged.FreshnessState, incoming.FreshnessState)
	merged.PolicyCoverageStatus = choosePolicyCoverageStatus(merged.PolicyCoverageStatus, incoming.PolicyCoverageStatus)
	merged.RuntimeEvidenceAbsenceStatus = compositionRuntimeAbsence(merged.RuntimeEvidenceAbsenceStatus, incoming.RuntimeEvidenceAbsenceStatus)
	merged.RiskTier = compositionRiskTierFromValues(merged.RiskTier, incoming.RiskTier)
	merged.RecommendedControl = compositionRecommendedControlFromValues(merged.RecommendedControl, incoming.RecommendedControl)
	merged.ClaimState = compositionClaimState(merged.EvidenceState, merged.PolicyCoverageStatus, merged.GaitCoverage, nil)
	if strings.TrimSpace(incoming.ClaimState) == CompositionClaimObservedExecution || strings.TrimSpace(current.ClaimState) == CompositionClaimObservedExecution {
		merged.ClaimState = CompositionClaimObservedExecution
	}
	merged.ProposedActionContract = BuildProposedActionContract(merged)
	if merged.ProposedActionContract != nil {
		merged.ProposedActionContractRefs = []string{merged.ProposedActionContract.ContractID}
	} else {
		merged.ProposedActionContractRefs = nil
	}
	return merged
}

func compareComposedActionPaths(left, right ComposedActionPath) bool {
	if riskTierRank(left.RiskTier) != riskTierRank(right.RiskTier) {
		return riskTierRank(left.RiskTier) < riskTierRank(right.RiskTier)
	}
	if recommendedControlRank(left.RecommendedControl) != recommendedControlRank(right.RecommendedControl) {
		return recommendedControlRank(left.RecommendedControl) < recommendedControlRank(right.RecommendedControl)
	}
	if left.PatternID != right.PatternID {
		return left.PatternID < right.PatternID
	}
	if left.TargetIdentity != right.TargetIdentity {
		return left.TargetIdentity < right.TargetIdentity
	}
	return left.CompositionID < right.CompositionID
}

func compositionID(patternID string, stages []CompositionStage, targetIdentity, outcomeKey string) string {
	parts := []string{"pattern=" + strings.TrimSpace(patternID)}
	for _, stage := range stages {
		parts = append(parts, strings.Join([]string{
			"role=" + strings.TrimSpace(stage.Role),
			"member=" + strings.TrimSpace(stage.ResolutionKey),
		}, ";"))
	}
	parts = append(parts, "target="+strings.TrimSpace(targetIdentity), "outcome="+strings.TrimSpace(outcomeKey))
	return "cap-" + stableCompositionHash(strings.Join(parts, "\x1f"))
}

func compositionStageID(role, memberKey, targetClass, evidenceState string) string {
	return "cas-" + stableCompositionHash(strings.Join([]string{role, memberKey, targetClass, evidenceState}, "|"))
}

func stableCompositionHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:8])
}

func compositionStageRoles(stages []CompositionStage) []string {
	out := make([]string, 0, len(stages))
	for _, stage := range stages {
		out = append(out, strings.TrimSpace(stage.Role))
	}
	return dedupeSortedStrings(out)
}

func compositionMemberKey(path ActionPath) string {
	if key := strings.TrimSpace(path.ResolutionKey); key != "" {
		return key
	}
	return strings.Join([]string{
		strings.TrimSpace(path.Org),
		strings.TrimSpace(path.Repo),
		strings.TrimSpace(path.ToolType),
		strings.TrimSpace(path.Location),
		strings.Join(dedupeSortedStrings(path.ActionClasses), ","),
		strings.TrimSpace(path.TargetClass),
		compositionTargetIdentity(compositionPatternSpec{}, []ActionPath{path}),
	}, "|")
}

func compositionCandidateKey(path ActionPath) string {
	return compositionMemberKey(path)
}

func compositionPathIDs(paths []ActionPath) []string {
	out := []string{}
	for _, path := range paths {
		out = append(out, strings.TrimSpace(path.PathID))
	}
	return dedupeSortedStrings(out)
}

func compositionWorkflowRefs(paths []ActionPath, refsByPath map[string][]string) []string {
	out := []string{}
	for _, path := range paths {
		out = append(out, path.WorkflowChainRefs...)
		out = append(out, refsByPath[strings.TrimSpace(path.PathID)]...)
	}
	return dedupeSortedStrings(out)
}

func compositionResolutionKey(paths []ActionPath) string {
	keys := []string{}
	for _, path := range paths {
		keys = append(keys, compositionMemberKey(path))
	}
	return strings.Join(dedupeSortedStrings(keys), "+")
}

func compositionTargetIdentity(_ compositionPatternSpec, paths []ActionPath) string {
	values := []string{}
	for _, path := range paths {
		values = append(values, path.MatchedProductionTargets...)
		if strings.TrimSpace(path.EndpointRefGroupID) != "" {
			values = append(values, "endpoint_group:"+strings.TrimSpace(path.EndpointRefGroupID))
		}
		for _, item := range path.MutableEndpointSemantics {
			values = append(values, strings.TrimSpace(item.Surface), strings.TrimSpace(item.Operation))
		}
		if path.CredentialAuthority != nil {
			values = append(values, strings.TrimSpace(path.CredentialAuthority.TargetSystem), strings.TrimSpace(path.CredentialAuthority.LikelyScope))
		}
		if path.CredentialProvenance != nil {
			values = append(values, strings.TrimSpace(path.CredentialProvenance.TargetSystem), strings.TrimSpace(path.CredentialProvenance.LikelyScope), strings.TrimSpace(path.CredentialProvenance.Scope))
		}
	}
	values = dedupeSortedStrings(values)
	if len(values) > 0 {
		return strings.Join(values, "+")
	}
	for _, path := range paths {
		if strings.TrimSpace(path.TargetClass) != "" {
			values = append(values, strings.TrimSpace(path.TargetClass))
		}
		values = append(values, strings.TrimSpace(path.Org)+"/"+strings.TrimSpace(path.Repo))
	}
	return strings.Join(dedupeSortedStrings(values), "+")
}

func compositionEnvironment(spec compositionPatternSpec, paths []ActionPath) string {
	for _, path := range paths {
		if path.ProductionWrite || normalizeTargetClass(path.TargetClass) == TargetClassProductionImpacting || len(path.MatchedProductionTargets) > 0 {
			return "production"
		}
		if strings.TrimSpace(path.RiskZone) == RiskZoneRelease || strings.Contains(strings.ToLower(path.Location), "release") {
			return "release"
		}
	}
	switch spec.outcome {
	case "data_egress", "network_egress":
		return "external"
	default:
		return "unknown"
	}
}

func compositionTargetClass(paths []ActionPath) string {
	best := ""
	for _, path := range paths {
		best = chooseTargetClass(best, path.TargetClass)
	}
	if strings.TrimSpace(best) == "" {
		return TargetClassUnknown
	}
	return best
}

func compositionEvidenceRefs(paths []ActionPath) []string {
	out := []string{}
	for _, path := range paths {
		out = append(out, path.ControlEvidenceRefs...)
		out = append(out, path.ConstraintEvidenceRefs...)
		out = append(out, path.TargetClassEvidenceRefs...)
		out = append(out, path.PolicyEvidenceRefs...)
		out = append(out, path.AutonomyTierEvidenceRefs...)
		out = append(out, path.RiskClassificationValidationRefs...)
		out = append(out, path.EvidencePacketRefs...)
		out = append(out, path.SourceFindingKeys...)
	}
	return dedupeSortedStrings(out)
}

func compositionProofRefs(paths []ActionPath) []string {
	out := []string{}
	for _, path := range paths {
		out = append(out, path.DecisionTraceRefs...)
		out = append(out, path.WorkflowChainRefs...)
	}
	return dedupeSortedStrings(out)
}

func compositionSourceDecisionRefs(paths []ActionPath) []string {
	out := []string{}
	for _, path := range paths {
		for _, decision := range path.EvidenceDecisions {
			out = append(out, decisionEvidenceRefs(decision)...)
		}
	}
	return dedupeSortedStrings(out)
}

func compositionContradictions(paths []ActionPath) []evidencepolicy.Contradiction {
	out := []evidencepolicy.Contradiction{}
	for _, path := range paths {
		out = append(out, path.Contradictions...)
	}
	return out
}

func compositionClosureRequirements(paths []ActionPath) []ClosureRequirement {
	out := []ClosureRequirement{}
	for _, path := range paths {
		out = append(out, CloneClosureRequirements(path.ClosureRequirements)...)
	}
	return out
}

func compositionEvidenceCompleteness(paths []ActionPath) *EvidenceCompleteness {
	for _, path := range paths {
		if path.EvidenceCompleteness != nil {
			return CloneEvidenceCompleteness(path.EvidenceCompleteness)
		}
	}
	return nil
}

func compositionEvidenceStateFromStages(stages []CompositionStage) string {
	state := ""
	for _, stage := range stages {
		state = compositionEvidenceState(state, stage.EvidenceState)
	}
	if strings.TrimSpace(state) == "" {
		return EvidenceStateUnknown
	}
	return state
}

func compositionFreshnessStateFromStages(stages []CompositionStage) string {
	state := ""
	for _, stage := range stages {
		state = compositionFreshnessState(state, stage.FreshnessState)
	}
	if strings.TrimSpace(state) == "" {
		return evidencepolicy.FreshnessStateUnknown
	}
	return state
}

func compositionPolicyCoverageStatusFromStages(stages []CompositionStage) string {
	status := ""
	for _, stage := range stages {
		status = choosePolicyCoverageStatus(status, stage.PolicyCoverageStatus)
	}
	if strings.TrimSpace(status) == "" {
		return PolicyCoverageStatusNone
	}
	return status
}

func compositionGaitCoverageFromStages(stages []CompositionStage) *GaitCoverage {
	var coverage *GaitCoverage
	for _, stage := range stages {
		coverage = MergeGaitCoverage(coverage, stage.GaitCoverage)
	}
	return coverage
}

func compositionRuntimeAbsenceFromStages(stages []CompositionStage) string {
	status := ""
	for _, stage := range stages {
		status = compositionRuntimeAbsence(status, stage.RuntimeEvidenceAbsenceStatus)
	}
	return status
}

func compositionEvidenceState(current, incoming string) string {
	current = normalizeEvidenceState(current)
	incoming = normalizeEvidenceState(incoming)
	if strings.TrimSpace(current) == "" {
		return firstNonEmptyString(incoming, EvidenceStateUnknown)
	}
	if strings.TrimSpace(incoming) == "" {
		return firstNonEmptyString(current, EvidenceStateUnknown)
	}
	current = firstNonEmptyString(current, EvidenceStateUnknown)
	incoming = firstNonEmptyString(incoming, EvidenceStateUnknown)
	if evidenceStatePriority(incoming) > evidenceStatePriority(current) {
		return incoming
	}
	return current
}

func compositionFreshnessState(current, incoming string) string {
	if strings.TrimSpace(current) == "" {
		return normalizeCompositionFreshness(incoming)
	}
	current = normalizeCompositionFreshness(current)
	incoming = normalizeCompositionFreshness(incoming)
	if compositionFreshnessRank(incoming) > compositionFreshnessRank(current) {
		return incoming
	}
	return current
}

func normalizeCompositionFreshness(value string) string {
	switch strings.TrimSpace(value) {
	case evidencepolicy.FreshnessStateFresh, evidencepolicy.FreshnessStateStale, evidencepolicy.FreshnessStateExpired:
		return strings.TrimSpace(value)
	default:
		return evidencepolicy.FreshnessStateUnknown
	}
}

func compositionFreshnessRank(value string) int {
	switch strings.TrimSpace(value) {
	case evidencepolicy.FreshnessStateExpired:
		return 3
	case evidencepolicy.FreshnessStateStale:
		return 2
	case evidencepolicy.FreshnessStateUnknown:
		return 1
	case evidencepolicy.FreshnessStateFresh:
		return 0
	default:
		return 1
	}
}

func compositionRuntimeAbsence(current, incoming string) string {
	if runtimeEvidenceAbsenceRank(incoming) < runtimeEvidenceAbsenceRank(current) {
		return incoming
	}
	if strings.TrimSpace(current) != "" {
		return current
	}
	return incoming
}

func pathConservativeEvidenceState(path ActionPath) string {
	state := EvidenceStateVerified
	for _, candidate := range []string{
		path.ControlResolutionStateEvidence(),
		path.OwnerEvidenceState,
		path.ApprovalEvidenceState,
		path.ProofEvidenceState,
		path.RuntimeEvidenceState,
		path.TargetEvidenceState,
		path.CredentialEvidenceState,
	} {
		state = compositionEvidenceState(state, candidate)
	}
	return state
}

func (path ActionPath) ControlResolutionStateEvidence() string {
	switch strings.TrimSpace(path.ControlResolutionState) {
	case ControlResolutionStateDetectedControl, ControlResolutionStateExternalControlReference:
		return EvidenceStateVerified
	case ControlResolutionStateDeclaredControl:
		return EvidenceStateDeclared
	case ControlResolutionStateContradictoryControl:
		return EvidenceStateContradictory
	case ControlResolutionStateNoVisibleControl:
		return EvidenceStateUnknown
	default:
		return ""
	}
}

func pathFreshnessState(path ActionPath) string {
	state := evidencepolicy.FreshnessStateFresh
	for _, decision := range path.EvidenceDecisions {
		state = compositionFreshnessState(state, decision.SelectedFreshnessState)
	}
	if len(path.EvidenceDecisions) == 0 {
		return evidencepolicy.FreshnessStateUnknown
	}
	return state
}

func compositionClaimState(evidenceState, policyCoverage string, gaitCoverage *GaitCoverage, paths []ActionPath) string {
	if strings.TrimSpace(evidenceState) == EvidenceStateContradictory || strings.TrimSpace(policyCoverage) == PolicyCoverageStatusConflict || GaitCoverageHasStatus(gaitCoverage, GaitStatusConflict) {
		return CompositionClaimContradictory
	}
	if compositionObservedExecution(paths, gaitCoverage) {
		return CompositionClaimObservedExecution
	}
	if compositionRuntimeControlled(policyCoverage, gaitCoverage) {
		return CompositionClaimRuntimeControlled
	}
	switch strings.TrimSpace(policyCoverage) {
	case PolicyCoverageStatusDeclared, PolicyCoverageStatusMatched:
		return CompositionClaimDeclaredPolicyOnly
	}
	switch strings.TrimSpace(evidenceState) {
	case EvidenceStateVerified, EvidenceStateDeclared:
		return CompositionClaimPartiallyEvidenced
	case EvidenceStateUnknown, EvidenceStateInferred:
		return CompositionClaimStaticOnly
	default:
		return CompositionClaimUnknown
	}
}

func compositionObservedExecution(paths []ActionPath, coverage *GaitCoverage) bool {
	if coverage == nil || strings.TrimSpace(coverage.ActionOutcome.Status) != GaitStatusPresent {
		return false
	}
	for _, path := range paths {
		if strings.TrimSpace(path.RuntimeEvidenceState) == EvidenceStateVerified {
			return true
		}
	}
	return false
}

func compositionRuntimeControlled(policyCoverage string, coverage *GaitCoverage) bool {
	if strings.TrimSpace(policyCoverage) != PolicyCoverageStatusRuntimeProven || coverage == nil {
		return false
	}
	required := []GaitCoverageDetail{coverage.PolicyDecision, coverage.ActionOutcome, coverage.ProofVerification}
	for _, detail := range required {
		if strings.TrimSpace(detail.Status) != GaitStatusPresent {
			return false
		}
	}
	for _, detail := range []GaitCoverageDetail{coverage.Approval, coverage.JITCredential, coverage.FreezeWindow, coverage.KillSwitch} {
		switch strings.TrimSpace(detail.Status) {
		case GaitStatusPresent, GaitStatusNotApplicable:
		default:
			return false
		}
	}
	return true
}

func compositionRiskTier(paths []ActionPath) string {
	tier := RiskTierLow
	for _, path := range paths {
		tier = compositionRiskTierFromValues(tier, path.RiskTier)
	}
	return tier
}

func compositionRiskTierFromValues(current, incoming string) string {
	if riskTierRank(incoming) < riskTierRank(current) {
		return strings.TrimSpace(incoming)
	}
	if strings.TrimSpace(current) != "" {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(incoming)
}

func compositionRecommendedControl(paths []ActionPath, claimState string) string {
	control := RecommendedControlAllow
	for _, path := range paths {
		control = compositionRecommendedControlFromValues(control, path.RecommendedControl)
	}
	if strings.TrimSpace(claimState) == CompositionClaimContradictory {
		return RecommendedControlBlock
	}
	if strings.TrimSpace(control) == "" {
		return RecommendedControlOwnerReview
	}
	return control
}

func compositionRecommendedControlFromValues(current, incoming string) string {
	if recommendedControlRank(incoming) < recommendedControlRank(current) {
		return strings.TrimSpace(incoming)
	}
	if strings.TrimSpace(current) != "" {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(incoming)
}

func recommendedControlRank(value string) int {
	switch strings.TrimSpace(value) {
	case RecommendedControlBlock:
		return 0
	case RecommendedControlBlockStandingCredential:
		return 1
	case RecommendedControlJITCredentialRequired:
		return 2
	case RecommendedControlProofRequired:
		return 3
	case RecommendedControlApprovalRequired:
		return 4
	case RecommendedControlSecurityReview:
		return 5
	case RecommendedControlOwnerReview:
		return 6
	case RecommendedControlAllow:
		return 7
	default:
		return 8
	}
}

func compositionStageRoleRank(role string) int {
	switch strings.TrimSpace(role) {
	case CompositionStageRoleSource:
		return 0
	case CompositionStageRoleTransform:
		return 1
	case CompositionStageRoleSink:
		return 2
	case CompositionStageRoleInternalSink:
		return 3
	case CompositionStageRoleExternalSink:
		return 4
	case CompositionStageRolePrivilegedSink:
		return 5
	case CompositionStageRoleDestructiveSink:
		return 6
	default:
		return 99
	}
}

func pathHasSensitiveRead(path ActionPath) bool {
	return containsAnyPathClass(path.ActionClasses, "read", "data.read", "sensitive_read", "data_export") ||
		agginventory.HasMutableEndpointSemantic(path.MutableEndpointSemantics, agginventory.EndpointSemanticRead) ||
		agginventory.HasMutableEndpointSemantic(path.MutableEndpointSemantics, agginventory.EndpointSemanticDataExport) ||
		normalizeTargetClass(path.TargetClass) == TargetClassCustomerDataAdjacent
}

func pathHasSecretAuthority(path ActionPath) bool {
	return path.CredentialAccess ||
		path.CredentialProvenance != nil ||
		path.CredentialAuthority != nil ||
		containsAnyPathClass(path.ActionClasses, "secret", "secret_read", "credential", "credential_read")
}

func pathHasExternalEgress(path ActionPath) bool {
	return containsAnyPathClass(path.ActionClasses, "egress", "network", "network_egress", "external_write", "data_export") ||
		strings.TrimSpace(path.RiskZone) == RiskZoneExternalEgress ||
		agginventory.HasMutableEndpointSemantic(path.MutableEndpointSemantics, agginventory.EndpointSemanticDataExport)
}

func pathHasNetworkEgress(path ActionPath) bool {
	return pathHasExternalEgress(path) || strings.Contains(strings.ToLower(path.ToolType), "mcp")
}

func pathMutatesCode(path ActionPath) bool {
	return path.WriteCapable ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		containsAnyPathClass(path.ActionClasses, "write", "code_write", "repo_write", "pull_request_write", "merge")
}

func pathDeploysProduction(path ActionPath) bool {
	return path.DeployWrite ||
		path.ProductionWrite ||
		containsAnyPathClass(path.ActionClasses, "deploy", "deploy_write", "production_deploy", "release") ||
		normalizeTargetClass(path.TargetClass) == TargetClassProductionImpacting ||
		len(path.MatchedProductionTargets) > 0
}

func pathMutatesWorkflow(path ActionPath) bool {
	location := strings.ToLower(strings.ReplaceAll(path.Location, "\\", "/"))
	return strings.Contains(location, ".github/workflows") && (path.WriteCapable || path.PullRequestWrite || containsAnyPathClass(path.ActionClasses, "write", "workflow_mutation", "workflow_write")) ||
		containsAnyPathClass(path.ActionClasses, "workflow_mutation", "workflow_write", "ci_write")
}

func pathProductionImpact(path ActionPath) bool {
	return path.ProductionWrite || path.DeployWrite || normalizeTargetClass(path.TargetClass) == TargetClassProductionImpacting || len(path.MatchedProductionTargets) > 0
}

func pathMutatesPackage(path ActionPath) bool {
	return containsAnyPathClass(path.ActionClasses, "package", "package_write", "dependency_change", "dependency_write", "release_write") ||
		containsAnyPathClass(path.WritePathClasses, "package_publish", "release_write")
}

func pathReleasesPackage(path ActionPath) bool {
	return containsAnyPathClass(path.ActionClasses, "release", "package_publish", "publish", "release_write") ||
		containsAnyPathClass(path.WritePathClasses, "package_publish", "release_write") ||
		strings.TrimSpace(path.RiskZone) == RiskZoneRelease
}
