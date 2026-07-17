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

	CompositionDelegationNarrowed      = "narrowed"
	CompositionDelegationEqual         = "equal"
	CompositionDelegationBroadened     = "broadened"
	CompositionDelegationUnknown       = "unknown"
	CompositionDelegationContradictory = "contradictory"

	CompositionApprovalEvasionNone     = "none"
	CompositionApprovalEvasionPossible = "possible"
	CompositionApprovalEvasionUnknown  = "unknown"

	CompositionMaterialityNone     = "none"
	CompositionMaterialityLow      = "low"
	CompositionMaterialityMaterial = "material"

	maxComposedActionPathCandidates = 128
	maxEquivalentOutcomeRefs        = 8
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
	Relationship                 string                         `json:"relationship,omitempty"`
	ParentAuthorityRef           string                         `json:"parent_authority_ref,omitempty"`
	ChildAuthorityRef            string                         `json:"child_authority_ref,omitempty"`
	ScopeDelta                   []string                       `json:"scope_delta,omitempty"`
	TargetDelta                  []string                       `json:"target_delta,omitempty"`
	CredentialDelta              []string                       `json:"credential_delta,omitempty"`
	ExpiryDelta                  []string                       `json:"expiry_delta,omitempty"`
	ReasonCodes                  []string                       `json:"reason_codes,omitempty"`
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
	Relationship                 string        `json:"relationship,omitempty"`
	ParentAuthorityRef           string        `json:"parent_authority_ref,omitempty"`
	ChildAuthorityRef            string        `json:"child_authority_ref,omitempty"`
	ScopeDelta                   []string      `json:"scope_delta,omitempty"`
	TargetDelta                  []string      `json:"target_delta,omitempty"`
	CredentialDelta              []string      `json:"credential_delta,omitempty"`
	ExpiryDelta                  []string      `json:"expiry_delta,omitempty"`
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
	OutcomeKey                   string                         `json:"outcome_key,omitempty"`
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
	RecommendedControlReasons    []string                       `json:"recommended_control_reasons,omitempty"`
	EscalatingTransitionRefs     []string                       `json:"escalating_transition_refs,omitempty"`
	MostRestrictiveSource        string                         `json:"most_restrictive_source,omitempty"`
	ClosureRequirements          []ClosureRequirement           `json:"closure_requirements,omitempty"`
	EvidenceCompleteness         *EvidenceCompleteness          `json:"evidence_completeness,omitempty"`
	UnsupportedSurfaces          []string                       `json:"unsupported_surfaces,omitempty"`
	TruncatedCandidates          []string                       `json:"truncated_candidates,omitempty"`
	ProposedActionContract       *ProposedActionContract        `json:"proposed_action_contract,omitempty"`
	ProposedActionContractRefs   []string                       `json:"proposed_action_contract_refs,omitempty"`
	EquivalentOutcomeRefs        []string                       `json:"equivalent_outcome_refs,omitempty"`
	ApprovalEvasionSignal        string                         `json:"approval_evasion_signal,omitempty"`
	CoverageDeltaReasons         []string                       `json:"coverage_delta_reasons,omitempty"`
	Materiality                  string                         `json:"materiality,omitempty"`
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
				composition := buildComposedActionPath(spec, source, sink, chainRefsByPath)
				if _, seen := compositionsByKey[composition.CompositionID]; !seen {
					count++
					if count > maxComposedActionPathCandidates {
						truncated[spec.id] = append(truncated[spec.id], compositionCandidateKey(source)+"->"+compositionCandidateKey(sink))
						continue
					}
				}
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
	annotateEquivalentOutcomeSignals(compositions)
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
		if !IsActionPathEligible(path) {
			continue
		}
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
	claimState := compositionClaimState(evidenceState, policyCoverage, freshnessState, gaitCoverage, stages, paths)
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
		RuntimeEvidenceAbsenceStatus: runtimeAbsence,
		Contradictions:               compositionContradictions(paths),
		EvidenceRefs:                 compositionEvidenceRefs(paths),
		ProofRefs:                    compositionProofRefs(paths),
		SourceDecisionRefs:           compositionSourceDecisionRefs(paths),
		RiskTier:                     compositionRiskTier(paths),
		ClosureRequirements:          compositionClosureRequirements(paths),
		EvidenceCompleteness:         compositionEvidenceCompleteness(paths),
	}
	applyCompositionDelegationRelationships(&composition, paths)
	applyCompositionRecommendedControl(&composition, paths)
	hydrateCompositionTransitions(&composition)
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
		current.PolicyCoverageStatus = compositionPolicyCoverageStatus(current.PolicyCoverageStatus, stage.PolicyCoverageStatus)
		current.RuntimeEvidenceAbsenceStatus = compositionRuntimeAbsence(current.RuntimeEvidenceAbsenceStatus, stage.RuntimeEvidenceAbsenceStatus)
		current.StageID = compositionStageID(current.Role, current.ResolutionKey, current.TargetClass, current.EvidenceState)
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

type compositionAuthorityProfile struct {
	Ref             string
	Scopes          []string
	Targets         []string
	Credentials     []string
	Expiry          string
	AccessRank      int
	DelegationDepth int
	EvidenceRefs    []string
	ReasonCodes     []string
	Unknown         bool
	Contradictory   bool
}

type compositionRecommendationCandidate struct {
	Control        string
	Source         string
	TransitionRefs []string
	Reasons        []string
}

func applyCompositionDelegationRelationships(composition *ComposedActionPath, paths []ActionPath) {
	if composition == nil || len(composition.Stages) == 0 {
		return
	}
	profiles := compositionAuthorityProfiles(paths)
	for idx := range composition.Stages {
		stage := &composition.Stages[idx]
		if profile, ok := profiles[strings.TrimSpace(stage.ResolutionKey)]; ok {
			stage.ChildAuthorityRef = strings.TrimSpace(profile.Ref)
			stage.ReasonCodes = dedupeSortedStrings(append(stage.ReasonCodes, profile.ReasonCodes...))
			stage.EvidenceRefs = dedupeSortedStrings(append(stage.EvidenceRefs, profile.EvidenceRefs...))
		}
	}
	stageByID := map[string]int{}
	for idx, stage := range composition.Stages {
		stageByID[strings.TrimSpace(stage.StageID)] = idx
	}
	for idx := range composition.Transitions {
		fromIdx, fromOK := stageByID[strings.TrimSpace(composition.Transitions[idx].FromStageID)]
		toIdx, toOK := stageByID[strings.TrimSpace(composition.Transitions[idx].ToStageID)]
		if !fromOK || !toOK {
			continue
		}
		parent := profiles[strings.TrimSpace(composition.Stages[fromIdx].ResolutionKey)]
		child := profiles[strings.TrimSpace(composition.Stages[toIdx].ResolutionKey)]
		relationship, scopeDelta, targetDelta, credentialDelta, expiryDelta, reasons := compareCompositionAuthority(parent, child)
		composition.Transitions[idx].Relationship = relationship
		composition.Transitions[idx].ParentAuthorityRef = strings.TrimSpace(parent.Ref)
		composition.Transitions[idx].ChildAuthorityRef = strings.TrimSpace(child.Ref)
		composition.Transitions[idx].ScopeDelta = scopeDelta
		composition.Transitions[idx].TargetDelta = targetDelta
		composition.Transitions[idx].CredentialDelta = credentialDelta
		composition.Transitions[idx].ExpiryDelta = expiryDelta
		composition.Transitions[idx].EvidenceRefs = dedupeSortedStrings(append(append(composition.Transitions[idx].EvidenceRefs, parent.EvidenceRefs...), child.EvidenceRefs...))
		composition.Transitions[idx].ReasonCodes = dedupeSortedStrings(append(composition.Transitions[idx].ReasonCodes, reasons...))

		for _, stageIdx := range []int{fromIdx, toIdx} {
			stage := &composition.Stages[stageIdx]
			stage.Relationship = relationship
			stage.ParentAuthorityRef = strings.TrimSpace(parent.Ref)
			stage.ChildAuthorityRef = strings.TrimSpace(child.Ref)
			stage.ScopeDelta = dedupeSortedStrings(append(stage.ScopeDelta, scopeDelta...))
			stage.TargetDelta = dedupeSortedStrings(append(stage.TargetDelta, targetDelta...))
			stage.CredentialDelta = dedupeSortedStrings(append(stage.CredentialDelta, credentialDelta...))
			stage.ExpiryDelta = dedupeSortedStrings(append(stage.ExpiryDelta, expiryDelta...))
			stage.ReasonCodes = dedupeSortedStrings(append(stage.ReasonCodes, reasons...))
			stage.EvidenceRefs = dedupeSortedStrings(append(append(stage.EvidenceRefs, parent.EvidenceRefs...), child.EvidenceRefs...))
		}
	}
}

func compositionAuthorityProfiles(paths []ActionPath) map[string]compositionAuthorityProfile {
	out := map[string]compositionAuthorityProfile{}
	for _, path := range paths {
		key := compositionMemberKey(path)
		if strings.TrimSpace(key) == "" {
			continue
		}
		out[key] = compositionAuthorityProfileForPath(path)
	}
	return out
}

func compositionAuthorityProfileForPath(path ActionPath) compositionAuthorityProfile {
	profile := compositionAuthorityProfile{
		Ref:             compositionAuthorityRef(path),
		Scopes:          compositionAuthorityScopes(path),
		Targets:         compositionAuthorityTargets(path),
		Credentials:     compositionAuthorityCredentials(path),
		Expiry:          strings.TrimSpace(path.ReviewValidUntil),
		AccessRank:      compositionAuthorityAccessRank(path),
		DelegationDepth: compositionDelegationDepth(path),
		EvidenceRefs:    compositionAuthorityEvidenceRefs(path),
		ReasonCodes:     []string{"authority_profile:static_projection"},
		Contradictory:   path.EvidenceStateContradictory(),
	}
	if strings.TrimSpace(profile.Ref) == "" {
		profile.Unknown = true
		profile.Ref = "authority-unknown:" + stableCompositionHash(compositionMemberKey(path))
		profile.ReasonCodes = append(profile.ReasonCodes, "authority_profile:missing_identity")
	}
	if len(profile.Scopes) == 0 {
		profile.ReasonCodes = append(profile.ReasonCodes, "scope:unknown")
	}
	if len(profile.Targets) == 0 {
		profile.ReasonCodes = append(profile.ReasonCodes, "target:unknown")
	}
	if strings.TrimSpace(profile.Expiry) == "" {
		profile.ReasonCodes = append(profile.ReasonCodes, "expiry:unknown")
	}
	profile.Scopes = dedupeSortedStrings(profile.Scopes)
	profile.Targets = dedupeSortedStrings(profile.Targets)
	profile.Credentials = dedupeSortedStrings(profile.Credentials)
	profile.EvidenceRefs = dedupeSortedStrings(profile.EvidenceRefs)
	profile.ReasonCodes = dedupeSortedStrings(profile.ReasonCodes)
	return profile
}

func (path ActionPath) EvidenceStateContradictory() bool {
	for _, value := range []string{
		path.ControlResolutionStateEvidence(),
		path.OwnerEvidenceState,
		path.ApprovalEvidenceState,
		path.ProofEvidenceState,
		path.RuntimeEvidenceState,
		path.TargetEvidenceState,
		path.CredentialEvidenceState,
	} {
		if strings.TrimSpace(value) == EvidenceStateContradictory {
			return true
		}
	}
	return len(path.Contradictions) > 0
}

func compositionAuthorityRef(path ActionPath) string {
	values := []string{strings.TrimSpace(path.CredentialAuthorityRef)}
	if path.CredentialAuthority != nil {
		values = append(values, compositionCredentialAuthorityIdentity(path.CredentialAuthority))
	}
	if path.CredentialProvenance != nil {
		values = append(values, compositionCredentialProvenanceIdentity(path.CredentialProvenance))
	}
	for _, credential := range path.Credentials {
		if credential == nil {
			continue
		}
		values = append(values, compositionCredentialProvenanceIdentity(credential))
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		values = append(values, strings.Join([]string{
			"binding",
			strings.TrimSpace(binding.Kind),
			strings.TrimSpace(binding.Provider),
			strings.TrimSpace(binding.TargetSystem),
			strings.TrimSpace(binding.Subject),
			strings.TrimSpace(binding.Resource),
			strings.TrimSpace(binding.AccessLevel),
		}, ":"))
	}
	values = dedupeSortedStrings(values)
	if len(values) == 0 {
		return ""
	}
	return "authority-" + stableCompositionHash(strings.Join(values, "\x1f"))
}

func compositionAuthorityScopes(path ActionPath) []string {
	values := []string{}
	if path.CredentialAuthority != nil {
		values = append(values, path.CredentialAuthority.LikelyScope)
		values = append(values, path.CredentialAuthority.TargetSystem)
	}
	if path.CredentialProvenance != nil {
		values = append(values, path.CredentialProvenance.Scope, path.CredentialProvenance.LikelyScope, path.CredentialProvenance.TargetSystem)
	}
	for _, credential := range path.Credentials {
		if credential == nil {
			continue
		}
		values = append(values, credential.Scope, credential.LikelyScope, credential.TargetSystem)
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		values = append(values, binding.LikelyScope, binding.Resource, binding.TargetSystem)
	}
	return dedupeSortedStrings(values)
}

func compositionAuthorityTargets(path ActionPath) []string {
	values := []string{normalizeTargetClass(path.TargetClass)}
	values = append(values, path.MatchedProductionTargets...)
	if strings.TrimSpace(path.EndpointRefGroupID) != "" {
		values = append(values, "endpoint_group:"+strings.TrimSpace(path.EndpointRefGroupID))
	}
	for _, item := range path.MutableEndpointSemantics {
		values = append(values, compositionMutableEndpointIdentity(item))
	}
	if path.CredentialAuthority != nil {
		values = append(values, path.CredentialAuthority.TargetSystem, path.CredentialAuthority.LikelyScope)
	}
	if path.CredentialProvenance != nil {
		values = append(values, path.CredentialProvenance.TargetSystem, path.CredentialProvenance.LikelyScope)
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		values = append(values, binding.TargetSystem, binding.Resource, binding.Environment)
	}
	return dedupeSortedStrings(values)
}

func compositionAuthorityCredentials(path ActionPath) []string {
	values := []string{}
	if path.CredentialAuthority != nil {
		values = append(values,
			"authority_kind:"+strings.TrimSpace(path.CredentialAuthority.CredentialKind),
			"authority_access:"+strings.TrimSpace(path.CredentialAuthority.AccessType),
			"authority_source:"+strings.TrimSpace(path.CredentialAuthority.CredentialSource),
		)
		if path.CredentialAuthority.StandingAccess {
			values = append(values, "authority_standing:true")
		}
		if path.CredentialAuthority.LikelyJIT {
			values = append(values, "authority_jit:true")
		}
	}
	if path.CredentialProvenance != nil {
		values = append(values,
			"provenance_type:"+strings.TrimSpace(path.CredentialProvenance.Type),
			"provenance_subject:"+strings.TrimSpace(path.CredentialProvenance.Subject),
			"provenance_access:"+strings.TrimSpace(path.CredentialProvenance.AccessType),
			"provenance_kind:"+strings.TrimSpace(path.CredentialProvenance.CredentialKind),
		)
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		values = append(values,
			"binding_subject:"+strings.TrimSpace(binding.Subject),
			"binding_access:"+strings.TrimSpace(binding.AccessLevel),
		)
	}
	return dedupeSortedStrings(values)
}

func compositionAuthorityEvidenceRefs(path ActionPath) []string {
	refs := append([]string(nil), path.ControlEvidenceRefs...)
	refs = append(refs, path.ConstraintEvidenceRefs...)
	refs = append(refs, path.TargetClassEvidenceRefs...)
	refs = append(refs, path.PolicyEvidenceRefs...)
	if path.CredentialAuthority != nil {
		refs = append(refs, path.CredentialAuthority.ReasonCodes...)
	}
	if path.CredentialProvenance != nil {
		refs = append(refs, path.CredentialProvenance.EvidenceBasis...)
		refs = append(refs, path.CredentialProvenance.ClassificationReasons...)
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		refs = append(refs, binding.EvidenceRefs...)
		refs = append(refs, binding.ReasonCodes...)
	}
	return dedupeSortedStrings(refs)
}

func compositionAuthorityAccessRank(path ActionPath) int {
	rank := 0
	for _, class := range append(append([]string(nil), path.ActionClasses...), path.WritePathClasses...) {
		rank = maxInt(rank, compositionActionClassAccessRank(class))
	}
	if path.CredentialAccess {
		rank = maxInt(rank, 3)
	}
	if path.WriteCapable || path.PullRequestWrite || path.MergeExecute {
		rank = maxInt(rank, 3)
	}
	if path.DeployWrite {
		rank = maxInt(rank, 4)
	}
	if path.ProductionWrite {
		rank = maxInt(rank, 5)
	}
	if path.CredentialAuthority != nil {
		rank = maxInt(rank, compositionAccessLevelRank(path.CredentialAuthority.AccessType))
		if path.CredentialAuthority.StandingAccess {
			rank = maxInt(rank, 4)
		}
	}
	if path.CredentialProvenance != nil {
		rank = maxInt(rank, compositionAccessLevelRank(path.CredentialProvenance.AccessType))
		if path.CredentialProvenance.StandingAccess {
			rank = maxInt(rank, 4)
		}
	}
	for _, binding := range path.AuthorityBindings {
		if binding == nil {
			continue
		}
		rank = maxInt(rank, compositionAccessLevelRank(binding.AccessLevel))
		if binding.Production {
			rank = maxInt(rank, 5)
		}
	}
	return rank
}

func compositionActionClassAccessRank(value string) int {
	switch strings.TrimSpace(value) {
	case "admin", "owner", "production_deploy":
		return 5
	case "deploy", "deploy_write", "release", "package_publish", "publish", "release_write":
		return 4
	case "write", "code_write", "repo_write", "pull_request_write", "merge", "workflow_mutation", "workflow_write", "ci_write", "external_write", "credential", "secret":
		return 3
	case "egress", "network", "network_egress", "data_export":
		return 2
	case "read", "data.read", "sensitive_read", "secret_read", "credential_read":
		return 1
	default:
		return 0
	}
}

func compositionAccessLevelRank(value string) int {
	switch strings.TrimSpace(value) {
	case agginventory.AuthorityAccessAdmin, "owner", "write-all", "full":
		return 5
	case agginventory.AuthorityAccessWrite, "deploy", "release":
		return 3
	case agginventory.AuthorityAccessRead:
		return 1
	case agginventory.AuthorityAccessUnknown, "":
		return 0
	default:
		if strings.Contains(strings.ToLower(value), "admin") {
			return 5
		}
		if strings.Contains(strings.ToLower(value), "write") {
			return 3
		}
		if strings.Contains(strings.ToLower(value), "read") {
			return 1
		}
		return 0
	}
}

func compositionDelegationDepth(path ActionPath) int {
	depth := 0
	if path.CredentialProvenance != nil && strings.TrimSpace(path.CredentialProvenance.Type) == agginventory.CredentialProvenanceOAuthDelegation {
		depth = maxInt(depth, 1)
	}
	if path.TrustDepth != nil {
		switch strings.TrimSpace(path.TrustDepth.DelegationModel) {
		case agginventory.TrustDelegationAgent:
			depth = maxInt(depth, 2)
		case agginventory.TrustDelegationToolProxy:
			depth = maxInt(depth, 1)
		case agginventory.TrustDelegationUnknown:
			depth = maxInt(depth, 1)
		}
	}
	return depth
}

func compareCompositionAuthority(parent, child compositionAuthorityProfile) (string, []string, []string, []string, []string, []string) {
	reasons := []string{"delegation_relationship:static_not_runtime_token_proof"}
	scopeDelta := stringSetDeltaLabels("scope", parent.Scopes, child.Scopes)
	targetDelta := stringSetDeltaLabels("target", parent.Targets, child.Targets)
	credentialDelta := stringSetDeltaLabels("credential", parent.Credentials, child.Credentials)
	expiryDelta := expiryDeltaLabels(parent.Expiry, child.Expiry)
	if parent.Contradictory || child.Contradictory {
		reasons = append(reasons, "delegation_relationship:contradictory_evidence")
		return CompositionDelegationContradictory, scopeDelta, targetDelta, credentialDelta, expiryDelta, dedupeSortedStrings(reasons)
	}
	if parent.Unknown || child.Unknown {
		reasons = append(reasons, "delegation_relationship:unknown_authority_identity")
		return CompositionDelegationUnknown, scopeDelta, targetDelta, credentialDelta, expiryDelta, dedupeSortedStrings(reasons)
	}

	broadened := false
	narrowed := false
	if child.AccessRank > parent.AccessRank {
		broadened = true
		reasons = append(reasons, "access:broadened")
	} else if child.AccessRank < parent.AccessRank {
		narrowed = true
		reasons = append(reasons, "access:narrowed")
	}
	if child.DelegationDepth > parent.DelegationDepth {
		broadened = true
		reasons = append(reasons, "delegation_depth:broadened")
	} else if child.DelegationDepth < parent.DelegationDepth {
		narrowed = true
		reasons = append(reasons, "delegation_depth:narrowed")
	}
	if targetRankBroadened(parent.Targets, child.Targets) {
		broadened = true
		reasons = append(reasons, "target:broadened")
	} else if len(targetDelta) > 0 {
		narrowed = true
	}
	if hasAddedDelta(scopeDelta) {
		broadened = true
		reasons = append(reasons, "scope:broadened")
	} else if len(scopeDelta) > 0 {
		narrowed = true
	}
	if hasAddedDelta(credentialDelta) && child.AccessRank >= parent.AccessRank {
		broadened = true
		reasons = append(reasons, "credential:changed_or_broadened")
	}
	if childExpiryLessRestrictive(parent.Expiry, child.Expiry) {
		broadened = true
		reasons = append(reasons, "expiry:broadened_or_missing")
	} else if len(expiryDelta) > 0 {
		narrowed = true
	}
	switch {
	case broadened:
		return CompositionDelegationBroadened, scopeDelta, targetDelta, credentialDelta, expiryDelta, dedupeSortedStrings(reasons)
	case narrowed:
		return CompositionDelegationNarrowed, scopeDelta, targetDelta, credentialDelta, expiryDelta, dedupeSortedStrings(reasons)
	default:
		reasons = append(reasons, "delegation_relationship:equal_authority")
		return CompositionDelegationEqual, nil, nil, nil, nil, dedupeSortedStrings(reasons)
	}
}

func stringSetDeltaLabels(prefix string, parent, child []string) []string {
	parentSet := stringSet(parent)
	childSet := stringSet(child)
	out := []string{}
	for _, value := range child {
		if _, ok := parentSet[value]; !ok {
			out = append(out, prefix+":added:"+value)
		}
	}
	for _, value := range parent {
		if _, ok := childSet[value]; !ok {
			out = append(out, prefix+":removed:"+value)
		}
	}
	return dedupeSortedStrings(out)
}

func stringSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	return out
}

func hasAddedDelta(values []string) bool {
	for _, value := range values {
		if strings.Contains(value, ":added:") {
			return true
		}
	}
	return false
}

func targetRankBroadened(parent, child []string) bool {
	parentRank := 99
	childRank := 99
	for _, value := range parent {
		parentRank = minInt(parentRank, targetClassRank(value))
	}
	for _, value := range child {
		childRank = minInt(childRank, targetClassRank(value))
	}
	return childRank < parentRank
}

func expiryDeltaLabels(parent, child string) []string {
	parent = strings.TrimSpace(parent)
	child = strings.TrimSpace(child)
	switch {
	case parent == "" && child == "":
		return nil
	case parent == child:
		return nil
	case parent == "":
		return []string{"expiry:added:" + child}
	case child == "":
		return []string{"expiry:removed:" + parent}
	default:
		return []string{"expiry:changed:" + parent + "->" + child}
	}
}

func childExpiryLessRestrictive(parent, child string) bool {
	parent = strings.TrimSpace(parent)
	child = strings.TrimSpace(child)
	if parent == "" {
		return false
	}
	if child == "" {
		return true
	}
	return child > parent
}

func mergeCompositionTransitionDelegation(composition *ComposedActionPath, sources ...[]CompositionTransition) {
	if composition == nil || len(composition.Transitions) == 0 {
		return
	}
	byTransition := map[string]CompositionTransition{}
	for _, source := range sources {
		for _, transition := range source {
			byTransition[strings.TrimSpace(transition.TransitionID)] = transition
		}
	}
	for idx := range composition.Transitions {
		current, ok := byTransition[strings.TrimSpace(composition.Transitions[idx].TransitionID)]
		if !ok {
			continue
		}
		composition.Transitions[idx].Relationship = strings.TrimSpace(current.Relationship)
		composition.Transitions[idx].ParentAuthorityRef = strings.TrimSpace(current.ParentAuthorityRef)
		composition.Transitions[idx].ChildAuthorityRef = strings.TrimSpace(current.ChildAuthorityRef)
		composition.Transitions[idx].ScopeDelta = dedupeSortedStrings(current.ScopeDelta)
		composition.Transitions[idx].TargetDelta = dedupeSortedStrings(current.TargetDelta)
		composition.Transitions[idx].CredentialDelta = dedupeSortedStrings(current.CredentialDelta)
		composition.Transitions[idx].ExpiryDelta = dedupeSortedStrings(current.ExpiryDelta)
		composition.Transitions[idx].ReasonCodes = dedupeSortedStrings(append(composition.Transitions[idx].ReasonCodes, current.ReasonCodes...))
	}
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
	merged.Stages = dedupeCompositionStages(append(append([]CompositionStage(nil), merged.Stages...), incoming.Stages...))
	merged.Transitions = buildCompositionTransitions(merged.CompositionID, merged.Stages)
	mergeCompositionTransitionDelegation(&merged, current.Transitions, incoming.Transitions)
	merged.Contradictions = mergeContradictions(merged.Contradictions, incoming.Contradictions)
	merged.ClosureRequirements = CloneClosureRequirements(firstNonEmptyClosureRequirements(merged.ClosureRequirements, incoming.ClosureRequirements))
	merged.EvidenceCompleteness = mergeEvidenceCompletenessValues(merged.EvidenceCompleteness, incoming.EvidenceCompleteness)
	merged.GaitCoverage = MergeGaitCoverage(merged.GaitCoverage, incoming.GaitCoverage)
	merged.EvidenceState = compositionEvidenceState(merged.EvidenceState, incoming.EvidenceState)
	merged.FreshnessState = compositionFreshnessState(merged.FreshnessState, incoming.FreshnessState)
	merged.PolicyCoverageStatus = compositionPolicyCoverageStatus(merged.PolicyCoverageStatus, incoming.PolicyCoverageStatus)
	merged.RuntimeEvidenceAbsenceStatus = compositionRuntimeAbsence(merged.RuntimeEvidenceAbsenceStatus, incoming.RuntimeEvidenceAbsenceStatus)
	merged.RiskTier = compositionRiskTierFromValues(merged.RiskTier, incoming.RiskTier)
	merged.RecommendedControl = compositionRecommendedControlFromValues(merged.RecommendedControl, incoming.RecommendedControl)
	merged.RecommendedControlReasons = dedupeSortedStrings(append(merged.RecommendedControlReasons, incoming.RecommendedControlReasons...))
	merged.EscalatingTransitionRefs = dedupeSortedStrings(append(merged.EscalatingTransitionRefs, incoming.EscalatingTransitionRefs...))
	if strings.TrimSpace(merged.MostRestrictiveSource) == "" {
		merged.MostRestrictiveSource = strings.TrimSpace(incoming.MostRestrictiveSource)
	}
	merged.ClaimState = compositionClaimState(merged.EvidenceState, merged.PolicyCoverageStatus, merged.FreshnessState, merged.GaitCoverage, merged.Stages, nil)
	hydrateCompositionTransitions(&merged)
	merged.ProposedActionContract = BuildProposedActionContract(merged)
	if merged.ProposedActionContract != nil {
		merged.ProposedActionContractRefs = []string{merged.ProposedActionContract.ContractID}
	} else {
		merged.ProposedActionContractRefs = nil
	}
	return merged
}

func hydrateCompositionTransitions(composition *ComposedActionPath) {
	if composition == nil {
		return
	}
	for idx := range composition.Transitions {
		composition.Transitions[idx].ClaimState = composition.ClaimState
		composition.Transitions[idx].EvidenceState = composition.EvidenceState
		composition.Transitions[idx].PolicyCoverageStatus = composition.PolicyCoverageStatus
		composition.Transitions[idx].GaitCoverage = CloneGaitCoverage(composition.GaitCoverage)
		composition.Transitions[idx].RuntimeEvidenceAbsenceStatus = composition.RuntimeEvidenceAbsenceStatus
		composition.Transitions[idx].EvidenceRefs = append([]string(nil), composition.EvidenceRefs...)
		composition.Transitions[idx].ProofRefs = append([]string(nil), composition.ProofRefs...)
		composition.Transitions[idx].SourceDecisionRefs = append([]string(nil), composition.SourceDecisionRefs...)
		composition.Transitions[idx].ReasonCodes = dedupeSortedStrings(append(composition.Transitions[idx].ReasonCodes, "pattern:"+composition.PatternID, "claim_state:"+composition.ClaimState))
	}
}

func applyCompositionRecommendedControl(composition *ComposedActionPath, paths []ActionPath) {
	if composition == nil {
		return
	}
	candidates := []compositionRecommendationCandidate{}
	for _, path := range paths {
		control := strings.TrimSpace(path.RecommendedControl)
		if control == "" {
			control = RecommendedControlOwnerReview
		}
		source := "path:" + firstNonEmptyString(strings.TrimSpace(path.PathID), compositionMemberKey(path))
		reasons := append([]string(nil), path.RecommendedControlReasons...)
		if len(reasons) == 0 {
			reasons = append(reasons, "path_recommendation:"+control)
		}
		candidates = append(candidates, compositionRecommendationCandidate{
			Control: control,
			Source:  source,
			Reasons: reasons,
		})
	}
	switch strings.TrimSpace(composition.ClaimState) {
	case CompositionClaimContradictory:
		candidates = append(candidates, compositionRecommendationCandidate{
			Control: RecommendedControlBlock,
			Source:  "composition_claim_state",
			Reasons: []string{"composition:contradictory_claim"},
		})
	case CompositionClaimStaticOnly, CompositionClaimUnknown:
		candidates = append(candidates, compositionRecommendationCandidate{
			Control: RecommendedControlSecurityReview,
			Source:  "composition_claim_state",
			Reasons: []string{"composition:static_or_unknown_claim"},
		})
	}
	switch strings.TrimSpace(composition.EvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		candidates = append(candidates, compositionRecommendationCandidate{
			Control: RecommendedControlProofRequired,
			Source:  "composition_evidence_state",
			Reasons: []string{"composition:evidence_incomplete"},
		})
	}
	switch strings.TrimSpace(composition.PolicyCoverageStatus) {
	case PolicyCoverageStatusNone, PolicyCoverageStatusStale:
		candidates = append(candidates, compositionRecommendationCandidate{
			Control: RecommendedControlApprovalRequired,
			Source:  "composition_policy_coverage",
			Reasons: []string{"composition:policy_coverage_gap"},
		})
	case PolicyCoverageStatusConflict:
		candidates = append(candidates, compositionRecommendationCandidate{
			Control: RecommendedControlBlock,
			Source:  "composition_policy_coverage",
			Reasons: []string{"composition:policy_coverage_conflict"},
		})
	}
	for _, transition := range composition.Transitions {
		ref := strings.TrimSpace(transition.TransitionID)
		switch strings.TrimSpace(transition.Relationship) {
		case CompositionDelegationContradictory:
			candidates = append(candidates, compositionRecommendationCandidate{
				Control:        RecommendedControlBlock,
				Source:         "transition:" + ref,
				TransitionRefs: []string{ref},
				Reasons:        []string{"composition:delegation_contradictory"},
			})
		case CompositionDelegationBroadened:
			candidates = append(candidates, compositionRecommendationCandidate{
				Control:        RecommendedControlJITCredentialRequired,
				Source:         "transition:" + ref,
				TransitionRefs: []string{ref},
				Reasons:        []string{"composition:delegation_broadened"},
			})
		case CompositionDelegationUnknown:
			candidates = append(candidates, compositionRecommendationCandidate{
				Control:        RecommendedControlSecurityReview,
				Source:         "transition:" + ref,
				TransitionRefs: []string{ref},
				Reasons:        []string{"composition:delegation_unknown"},
			})
		}
	}
	control := RecommendedControlAllow
	source := ""
	reasons := []string{}
	transitionRefs := []string{}
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.Control) == "" {
			continue
		}
		reasons = append(reasons, candidate.Reasons...)
		transitionRefs = append(transitionRefs, candidate.TransitionRefs...)
		if recommendedControlRank(candidate.Control) < recommendedControlRank(control) {
			control = strings.TrimSpace(candidate.Control)
			source = strings.TrimSpace(candidate.Source)
		}
	}
	if strings.TrimSpace(control) == "" {
		control = RecommendedControlOwnerReview
	}
	composition.RecommendedControl = control
	composition.RecommendedControlReasons = dedupeSortedStrings(reasons)
	composition.EscalatingTransitionRefs = dedupeSortedStrings(transitionRefs)
	composition.MostRestrictiveSource = strings.TrimSpace(source)
	if composition.MostRestrictiveSource == "" && control != RecommendedControlAllow {
		composition.MostRestrictiveSource = "composition"
	}
}

func annotateEquivalentOutcomeSignals(compositions []ComposedActionPath) {
	if len(compositions) < 2 {
		return
	}
	byOutcome := map[string][]int{}
	for idx := range compositions {
		compositions[idx].OutcomeKey = firstNonEmptyString(strings.TrimSpace(compositions[idx].OutcomeKey), strings.TrimSpace(compositions[idx].DurableOutcomeKey))
		if !compositionOutcomeEquivalenceEligible(compositions[idx]) {
			if strings.TrimSpace(compositions[idx].OutcomeKey) == "" || !compositionHasStableOutcomeTarget(compositions[idx]) {
				compositions[idx].CoverageDeltaReasons = dedupeSortedStrings(append(compositions[idx].CoverageDeltaReasons, "equivalence:stable_target_identity_absent"))
				compositions[idx].ApprovalEvasionSignal = CompositionApprovalEvasionUnknown
				compositions[idx].Materiality = CompositionMaterialityNone
			}
			continue
		}
		byOutcome[strings.TrimSpace(compositions[idx].OutcomeKey)] = append(byOutcome[strings.TrimSpace(compositions[idx].OutcomeKey)], idx)
	}
	for _, indexes := range byOutcome {
		if len(indexes) < 2 {
			continue
		}
		for _, idx := range indexes {
			refs := []string{}
			reasons := []string{}
			material := false
			possibleEvasion := false
			for _, peerIdx := range indexes {
				if peerIdx == idx {
					continue
				}
				peer := compositions[peerIdx]
				deltas := equivalentOutcomeDeltaReasons(compositions[idx], peer)
				if len(deltas) == 0 {
					continue
				}
				refs = append(refs, strings.TrimSpace(peer.CompositionID))
				reasons = append(reasons, deltas...)
				material = true
				if compositionWeakerThanPeer(compositions[idx], peer) {
					possibleEvasion = true
				}
			}
			refs = dedupeSortedStrings(refs)
			if len(refs) > maxEquivalentOutcomeRefs {
				refs = append(append([]string(nil), refs[:maxEquivalentOutcomeRefs]...), "truncated:"+stableCompositionHash(strings.Join(refs, "\x1f")))
			}
			compositions[idx].EquivalentOutcomeRefs = refs
			compositions[idx].CoverageDeltaReasons = dedupeSortedStrings(append(compositions[idx].CoverageDeltaReasons, reasons...))
			switch {
			case possibleEvasion:
				compositions[idx].ApprovalEvasionSignal = CompositionApprovalEvasionPossible
			case material:
				compositions[idx].ApprovalEvasionSignal = CompositionApprovalEvasionNone
			default:
				compositions[idx].ApprovalEvasionSignal = CompositionApprovalEvasionNone
			}
			if material {
				compositions[idx].Materiality = CompositionMaterialityMaterial
			} else {
				compositions[idx].Materiality = CompositionMaterialityNone
			}
			compositions[idx].ProposedActionContract = BuildProposedActionContract(compositions[idx])
			if compositions[idx].ProposedActionContract != nil {
				compositions[idx].ProposedActionContractRefs = []string{compositions[idx].ProposedActionContract.ContractID}
			}
		}
	}
}

func compositionOutcomeEquivalenceEligible(composition ComposedActionPath) bool {
	if strings.TrimSpace(composition.OutcomeKey) == "" || !compositionHasStableOutcomeTarget(composition) {
		return false
	}
	switch strings.TrimSpace(composition.OutcomeClass) {
	case "production_deploy", "data_egress", "network_egress", "production_mutation", "release_publish":
		return true
	default:
		return false
	}
}

func compositionHasStableOutcomeTarget(composition ComposedActionPath) bool {
	target := strings.TrimSpace(composition.TargetIdentity)
	if target == "" || target == TargetClassUnknown || target == "unknown" {
		return false
	}
	return !strings.HasSuffix(target, "/") && target != strings.TrimSpace(composition.TargetClass)
}

func equivalentOutcomeDeltaReasons(current, peer ComposedActionPath) []string {
	reasons := []string{}
	if strings.Join(compositionAuthorityRefs(current), ",") != strings.Join(compositionAuthorityRefs(peer), ",") {
		reasons = append(reasons, "equivalent_outcome:authority_identity_delta")
	}
	if strings.Join(current.WorkflowChainRefs, ",") != strings.Join(peer.WorkflowChainRefs, ",") {
		reasons = append(reasons, "equivalent_outcome:workflow_identity_delta")
	}
	if compositionTransitionApprovalRequired(current) != compositionTransitionApprovalRequired(peer) {
		reasons = append(reasons, "equivalent_outcome:approval_requirement_delta")
	}
	if strings.TrimSpace(current.PolicyCoverageStatus) != strings.TrimSpace(peer.PolicyCoverageStatus) {
		reasons = append(reasons, "equivalent_outcome:policy_coverage_delta")
	}
	if compositionGaitCoverageSignature(current.GaitCoverage) != compositionGaitCoverageSignature(peer.GaitCoverage) {
		reasons = append(reasons, "equivalent_outcome:gait_coverage_delta")
	}
	if proposedCredentialMode(current) != proposedCredentialMode(peer) {
		reasons = append(reasons, "equivalent_outcome:credential_mode_delta")
	}
	if strings.TrimSpace(current.EvidenceState) != strings.TrimSpace(peer.EvidenceState) ||
		strings.TrimSpace(current.ClaimState) != strings.TrimSpace(peer.ClaimState) {
		reasons = append(reasons, "equivalent_outcome:evidence_state_delta")
	}
	if recommendedControlRank(current.RecommendedControl) != recommendedControlRank(peer.RecommendedControl) {
		reasons = append(reasons, "equivalent_outcome:recommended_control_delta")
	}
	return dedupeSortedStrings(reasons)
}

func compositionAuthorityRefs(composition ComposedActionPath) []string {
	refs := []string{}
	for _, stage := range composition.Stages {
		refs = append(refs, stage.ParentAuthorityRef, stage.ChildAuthorityRef)
	}
	for _, transition := range composition.Transitions {
		refs = append(refs, transition.ParentAuthorityRef, transition.ChildAuthorityRef)
	}
	return dedupeSortedStrings(refs)
}

func compositionTransitionApprovalRequired(composition ComposedActionPath) bool {
	if composition.ProposedActionContract == nil {
		return false
	}
	return len(composition.ProposedActionContract.ApprovalRequiredTransitions) > 0 || len(composition.ProposedActionContract.ProhibitedTransitions) > 0
}

func compositionGaitCoverageSignature(coverage *GaitCoverage) string {
	if coverage == nil {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(coverage.PolicyDecision.Status),
		strings.TrimSpace(coverage.Approval.Status),
		strings.TrimSpace(coverage.JITCredential.Status),
		strings.TrimSpace(coverage.FreezeWindow.Status),
		strings.TrimSpace(coverage.KillSwitch.Status),
		strings.TrimSpace(coverage.ActionOutcome.Status),
		strings.TrimSpace(coverage.ProofVerification.Status),
	}, "|")
}

func compositionWeakerThanPeer(current, peer ComposedActionPath) bool {
	if recommendedControlRank(current.RecommendedControl) > recommendedControlRank(peer.RecommendedControl) {
		return true
	}
	if compositionPolicyCoverageRank(current.PolicyCoverageStatus) > compositionPolicyCoverageRank(peer.PolicyCoverageStatus) {
		return true
	}
	if evidenceStatePriority(current.EvidenceState) > evidenceStatePriority(peer.EvidenceState) {
		return true
	}
	return false
}

func compositionPolicyCoverageRank(value string) int {
	switch strings.TrimSpace(value) {
	case PolicyCoverageStatusRuntimeProven:
		return 0
	case PolicyCoverageStatusMatched:
		return 1
	case PolicyCoverageStatusDeclared:
		return 2
	case PolicyCoverageStatusStale:
		return 3
	case PolicyCoverageStatusNone:
		return 4
	case PolicyCoverageStatusConflict:
		return 5
	default:
		return 4
	}
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
			values = append(values, compositionMutableEndpointIdentity(item))
		}
		if path.CredentialAuthority != nil {
			values = append(values, compositionCredentialAuthorityIdentity(path.CredentialAuthority))
		}
		if path.CredentialProvenance != nil {
			values = append(values, compositionCredentialProvenanceIdentity(path.CredentialProvenance))
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
	var merged *EvidenceCompleteness
	for _, path := range paths {
		merged = mergeEvidenceCompletenessValues(merged, path.EvidenceCompleteness)
	}
	return merged
}

func compositionMutableEndpointIdentity(item agginventory.MutableEndpointSemantic) string {
	surface := strings.TrimSpace(item.Surface)
	operation := strings.TrimSpace(item.Operation)
	switch {
	case surface == "" && operation == "":
		return ""
	case surface == "":
		return "endpoint:(operation=" + operation + ")"
	case operation == "":
		return "endpoint:(surface=" + surface + ")"
	default:
		return "endpoint:(surface=" + surface + ",operation=" + operation + ")"
	}
}

func compositionCredentialAuthorityIdentity(authority *agginventory.CredentialAuthority) string {
	if authority == nil {
		return ""
	}
	targetSystem := strings.TrimSpace(authority.TargetSystem)
	likelyScope := strings.TrimSpace(authority.LikelyScope)
	switch {
	case targetSystem == "" && likelyScope == "":
		return ""
	case targetSystem == "":
		return "credential_authority:(likely_scope=" + likelyScope + ")"
	case likelyScope == "":
		return "credential_authority:(target_system=" + targetSystem + ")"
	default:
		return "credential_authority:(target_system=" + targetSystem + ",likely_scope=" + likelyScope + ")"
	}
}

func compositionCredentialProvenanceIdentity(provenance *agginventory.CredentialProvenance) string {
	if provenance == nil {
		return ""
	}
	targetSystem := strings.TrimSpace(provenance.TargetSystem)
	likelyScope := strings.TrimSpace(provenance.LikelyScope)
	scope := strings.TrimSpace(provenance.Scope)
	parts := []string{}
	if targetSystem != "" {
		parts = append(parts, "target_system="+targetSystem)
	}
	if likelyScope != "" {
		parts = append(parts, "likely_scope="+likelyScope)
	}
	if scope != "" {
		parts = append(parts, "scope="+scope)
	}
	if len(parts) == 0 {
		return ""
	}
	return "credential_provenance:(" + strings.Join(parts, ",") + ")"
}

func mergeEvidenceCompletenessValues(values ...*EvidenceCompleteness) *EvidenceCompleteness {
	present := make([]*EvidenceCompleteness, 0, len(values))
	for _, value := range values {
		if value != nil {
			present = append(present, CloneEvidenceCompleteness(value))
		}
	}
	if len(present) == 0 {
		return nil
	}
	merged := present[0]
	axisScores := map[string]EvidenceCompletenessAxisScore{}
	for _, item := range merged.AxisScores {
		axisScores[strings.TrimSpace(item.Axis)] = item
	}
	for _, completeness := range present[1:] {
		if completeness.TotalScore < merged.TotalScore {
			merged.TotalScore = completeness.TotalScore
		}
		merged.EvidenceGaps = dedupeSortedStrings(append(merged.EvidenceGaps, completeness.EvidenceGaps...))
		merged.UnsupportedSurfaces = dedupeSortedStrings(append(merged.UnsupportedSurfaces, completeness.UnsupportedSurfaces...))
		merged.FreshnessPenalties = dedupeSortedStrings(append(merged.FreshnessPenalties, completeness.FreshnessPenalties...))
		merged.ContradictionPenalties = dedupeSortedStrings(append(merged.ContradictionPenalties, completeness.ContradictionPenalties...))
		merged.Reasons = dedupeSortedStrings(append(merged.Reasons, completeness.Reasons...))
		for _, incoming := range completeness.AxisScores {
			key := strings.TrimSpace(incoming.Axis)
			current, ok := axisScores[key]
			if !ok {
				axisScores[key] = incoming
				continue
			}
			if incoming.Score < current.Score {
				current.Score = incoming.Score
			}
			current.Reasons = dedupeSortedStrings(append(current.Reasons, incoming.Reasons...))
			axisScores[key] = current
		}
	}
	merged.Label = evidenceCompletenessLabel(merged.TotalScore)
	merged.AxisScores = make([]EvidenceCompletenessAxisScore, 0, len(axisScores))
	seen := map[string]struct{}{}
	for _, axis := range completenessAxisOrder {
		score, ok := axisScores[axis]
		if !ok {
			continue
		}
		merged.AxisScores = append(merged.AxisScores, score)
		seen[axis] = struct{}{}
	}
	extras := make([]string, 0, len(axisScores))
	for axis := range axisScores {
		if _, ok := seen[axis]; ok {
			continue
		}
		extras = append(extras, axis)
	}
	sort.Strings(extras)
	for _, axis := range extras {
		merged.AxisScores = append(merged.AxisScores, axisScores[axis])
	}
	return merged
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
		status = compositionPolicyCoverageStatus(status, stage.PolicyCoverageStatus)
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

func compositionPolicyCoverageStatus(current, incoming string) string {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	if current == "" {
		if incoming == "" {
			return PolicyCoverageStatusNone
		}
		return incoming
	}
	if incoming == "" {
		return current
	}
	if current == PolicyCoverageStatusConflict || incoming == PolicyCoverageStatusConflict {
		return PolicyCoverageStatusConflict
	}
	if current == PolicyCoverageStatusNone || incoming == PolicyCoverageStatusNone {
		return PolicyCoverageStatusNone
	}
	if current == PolicyCoverageStatusStale || incoming == PolicyCoverageStatusStale {
		return PolicyCoverageStatusStale
	}
	if choosePolicyCoverageStatus(current, incoming) == current {
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

func compositionClaimState(evidenceState, policyCoverage, freshnessState string, gaitCoverage *GaitCoverage, stages []CompositionStage, paths []ActionPath) string {
	if strings.TrimSpace(evidenceState) == EvidenceStateContradictory || strings.TrimSpace(policyCoverage) == PolicyCoverageStatusConflict || GaitCoverageHasStatus(gaitCoverage, GaitStatusConflict) {
		return CompositionClaimContradictory
	}
	if compositionObservedExecution(paths, stages, gaitCoverage) {
		return CompositionClaimObservedExecution
	}
	if compositionRuntimeControlled(policyCoverage, freshnessState, gaitCoverage, stages) {
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

func compositionObservedExecution(paths []ActionPath, stages []CompositionStage, coverage *GaitCoverage) bool {
	if coverage == nil || strings.TrimSpace(coverage.ActionOutcome.Status) != GaitStatusPresent {
		return false
	}
	if len(paths) > 0 {
		for _, path := range paths {
			if strings.TrimSpace(path.RuntimeEvidenceState) != EvidenceStateVerified {
				return false
			}
			if path.GaitCoverage == nil {
				return false
			}
			actionOutcome := path.GaitCoverage.ActionOutcome
			if strings.TrimSpace(actionOutcome.Status) != GaitStatusPresent || len(actionOutcome.EvidenceRefs) == 0 {
				return false
			}
		}
		return true
	}
	if len(stages) == 0 {
		return false
	}
	for _, stage := range stages {
		if stage.GaitCoverage == nil {
			return false
		}
		actionOutcome := stage.GaitCoverage.ActionOutcome
		if strings.TrimSpace(actionOutcome.Status) != GaitStatusPresent || len(actionOutcome.EvidenceRefs) == 0 {
			return false
		}
	}
	return true
}

func compositionRuntimeControlled(policyCoverage, freshnessState string, coverage *GaitCoverage, stages []CompositionStage) bool {
	if strings.TrimSpace(policyCoverage) != PolicyCoverageStatusRuntimeProven || coverage == nil || len(stages) < 2 {
		return false
	}
	switch strings.TrimSpace(freshnessState) {
	case evidencepolicy.FreshnessStateStale, evidencepolicy.FreshnessStateExpired:
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
	for _, stage := range stages {
		if !compositionStageHasRuntimeControlledCoverage(stage) {
			return false
		}
	}
	return true
}

func compositionStageHasRuntimeControlledCoverage(stage CompositionStage) bool {
	if strings.TrimSpace(stage.PolicyCoverageStatus) != PolicyCoverageStatusRuntimeProven || stage.GaitCoverage == nil {
		return false
	}
	switch strings.TrimSpace(stage.FreshnessState) {
	case evidencepolicy.FreshnessStateStale, evidencepolicy.FreshnessStateExpired:
		return false
	}
	required := []GaitCoverageDetail{
		stage.GaitCoverage.PolicyDecision,
		stage.GaitCoverage.ActionOutcome,
		stage.GaitCoverage.ProofVerification,
	}
	for _, detail := range required {
		if strings.TrimSpace(detail.Status) != GaitStatusPresent || len(detail.EvidenceRefs) == 0 {
			return false
		}
	}
	for _, detail := range []GaitCoverageDetail{
		stage.GaitCoverage.Approval,
		stage.GaitCoverage.JITCredential,
		stage.GaitCoverage.FreezeWindow,
		stage.GaitCoverage.KillSwitch,
	} {
		switch strings.TrimSpace(detail.Status) {
		case GaitStatusPresent, GaitStatusNotApplicable:
		default:
			return false
		}
		if strings.TrimSpace(detail.Status) == GaitStatusPresent && len(detail.EvidenceRefs) == 0 {
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
