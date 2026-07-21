package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	proofcanon "github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

const (
	ProposedActionContractVersionV2 = "2"
	ProposedActionContractVersionV3 = "3"
	ProposedActionContractVersion   = ProposedActionContractVersionV3
	ProposedActionContractKind      = "proposed_action_contract"

	proposedActionContractReadinessNeedsEvidence = "needs_evidence"
	proposedCredentialModeEphemeral              = "ephemeral"
	proposedCredentialModeScoped                 = "scoped"
)

type ProposedActionContract struct {
	ContractID                  string                               `json:"contract_id"`
	ContractFamilyID            string                               `json:"contract_family_id"`
	ContractContentDigest       string                               `json:"contract_content_digest"`
	ContractVersion             string                               `json:"contract_version"`
	ContractKind                string                               `json:"contract_kind"`
	CompositionRef              string                               `json:"composition_ref"`
	ResolutionKey               string                               `json:"resolution_key,omitempty"`
	AllowedTransitions          []ProposedActionTransition           `json:"allowed_transitions,omitempty"`
	ProhibitedTransitions       []ProposedActionTransition           `json:"prohibited_transitions,omitempty"`
	ApprovalRequiredTransitions []ProposedActionTransition           `json:"approval_required_transitions,omitempty"`
	TargetConstraints           []ProposedActionTargetConstraint     `json:"target_constraints,omitempty"`
	RequiredCredentialMode      string                               `json:"required_credential_mode,omitempty"`
	MaximumDelegationDepth      int                                  `json:"maximum_delegation_depth"`
	EvidenceRequirements        []string                             `json:"evidence_requirements,omitempty"`
	AcceptableCountersigners    []string                             `json:"acceptable_countersigners,omitempty"`
	ExpectedOutcomeClass        string                               `json:"expected_outcome_class,omitempty"`
	CompensationRequired        bool                                 `json:"compensation_required,omitempty"`
	ExpiresAt                   string                               `json:"expires_at,omitempty"`
	SourceDigests               []string                             `json:"source_digests,omitempty"`
	ReportOnly                  bool                                 `json:"report_only"`
	ReadinessState              string                               `json:"readiness_state,omitempty"`
	ReasonCodes                 []string                             `json:"reason_codes,omitempty"`
	Revision                    int                                  `json:"revision,omitempty"`
	AuthorityRequirements       []ProposedActionRequirement          `json:"authority_requirements,omitempty"`
	AuthorityReadinessState     string                               `json:"authority_readiness_state,omitempty"`
	Preconditions               []ProposedActionPrecondition         `json:"preconditions,omitempty"`
	ConfirmationRequirement     *ProposedActionConfirmation          `json:"confirmation_requirement,omitempty"`
	ApprovalRequirement         *ProposedActionApproval              `json:"approval_requirement,omitempty"`
	CompensationRequirement     *ProposedActionCompensation          `json:"compensation_requirement,omitempty"`
	SupersedesRef               string                               `json:"supersedes_ref,omitempty"`
	LifecycleObservations       []ProposedActionLifecycleObservation `json:"lifecycle_observations,omitempty"`
}

// ProposedActionRequirement is a report-only description of required
// authority. Evidence state records what Wrkr found; it is never a grant.
type ProposedActionRequirement struct {
	RequirementID      string   `json:"requirement_id"`
	Kind               string   `json:"kind"`
	RequiredConstraint string   `json:"required_constraint"`
	ObservedValue      string   `json:"observed_value,omitempty"`
	EvidenceState      string   `json:"evidence_state"`
	FreshnessState     string   `json:"freshness_state"`
	EvidenceRefs       []string `json:"evidence_refs,omitempty"`
	ReasonCodes        []string `json:"reason_codes,omitempty"`
}

// ProposedActionPrecondition keeps the required constraint separate from an
// observed result so serialization cannot turn a declared requirement into a
// satisfied runtime claim.
type ProposedActionPrecondition struct {
	RequirementID       string   `json:"requirement_id"`
	Kind                string   `json:"kind"`
	RequiredConstraint  string   `json:"required_constraint"`
	ObservedValue       string   `json:"observed_value,omitempty"`
	ObservedResult      string   `json:"observed_result,omitempty"`
	AcceptableProducers []string `json:"acceptable_producers,omitempty"`
	MaxAge              string   `json:"max_age,omitempty"`
	EvidenceState       string   `json:"evidence_state"`
	FreshnessState      string   `json:"freshness_state"`
	EvidenceRefs        []string `json:"evidence_refs,omitempty"`
	ReasonCodes         []string `json:"reason_codes,omitempty"`
}

type ProposedActionConfirmation struct {
	Mode           string   `json:"mode"`
	Required       bool     `json:"required"`
	EvidenceState  string   `json:"evidence_state"`
	FreshnessState string   `json:"freshness_state"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
	ReasonCodes    []string `json:"reason_codes,omitempty"`
}

type ProposedActionApproval struct {
	Required           bool     `json:"required"`
	ApproverRoles      []string `json:"approver_roles,omitempty"`
	MinimumApprovals   int      `json:"minimum_approvals"`
	SeparationOfDuties []string `json:"separation_of_duties,omitempty"`
	ScopeDigest        string   `json:"scope_digest"`
	ValidityWindow     string   `json:"validity_window,omitempty"`
	ReapprovalTriggers []string `json:"reapproval_triggers,omitempty"`
	EvidenceState      string   `json:"evidence_state"`
	FreshnessState     string   `json:"freshness_state"`
	EvidenceRefs       []string `json:"evidence_refs,omitempty"`
	ReasonCodes        []string `json:"reason_codes,omitempty"`
}

type ProposedActionCompensation struct {
	Required             bool     `json:"required"`
	Kind                 string   `json:"kind"`
	ProcedureRef         string   `json:"procedure_ref,omitempty"`
	Target               string   `json:"target,omitempty"`
	ExecutionWindow      string   `json:"execution_window,omitempty"`
	VerificationRequired bool     `json:"verification_required"`
	AcceptableProducers  []string `json:"acceptable_producers,omitempty"`
	EvidenceState        string   `json:"evidence_state"`
	FreshnessState       string   `json:"freshness_state"`
	EvidenceRefs         []string `json:"evidence_refs,omitempty"`
	ReasonCodes          []string `json:"reason_codes,omitempty"`
}

// ProposedActionLifecycleObservation records evidence imported from Gait or
// Axym. It is evidence about a downstream event, never a Wrkr transition.
type ProposedActionLifecycleObservation struct {
	ObservationID  string   `json:"observation_id"`
	Kind           string   `json:"kind"`
	Producer       string   `json:"producer"`
	EvidenceState  string   `json:"evidence_state"`
	FreshnessState string   `json:"freshness_state"`
	ObservedAt     string   `json:"observed_at,omitempty"`
	EvidenceRefs   []string `json:"evidence_refs,omitempty"`
	ProofRefs      []string `json:"proof_refs,omitempty"`
	ReasonCodes    []string `json:"reason_codes,omitempty"`
}

type ProposedActionTransition struct {
	TransitionID string `json:"transition_id"`
	FromStageID  string `json:"from_stage_id"`
	ToStageID    string `json:"to_stage_id"`
	FromRole     string `json:"from_role,omitempty"`
	ToRole       string `json:"to_role,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

type ProposedActionTargetConstraint struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func BuildProposedActionContract(composition ComposedActionPath) *ProposedActionContract {
	if strings.TrimSpace(composition.CompositionID) == "" {
		return nil
	}
	transitions := proposedTransitionsForComposition(composition, "composition_transition")
	readiness, reasons := proposedActionContractReadiness(composition)
	contract := &ProposedActionContract{
		ContractVersion:             ProposedActionContractVersion,
		ContractKind:                ProposedActionContractKind,
		CompositionRef:              strings.TrimSpace(composition.CompositionID),
		ResolutionKey:               strings.TrimSpace(composition.ResolutionKey),
		AllowedTransitions:          proposedAllowedTransitions(composition, transitions),
		ProhibitedTransitions:       proposedProhibitedTransitions(composition, transitions),
		ApprovalRequiredTransitions: proposedApprovalRequiredTransitions(composition, transitions),
		TargetConstraints:           proposedTargetConstraints(composition),
		RequiredCredentialMode:      proposedCredentialMode(composition),
		MaximumDelegationDepth:      proposedMaximumDelegationDepth(composition),
		EvidenceRequirements:        proposedEvidenceRequirements(composition),
		AcceptableCountersigners:    proposedCountersigners(composition),
		ExpectedOutcomeClass:        strings.TrimSpace(composition.OutcomeClass),
		CompensationRequired:        proposedCompensationRequired(composition),
		SourceDigests:               proposedSourceDigests(composition),
		ReportOnly:                  true,
		ReadinessState:              readiness,
		ReasonCodes:                 dedupeSortedStrings(append(append(reasons, composition.RecommendedControlReasons...), "report_only:true")),
		Revision:                    1,
	}
	contract.AuthorityRequirements = proposedAuthorityRequirements(composition)
	contract.Preconditions = proposedActionPreconditions(composition)
	contract.ConfirmationRequirement = proposedConfirmationRequirement(composition)
	contract.ApprovalRequirement = proposedApprovalRequirement(composition)
	contract.CompensationRequirement = proposedCompensationRequirement(composition)
	contract.AuthorityReadinessState, contract.ReasonCodes = proposedAuthorityReadiness(contract.AuthorityRequirements, contract.ReasonCodes)
	contract.ReadinessState, contract.ReasonCodes = proposedActionContractV3Readiness(contract, readiness, contract.ReasonCodes)
	if strings.TrimSpace(contract.ExpiresAt) == "" {
		contract.ReasonCodes = dedupeSortedStrings(append(contract.ReasonCodes, "expiry:deterministic_source_absent"))
	}
	RefreshProposedActionContractIdentity(contract)
	return contract
}

func CloneProposedActionContract(in *ProposedActionContract) *ProposedActionContract {
	if in == nil {
		return nil
	}
	out := *in
	out.AllowedTransitions = append([]ProposedActionTransition(nil), in.AllowedTransitions...)
	out.ProhibitedTransitions = append([]ProposedActionTransition(nil), in.ProhibitedTransitions...)
	out.ApprovalRequiredTransitions = append([]ProposedActionTransition(nil), in.ApprovalRequiredTransitions...)
	out.TargetConstraints = append([]ProposedActionTargetConstraint(nil), in.TargetConstraints...)
	out.EvidenceRequirements = append([]string(nil), in.EvidenceRequirements...)
	out.AcceptableCountersigners = append([]string(nil), in.AcceptableCountersigners...)
	out.SourceDigests = append([]string(nil), in.SourceDigests...)
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	out.LifecycleObservations = cloneProposedActionLifecycleObservations(in.LifecycleObservations)
	out.AuthorityRequirements = cloneProposedActionRequirements(in.AuthorityRequirements)
	out.Preconditions = cloneProposedActionPreconditions(in.Preconditions)
	if in.ConfirmationRequirement != nil {
		copyConfirmation := *in.ConfirmationRequirement
		copyConfirmation.EvidenceRefs = append([]string(nil), in.ConfirmationRequirement.EvidenceRefs...)
		copyConfirmation.ReasonCodes = append([]string(nil), in.ConfirmationRequirement.ReasonCodes...)
		out.ConfirmationRequirement = &copyConfirmation
	}
	if in.ApprovalRequirement != nil {
		copyApproval := *in.ApprovalRequirement
		copyApproval.ApproverRoles = append([]string(nil), in.ApprovalRequirement.ApproverRoles...)
		copyApproval.SeparationOfDuties = append([]string(nil), in.ApprovalRequirement.SeparationOfDuties...)
		copyApproval.ReapprovalTriggers = append([]string(nil), in.ApprovalRequirement.ReapprovalTriggers...)
		copyApproval.EvidenceRefs = append([]string(nil), in.ApprovalRequirement.EvidenceRefs...)
		copyApproval.ReasonCodes = append([]string(nil), in.ApprovalRequirement.ReasonCodes...)
		out.ApprovalRequirement = &copyApproval
	}
	if in.CompensationRequirement != nil {
		copyCompensation := *in.CompensationRequirement
		copyCompensation.AcceptableProducers = append([]string(nil), in.CompensationRequirement.AcceptableProducers...)
		copyCompensation.EvidenceRefs = append([]string(nil), in.CompensationRequirement.EvidenceRefs...)
		copyCompensation.ReasonCodes = append([]string(nil), in.CompensationRequirement.ReasonCodes...)
		out.CompensationRequirement = &copyCompensation
	}
	return &out
}

func proposedTransitionsForComposition(composition ComposedActionPath, reason string) []ProposedActionTransition {
	roleByStage := map[string]string{}
	for _, stage := range composition.Stages {
		roleByStage[strings.TrimSpace(stage.StageID)] = strings.TrimSpace(stage.Role)
	}
	out := make([]ProposedActionTransition, 0, len(composition.Transitions))
	for _, transition := range composition.Transitions {
		out = append(out, ProposedActionTransition{
			TransitionID: strings.TrimSpace(transition.TransitionID),
			FromStageID:  strings.TrimSpace(transition.FromStageID),
			ToStageID:    strings.TrimSpace(transition.ToStageID),
			FromRole:     roleByStage[strings.TrimSpace(transition.FromStageID)],
			ToRole:       roleByStage[strings.TrimSpace(transition.ToStageID)],
			Reason:       strings.TrimSpace(reason),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return proposedTransitionKey(out[i]) < proposedTransitionKey(out[j])
	})
	return out
}

func proposedAllowedTransitions(composition ComposedActionPath, transitions []ProposedActionTransition) []ProposedActionTransition {
	if len(proposedProhibitedTransitions(composition, transitions)) > 0 {
		return nil
	}
	switch strings.TrimSpace(composition.ClaimState) {
	case CompositionClaimRuntimeControlled, CompositionClaimObservedExecution:
		return append([]ProposedActionTransition(nil), transitions...)
	default:
		return nil
	}
}

func proposedProhibitedTransitions(composition ComposedActionPath, transitions []ProposedActionTransition) []ProposedActionTransition {
	switch strings.TrimSpace(composition.RecommendedControl) {
	case RecommendedControlBlock, RecommendedControlBlockStandingCredential:
		return append([]ProposedActionTransition(nil), transitions...)
	default:
		if strings.TrimSpace(composition.ClaimState) == CompositionClaimContradictory {
			return append([]ProposedActionTransition(nil), transitions...)
		}
		return nil
	}
}

func proposedApprovalRequiredTransitions(composition ComposedActionPath, transitions []ProposedActionTransition) []ProposedActionTransition {
	if len(transitions) == 0 {
		return nil
	}
	if len(proposedProhibitedTransitions(composition, transitions)) > 0 {
		return nil
	}
	switch strings.TrimSpace(composition.ClaimState) {
	case CompositionClaimRuntimeControlled, CompositionClaimObservedExecution:
		if strings.TrimSpace(composition.RecommendedControl) == RecommendedControlAllow {
			return nil
		}
	default:
		return append([]ProposedActionTransition(nil), transitions...)
	}
	switch strings.TrimSpace(composition.RecommendedControl) {
	case RecommendedControlAllow:
		return nil
	default:
		return append([]ProposedActionTransition(nil), transitions...)
	}
}

func proposedTargetConstraints(composition ComposedActionPath) []ProposedActionTargetConstraint {
	values := []ProposedActionTargetConstraint{
		{Key: "composition_id", Value: strings.TrimSpace(composition.CompositionID)},
		{Key: "target_identity", Value: strings.TrimSpace(composition.TargetIdentity)},
		{Key: "target_class", Value: strings.TrimSpace(composition.TargetClass)},
		{Key: "environment", Value: strings.TrimSpace(composition.Environment)},
		{Key: "outcome_class", Value: strings.TrimSpace(composition.OutcomeClass)},
	}
	if strings.TrimSpace(composition.ReachabilityState) != "" {
		values = append(values,
			ProposedActionTargetConstraint{Key: "reachability_state", Value: strings.TrimSpace(composition.ReachabilityState)},
			ProposedActionTargetConstraint{Key: "observed_execution", Value: strconv.FormatBool(composition.ObservedExecution)},
			ProposedActionTargetConstraint{Key: "system_class_sequence", Value: proposedSystemClassSequence(composition.Stages)},
			ProposedActionTargetConstraint{Key: "trust_boundary_sequence", Value: proposedTrustBoundarySequence(composition.Stages)},
		)
	}
	out := []ProposedActionTargetConstraint{}
	for _, item := range values {
		if strings.TrimSpace(item.Value) == "" {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func proposedCredentialMode(composition ComposedActionPath) string {
	for _, stage := range composition.Stages {
		for _, reason := range stage.EvidenceRefs {
			if strings.Contains(strings.ToLower(reason), "jit") {
				return proposedCredentialModeEphemeral
			}
		}
	}
	switch strings.TrimSpace(composition.RecommendedControl) {
	case RecommendedControlJITCredentialRequired, RecommendedControlBlockStandingCredential:
		return proposedCredentialModeEphemeral
	default:
		return proposedCredentialModeScoped
	}
}

func proposedMaximumDelegationDepth(composition ComposedActionPath) int {
	switch strings.TrimSpace(composition.RiskTier) {
	case RiskTierCritical, RiskTierHigh:
		return 1
	default:
		return 2
	}
}

func proposedEvidenceRequirements(composition ComposedActionPath) []string {
	requirements := []string{"policy_decision", "approval", "action_outcome", "proof_verification"}
	if strings.TrimSpace(composition.ReachabilityState) != "" {
		requirements = append(requirements, "transition_correlation", "trust_boundary_evidence")
	}
	if strings.TrimSpace(composition.RecommendedControl) == RecommendedControlJITCredentialRequired ||
		strings.TrimSpace(composition.RecommendedControl) == RecommendedControlBlockStandingCredential {
		requirements = append(requirements, "jit_credential")
	}
	for _, transition := range composition.Transitions {
		switch strings.TrimSpace(transition.Relationship) {
		case CompositionDelegationBroadened:
			requirements = append(requirements, "delegation_relationship", "credential_attenuation", "runtime_token_propagation")
		case CompositionDelegationContradictory:
			requirements = append(requirements, "delegation_relationship", "contradiction_resolution")
		case CompositionDelegationUnknown:
			requirements = append(requirements, "delegation_relationship", "runtime_token_propagation")
		}
	}
	if strings.TrimSpace(composition.ApprovalEvasionSignal) == CompositionApprovalEvasionPossible {
		requirements = append(requirements, "equivalent_outcome_review", "approval_path_parity")
	}
	return dedupeSortedStrings(requirements)
}

func proposedCountersigners(composition ComposedActionPath) []string {
	switch strings.TrimSpace(composition.RiskTier) {
	case RiskTierCritical, RiskTierHigh:
		return []string{"control_owner", "security_reviewer"}
	default:
		return []string{"control_owner"}
	}
}

func proposedCompensationRequired(composition ComposedActionPath) bool {
	switch strings.TrimSpace(composition.OutcomeClass) {
	case "production_deploy", "production_mutation", "release_publish":
		return true
	default:
		return strings.TrimSpace(composition.RecommendedControl) == RecommendedControlBlock
	}
}

func proposedSourceDigests(composition ComposedActionPath) []string {
	values := []string{composition.CompositionID, composition.ResolutionKey, composition.DurableOutcomeKey}
	values = append(values, composition.EvidenceRefs...)
	values = append(values, composition.ProofRefs...)
	values = append(values, composition.SourceDecisionRefs...)
	values = dedupeSortedStrings(values)
	if len(values) == 0 {
		return nil
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "\x1f")))
	return []string{"sha256:" + hex.EncodeToString(sum[:])}
}

func proposedActionContractReadiness(composition ComposedActionPath) (string, []string) {
	if strings.TrimSpace(composition.ClaimState) == CompositionClaimContradictory {
		return ActionContractReadinessBlockedContradict, []string{"readiness:contradictory_composition"}
	}
	reasons := []string{}
	if strings.TrimSpace(composition.ReachabilityState) == CompositionReachabilityIncomplete {
		reasons = append(reasons, "readiness:needs_composition_correlation")
	}
	if strings.TrimSpace(composition.CompositionID) == "" || len(composition.Stages) < 2 {
		reasons = append(reasons, "readiness:needs_composition_correlation")
	}
	switch strings.TrimSpace(composition.EvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		reasons = append(reasons, "readiness:needs_proof_evidence")
	}
	switch strings.TrimSpace(composition.PolicyCoverageStatus) {
	case PolicyCoverageStatusNone, PolicyCoverageStatusStale:
		reasons = append(reasons, "readiness:needs_policy_evidence")
	}
	switch strings.TrimSpace(composition.FreshnessState) {
	case evidencepolicy.FreshnessStateStale, evidencepolicy.FreshnessStateExpired:
		reasons = append(reasons, "readiness:needs_fresh_evidence")
	}
	for _, transition := range composition.Transitions {
		switch strings.TrimSpace(transition.Relationship) {
		case CompositionDelegationBroadened:
			reasons = append(reasons, "readiness:needs_delegation_attenuation_evidence")
		case CompositionDelegationUnknown:
			reasons = append(reasons, "readiness:needs_runtime_token_propagation_evidence")
		case CompositionDelegationContradictory:
			return ActionContractReadinessBlockedContradict, []string{"readiness:contradictory_delegation_relationship"}
		}
	}
	if strings.TrimSpace(composition.ApprovalEvasionSignal) == CompositionApprovalEvasionPossible {
		reasons = append(reasons, "readiness:needs_equivalent_outcome_control_parity")
	}
	if len(reasons) > 0 {
		return proposedActionContractReadinessNeedsEvidence, dedupeSortedStrings(reasons)
	}
	reasons = append(reasons, "readiness:ready_for_report_only")
	return ActionContractReadinessReadyForReportOnly, dedupeSortedStrings(reasons)
}

func proposedSystemClassSequence(stages []CompositionStage) string {
	values := make([]string, 0, len(stages))
	for _, stage := range stages {
		value := strings.TrimSpace(stage.SystemClass)
		if value == "" {
			return ""
		}
		values = append(values, value)
	}
	return strings.Join(values, "->")
}

func proposedTrustBoundarySequence(stages []CompositionStage) string {
	values := make([]string, 0, len(stages))
	for _, stage := range stages {
		value := strings.TrimSpace(stage.TrustBoundary)
		if value == "" {
			return ""
		}
		values = append(values, value)
	}
	return strings.Join(values, "->")
}

func RefreshProposedActionContractIdentity(contract *ProposedActionContract) {
	if contract == nil {
		return
	}
	contract.ContractFamilyID = proposedContractFamilyID(contract)
	if strings.TrimSpace(contract.ContractVersion) == ProposedActionContractVersionV3 && contract.ApprovalRequirement != nil {
		contract.ApprovalRequirement.ScopeDigest = proposedApprovalScopeDigest(contract)
	}
	contract.ContractContentDigest = proposedContractContentDigest(contract)
	contract.ContractID = "pac-" + stableProposedContractHash(strings.Join([]string{
		contract.ContractFamilyID,
		contract.ContractContentDigest,
		contract.ContractVersion,
	}, "|"))
}

func proposedContractFamilyID(contract *ProposedActionContract) string {
	if contract == nil {
		return ""
	}
	controlIntent := strings.Join([]string{
		strings.TrimSpace(contract.RequiredCredentialMode),
		strconv.Itoa(contract.MaximumDelegationDepth),
		strings.TrimSpace(contract.ExpectedOutcomeClass),
		strings.TrimSpace(contract.ResolutionKey),
	}, "|")
	targetConstraints := make([]string, 0, len(contract.TargetConstraints))
	for _, constraint := range contract.TargetConstraints {
		targetConstraints = append(targetConstraints, constraint.Key+"="+constraint.Value)
	}
	return "pacf-" + stableProposedContractHash(strings.Join([]string{
		strings.TrimSpace(contract.CompositionRef),
		controlIntent,
		strings.Join(targetConstraints, "|"),
	}, "\x1f"))
}

func proposedContractContentDigest(contract *ProposedActionContract) string {
	parts := []string{
		"version=" + strings.TrimSpace(contract.ContractVersion),
		"kind=" + strings.TrimSpace(contract.ContractKind),
		"composition=" + strings.TrimSpace(contract.CompositionRef),
		"resolution=" + strings.TrimSpace(contract.ResolutionKey),
		"credential_mode=" + strings.TrimSpace(contract.RequiredCredentialMode),
		"delegation_depth=" + strconv.Itoa(contract.MaximumDelegationDepth),
		"outcome=" + strings.TrimSpace(contract.ExpectedOutcomeClass),
		"compensation=" + strconv.FormatBool(contract.CompensationRequired),
		"expires_at=" + strings.TrimSpace(contract.ExpiresAt),
		"report_only=" + strconv.FormatBool(contract.ReportOnly),
		"readiness=" + strings.TrimSpace(contract.ReadinessState),
		"revision=" + strconv.Itoa(contract.Revision),
		"supersedes=" + strings.TrimSpace(contract.SupersedesRef),
		"authority_readiness=" + strings.TrimSpace(contract.AuthorityReadinessState),
	}
	for _, transition := range contract.AllowedTransitions {
		parts = append(parts, "allow="+proposedTransitionKey(transition))
	}
	for _, transition := range contract.ProhibitedTransitions {
		parts = append(parts, "prohibit="+proposedTransitionKey(transition))
	}
	for _, transition := range contract.ApprovalRequiredTransitions {
		parts = append(parts, "approval="+proposedTransitionKey(transition))
	}
	for _, constraint := range contract.TargetConstraints {
		parts = append(parts, "target="+constraint.Key+"="+constraint.Value)
	}
	for _, value := range contract.EvidenceRequirements {
		parts = append(parts, "evidence="+strings.TrimSpace(value))
	}
	for _, value := range contract.AcceptableCountersigners {
		parts = append(parts, "countersigner="+strings.TrimSpace(value))
	}
	for _, value := range contract.SourceDigests {
		parts = append(parts, "digest="+strings.TrimSpace(value))
	}
	for _, value := range contract.ReasonCodes {
		parts = append(parts, "reason="+strings.TrimSpace(value))
	}
	for _, requirement := range contract.AuthorityRequirements {
		parts = append(parts, "authority="+proposedActionRequirementKey(requirement))
	}
	for _, precondition := range contract.Preconditions {
		parts = append(parts, "precondition="+proposedActionPreconditionKey(precondition))
	}
	if contract.ConfirmationRequirement != nil {
		parts = append(parts, "confirmation="+strings.Join([]string{
			contract.ConfirmationRequirement.Mode,
			strconv.FormatBool(contract.ConfirmationRequirement.Required),
			contract.ConfirmationRequirement.EvidenceState,
			contract.ConfirmationRequirement.FreshnessState,
			strings.Join(contract.ConfirmationRequirement.EvidenceRefs, ","),
			strings.Join(contract.ConfirmationRequirement.ReasonCodes, ","),
		}, "|"))
	}
	if contract.ApprovalRequirement != nil {
		parts = append(parts, "approval="+strings.Join([]string{
			strconv.FormatBool(contract.ApprovalRequirement.Required),
			strings.Join(contract.ApprovalRequirement.ApproverRoles, ","),
			strconv.Itoa(contract.ApprovalRequirement.MinimumApprovals),
			strings.Join(contract.ApprovalRequirement.SeparationOfDuties, ","),
			contract.ApprovalRequirement.ScopeDigest,
			contract.ApprovalRequirement.ValidityWindow,
			strings.Join(contract.ApprovalRequirement.ReapprovalTriggers, ","),
			contract.ApprovalRequirement.EvidenceState,
			contract.ApprovalRequirement.FreshnessState,
			strings.Join(contract.ApprovalRequirement.EvidenceRefs, ","),
			strings.Join(contract.ApprovalRequirement.ReasonCodes, ","),
		}, "|"))
	}
	if contract.CompensationRequirement != nil {
		parts = append(parts, "compensation="+strings.Join([]string{
			strconv.FormatBool(contract.CompensationRequirement.Required),
			contract.CompensationRequirement.Kind,
			contract.CompensationRequirement.ProcedureRef,
			contract.CompensationRequirement.Target,
			contract.CompensationRequirement.ExecutionWindow,
			strconv.FormatBool(contract.CompensationRequirement.VerificationRequired),
			strings.Join(contract.CompensationRequirement.AcceptableProducers, ","),
			contract.CompensationRequirement.EvidenceState,
			contract.CompensationRequirement.FreshnessState,
			strings.Join(contract.CompensationRequirement.EvidenceRefs, ","),
			strings.Join(contract.CompensationRequirement.ReasonCodes, ","),
		}, "|"))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func proposedApprovalScopeDigest(contract *ProposedActionContract) string {
	if contract == nil {
		return ""
	}
	payload := map[string]any{
		"contract_family_id":       strings.TrimSpace(contract.ContractFamilyID),
		"revision":                 contract.Revision,
		"composition_ref":          strings.TrimSpace(contract.CompositionRef),
		"resolution_key":           strings.TrimSpace(contract.ResolutionKey),
		"target_constraints":       contract.TargetConstraints,
		"authority_requirements":   contract.AuthorityRequirements,
		"preconditions":            contract.Preconditions,
		"allowed_transitions":      contract.AllowedTransitions,
		"prohibited_transitions":   contract.ProhibitedTransitions,
		"approval_transitions":     contract.ApprovalRequiredTransitions,
		"expected_outcome_class":   strings.TrimSpace(contract.ExpectedOutcomeClass),
		"required_credential_mode": strings.TrimSpace(contract.RequiredCredentialMode),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	digest, err := proofcanon.DigestHex(encoded, proofcanon.DomainJSON)
	if err != nil {
		return ""
	}
	return "sha256:" + digest
}

func proposedTransitionKey(transition ProposedActionTransition) string {
	return strings.Join([]string{
		strings.TrimSpace(transition.TransitionID),
		strings.TrimSpace(transition.FromStageID),
		strings.TrimSpace(transition.ToStageID),
		strings.TrimSpace(transition.FromRole),
		strings.TrimSpace(transition.ToRole),
		strings.TrimSpace(transition.Reason),
	}, "|")
}

func stableProposedContractHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:8])
}
