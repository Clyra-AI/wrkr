package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

const (
	ProposedActionContractVersion = "2"
	ProposedActionContractKind    = "proposed_action_contract"

	proposedActionContractReadinessNeedsEvidence = "needs_evidence"
	proposedCredentialModeEphemeral              = "ephemeral"
	proposedCredentialModeScoped                 = "scoped"
)

type ProposedActionContract struct {
	ContractID                  string                           `json:"contract_id"`
	ContractFamilyID            string                           `json:"contract_family_id"`
	ContractContentDigest       string                           `json:"contract_content_digest"`
	ContractVersion             string                           `json:"contract_version"`
	ContractKind                string                           `json:"contract_kind"`
	CompositionRef              string                           `json:"composition_ref"`
	ResolutionKey               string                           `json:"resolution_key,omitempty"`
	AllowedTransitions          []ProposedActionTransition       `json:"allowed_transitions,omitempty"`
	ProhibitedTransitions       []ProposedActionTransition       `json:"prohibited_transitions,omitempty"`
	ApprovalRequiredTransitions []ProposedActionTransition       `json:"approval_required_transitions,omitempty"`
	TargetConstraints           []ProposedActionTargetConstraint `json:"target_constraints,omitempty"`
	RequiredCredentialMode      string                           `json:"required_credential_mode,omitempty"`
	MaximumDelegationDepth      int                              `json:"maximum_delegation_depth"`
	EvidenceRequirements        []string                         `json:"evidence_requirements,omitempty"`
	AcceptableCountersigners    []string                         `json:"acceptable_countersigners,omitempty"`
	ExpectedOutcomeClass        string                           `json:"expected_outcome_class,omitempty"`
	CompensationRequired        bool                             `json:"compensation_required,omitempty"`
	ExpiresAt                   string                           `json:"expires_at,omitempty"`
	SourceDigests               []string                         `json:"source_digests,omitempty"`
	ReportOnly                  bool                             `json:"report_only"`
	ReadinessState              string                           `json:"readiness_state,omitempty"`
	ReasonCodes                 []string                         `json:"reason_codes,omitempty"`
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
		ReasonCodes:                 dedupeSortedStrings(append(reasons, "report_only:true")),
	}
	if strings.TrimSpace(contract.ExpiresAt) == "" {
		contract.ReasonCodes = dedupeSortedStrings(append(contract.ReasonCodes, "expiry:deterministic_source_absent"))
	}
	contract.ContractFamilyID = proposedContractFamilyID(composition, contract)
	contract.ContractContentDigest = proposedContractContentDigest(contract)
	contract.ContractID = "pac-" + stableProposedContractHash(strings.Join([]string{
		contract.ContractFamilyID,
		contract.ContractContentDigest,
		contract.ContractVersion,
	}, "|"))
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
	if strings.TrimSpace(composition.RecommendedControl) == RecommendedControlJITCredentialRequired ||
		strings.TrimSpace(composition.RecommendedControl) == RecommendedControlBlockStandingCredential {
		requirements = append(requirements, "jit_credential")
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
	if strings.TrimSpace(composition.CompositionID) == "" || len(composition.Stages) < 2 {
		reasons = append(reasons, "readiness:needs_composition_correlation")
	}
	switch strings.TrimSpace(composition.EvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		reasons = append(reasons, "readiness:needs_proof_evidence")
	}
	if strings.TrimSpace(composition.PolicyCoverageStatus) == PolicyCoverageStatusNone {
		reasons = append(reasons, "readiness:needs_policy_evidence")
	}
	if len(reasons) > 0 {
		return proposedActionContractReadinessNeedsEvidence, dedupeSortedStrings(reasons)
	}
	reasons = append(reasons, "readiness:ready_for_report_only")
	return ActionContractReadinessReadyForReportOnly, dedupeSortedStrings(reasons)
}

func proposedContractFamilyID(composition ComposedActionPath, contract *ProposedActionContract) string {
	controlIntent := strings.Join([]string{
		strings.TrimSpace(composition.RecommendedControl),
		strings.TrimSpace(contract.RequiredCredentialMode),
		strconv.Itoa(contract.MaximumDelegationDepth),
		strings.TrimSpace(composition.OutcomeClass),
	}, "|")
	return "pacf-" + stableProposedContractHash(strings.Join([]string{
		strings.TrimSpace(composition.CompositionID),
		strings.TrimSpace(composition.TargetIdentity),
		controlIntent,
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
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "sha256:" + hex.EncodeToString(sum[:])
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
