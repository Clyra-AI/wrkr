package risk

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

const (
	proposedRequirementReady   = "ready"
	proposedRequirementNeeds   = "needs_evidence"
	proposedRequirementBlocked = "blocked_by_contradiction"
)

func proposedAuthorityRequirements(composition ComposedActionPath) []ProposedActionRequirement {
	state := proposedContractEvidenceState(composition.EvidenceState)
	freshness := proposedContractFreshnessState(composition.FreshnessState)
	refs := proposedContractEvidenceRefs(composition)
	requester := ""
	roles := []string{}
	delegationRoot := ""
	for _, stage := range composition.Stages {
		if requester == "" && strings.TrimSpace(stage.StageID) != "" {
			requester = "stage:" + strings.TrimSpace(stage.StageID)
		}
		roles = append(roles, strings.TrimSpace(stage.Role))
		if delegationRoot == "" {
			delegationRoot = strings.TrimSpace(stage.ParentAuthorityRef)
		}
	}
	if delegationRoot == "" {
		for _, transition := range composition.Transitions {
			if strings.TrimSpace(transition.ParentAuthorityRef) != "" {
				delegationRoot = strings.TrimSpace(transition.ParentAuthorityRef)
				break
			}
		}
	}
	policyAuthority := firstPrefixedRef(refs, "policy:")
	if policyAuthority == "" {
		policyAuthority = firstPrefixedRef(refs, "gait:")
	}
	credentialSubject := strings.TrimSpace(composition.TargetIdentity)
	if credentialSubject == "" {
		credentialSubject = "target:required"
	}
	roleConstraint := strings.Join(dedupeSortedStrings(roles), ",")
	if roleConstraint == "" {
		roleConstraint = "role:required"
	}
	businessOwner := firstPrefixedRef(refs, "owner:business:")
	affectedSystemOwner := firstPrefixedRef(refs, "owner:system:")
	separationOfDuties := firstPrefixedRef(refs, "sod:")

	items := []ProposedActionRequirement{
		proposedAuthorityRequirement(composition, "originating_intent", "composition:"+strings.TrimSpace(composition.CompositionID), strings.TrimSpace(composition.PatternID), state, freshness, refs),
		proposedAuthorityRequirement(composition, "requester_identity", "requester_identity:required", requester, state, freshness, refs),
		proposedAuthorityRequirement(composition, "business_owner", "business_owner:required", businessOwner, state, freshness, refs),
		proposedAuthorityRequirement(composition, "affected_system_owner", "affected_system_owner:required", affectedSystemOwner, state, freshness, refs),
		proposedAuthorityRequirement(composition, "permitted_agent_role", "roles:"+roleConstraint, roleConstraint, state, freshness, refs),
		proposedAuthorityRequirement(composition, "policy_authority", "policy_authority:required", policyAuthority, state, freshness, refs),
		proposedAuthorityRequirement(composition, "delegation_root", "delegation_root:required", delegationRoot, state, freshness, refs),
		proposedAuthorityRequirement(composition, "credential_subject_constraint", "subject:"+credentialSubject, credentialSubject, state, freshness, refs),
		proposedAuthorityRequirement(composition, "separation_of_duties", "requester_must_not_approve", separationOfDuties, state, freshness, refs),
	}
	for idx := range items {
		if strings.TrimSpace(items[idx].ObservedValue) == "" {
			items[idx].EvidenceState = EvidenceStateUnknown
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "authority:"+items[idx].Kind+":missing"))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RequirementID < items[j].RequirementID })
	return items
}

func proposedAuthorityRequirement(composition ComposedActionPath, kind string, required string, observed string, state string, freshness string, refs []string) ProposedActionRequirement {
	return ProposedActionRequirement{
		RequirementID:      "pacr-" + stableProposedContractHash(strings.Join([]string{strings.TrimSpace(composition.CompositionID), kind, required}, "|")),
		Kind:               kind,
		RequiredConstraint: required,
		ObservedValue:      strings.TrimSpace(observed),
		EvidenceState:      state,
		FreshnessState:     freshness,
		EvidenceRefs:       append([]string(nil), refs...),
		ReasonCodes:        []string{"authority:" + kind + ":" + state},
	}
}

func proposedActionPreconditions(composition ComposedActionPath) []ProposedActionPrecondition {
	state := proposedContractEvidenceState(composition.EvidenceState)
	freshness := proposedContractFreshnessState(composition.FreshnessState)
	refs := proposedContractEvidenceRefs(composition)
	environment := strings.TrimSpace(composition.Environment)
	target := strings.TrimSpace(composition.TargetIdentity)
	policyDigest := firstPrefixedRef(composition.SourceDecisionRefs, "sha256:")
	if policyDigest == "" && len(composition.SourceDigestsForContract()) > 0 {
		policyDigest = composition.SourceDigestsForContract()[0]
	}
	items := []ProposedActionPrecondition{
		proposedPrecondition(composition, "validation_contract", "validation_contract:required", firstPrefixedRef(refs, "validation"), "", []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "effect_contract", "effect_contract:required", firstPrefixedRef(refs, "effect"), "", []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "required_check", "check:required", firstPrefixedRef(refs, "check"), "", []string{"ci", "gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "producer", "producer:approved", firstPrefixedRef(refs, "producer:"), "", []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "freshness", "fresh", freshness, freshness, []string{"evidence_policy"}, state, freshness, refs),
		proposedPrecondition(composition, "environment", "environment:declared", environment, environment, []string{"control_declaration", "gait_policy"}, state, freshness, refs),
		proposedPrecondition(composition, "target", "target:bounded", target, target, []string{"action_path"}, state, freshness, refs),
		proposedPrecondition(composition, "sandbox", "sandbox:required", firstPrefixedRef(refs, "sandbox"), "", []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "policy_digest", "policy_digest:required", policyDigest, policyDigest, []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "credential_mode", "credential_mode:"+proposedCredentialMode(composition), proposedCredentialMode(composition), proposedCredentialMode(composition), []string{"credential_authority"}, state, freshness, refs),
		proposedPrecondition(composition, "expected_effect", "effect:"+strings.TrimSpace(composition.OutcomeClass), strings.TrimSpace(composition.OutcomeClass), strings.TrimSpace(composition.OutcomeClass), []string{"action_path"}, state, freshness, refs),
		proposedPrecondition(composition, "forbidden_effect", "effect:not_unbounded", firstPrefixedRef(refs, "forbidden_effect:"), "", []string{"gait_policy", "control_declaration"}, state, freshness, refs),
	}
	for idx := range items {
		if strings.TrimSpace(items[idx].ObservedValue) == "" {
			items[idx].EvidenceState = EvidenceStateUnknown
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "precondition:"+items[idx].Kind+":missing"))
		}
		if items[idx].Kind == "freshness" && freshness != evidencepolicy.FreshnessStateFresh {
			items[idx].EvidenceState = EvidenceStateUnknown
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "precondition:freshness:not_fresh"))
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RequirementID < items[j].RequirementID })
	return items
}

func proposedPrecondition(composition ComposedActionPath, kind string, required string, observed string, result string, producers []string, state string, freshness string, refs []string) ProposedActionPrecondition {
	return ProposedActionPrecondition{
		RequirementID:       "pacp-" + stableProposedContractHash(strings.Join([]string{strings.TrimSpace(composition.CompositionID), kind, required}, "|")),
		Kind:                kind,
		RequiredConstraint:  required,
		ObservedValue:       strings.TrimSpace(observed),
		ObservedResult:      strings.TrimSpace(result),
		AcceptableProducers: dedupeSortedStrings(producers),
		MaxAge:              "PT24H",
		EvidenceState:       state,
		FreshnessState:      freshness,
		EvidenceRefs:        append([]string(nil), refs...),
		ReasonCodes:         []string{"precondition:" + kind + ":" + state},
	}
}

func proposedConfirmationRequirement(composition ComposedActionPath) *ProposedActionConfirmation {
	required := len(proposedApprovalRequiredTransitions(composition, proposedTransitionsForComposition(composition, "composition_transition"))) > 0
	state := proposedContractEvidenceState(composition.EvidenceState)
	if !required {
		state = EvidenceStateVerified
	}
	return &ProposedActionConfirmation{
		Mode:           firstNonEmptyString(map[bool]string{true: "explicit_confirmation", false: "not_required"}[required]),
		Required:       required,
		EvidenceState:  state,
		FreshnessState: proposedContractFreshnessState(composition.FreshnessState),
		EvidenceRefs:   proposedContractEvidenceRefs(composition),
		ReasonCodes:    []string{"confirmation:" + map[bool]string{true: "required", false: "not_required"}[required]},
	}
}

func proposedApprovalRequirement(composition ComposedActionPath) *ProposedActionApproval {
	required := len(proposedApprovalRequiredTransitions(composition, proposedTransitionsForComposition(composition, "composition_transition"))) > 0
	state := proposedContractEvidenceState(composition.EvidenceState)
	if !required {
		state = EvidenceStateVerified
	}
	minimum := 0
	if required {
		minimum = 1
		if strings.TrimSpace(composition.RiskTier) == RiskTierCritical || strings.TrimSpace(composition.RiskTier) == RiskTierHigh {
			minimum = 2
		}
	}
	return &ProposedActionApproval{
		Required:           required,
		ApproverRoles:      proposedCountersigners(composition),
		MinimumApprovals:   minimum,
		SeparationOfDuties: []string{"requester_must_not_approve"},
		ValidityWindow:     "PT24H",
		ReapprovalTriggers: []string{"contract_content_change", "scope_digest_change"},
		EvidenceState:      state,
		FreshnessState:     proposedContractFreshnessState(composition.FreshnessState),
		EvidenceRefs:       proposedContractEvidenceRefs(composition),
		ReasonCodes:        []string{"approval:" + map[bool]string{true: "required", false: "not_required"}[required]},
	}
}

func proposedCompensationRequirement(composition ComposedActionPath) *ProposedActionCompensation {
	required := proposedCompensationRequired(composition)
	state := proposedContractEvidenceState(composition.EvidenceState)
	refs := proposedContractEvidenceRefs(composition)
	procedure := firstPrefixedRef(refs, "compensation:")
	if required && procedure == "" {
		state = EvidenceStateUnknown
	}
	if !required {
		state = EvidenceStateVerified
	}
	return &ProposedActionCompensation{
		Required:             required,
		Kind:                 firstNonEmptyString(map[bool]string{true: "documented_recovery", false: "not_required"}[required]),
		ProcedureRef:         procedure,
		Target:               strings.TrimSpace(composition.TargetIdentity),
		ExecutionWindow:      "PT24H",
		VerificationRequired: required,
		AcceptableProducers:  []string{"gait_policy", "control_declaration"},
		EvidenceState:        state,
		FreshnessState:       proposedContractFreshnessState(composition.FreshnessState),
		EvidenceRefs:         refs,
		ReasonCodes:          []string{"compensation:" + map[bool]string{true: "required", false: "not_required"}[required]},
	}
}

func proposedAuthorityReadiness(requirements []ProposedActionRequirement, reasons []string) (string, []string) {
	state := proposedRequirementReady
	for _, requirement := range requirements {
		switch {
		case requirement.EvidenceState == EvidenceStateContradictory:
			state = proposedRequirementBlocked
			reasons = append(reasons, "authority:contradictory:"+requirement.Kind)
		case requirement.EvidenceState != EvidenceStateVerified || requirement.FreshnessState != evidencepolicy.FreshnessStateFresh:
			if state != proposedRequirementBlocked {
				state = proposedRequirementNeeds
			}
			reasons = append(reasons, "authority:unresolved:"+requirement.Kind)
		}
	}
	return state, dedupeSortedStrings(reasons)
}

func proposedActionContractV3Readiness(contract *ProposedActionContract, base string, reasons []string) (string, []string) {
	if contract == nil {
		return proposedActionContractReadinessNeedsEvidence, reasons
	}
	blocked := base == ActionContractReadinessBlockedContradict || contract.AuthorityReadinessState == proposedRequirementBlocked
	needs := base != ActionContractReadinessReadyForReportOnly || contract.AuthorityReadinessState != proposedRequirementReady
	for _, precondition := range contract.Preconditions {
		switch {
		case precondition.EvidenceState == EvidenceStateContradictory:
			blocked = true
			reasons = append(reasons, "precondition:contradictory:"+precondition.Kind)
		case precondition.EvidenceState != EvidenceStateVerified || precondition.FreshnessState != evidencepolicy.FreshnessStateFresh:
			needs = true
			reasons = append(reasons, "precondition:unresolved:"+precondition.Kind)
		}
	}
	for _, item := range []struct {
		name     string
		required bool
		state    string
		fresh    string
	}{
		{"confirmation", contract.ConfirmationRequirement != nil && contract.ConfirmationRequirement.Required, contractConfirmationState(contract), contractConfirmationFreshness(contract)},
		{"approval", contract.ApprovalRequirement != nil && contract.ApprovalRequirement.Required, contractApprovalState(contract), contractApprovalFreshness(contract)},
		{"compensation", contract.CompensationRequirement != nil && contract.CompensationRequirement.Required, contractCompensationState(contract), contractCompensationFreshness(contract)},
	} {
		if !item.required {
			continue
		}
		if item.state == EvidenceStateContradictory {
			blocked = true
			reasons = append(reasons, item.name+":contradictory")
		} else if item.state != EvidenceStateVerified || item.fresh != evidencepolicy.FreshnessStateFresh {
			needs = true
			reasons = append(reasons, item.name+":unresolved")
		}
	}
	if blocked {
		return ActionContractReadinessBlockedContradict, dedupeSortedStrings(reasons)
	}
	if needs {
		return proposedActionContractReadinessNeedsEvidence, dedupeSortedStrings(reasons)
	}
	return ActionContractReadinessReadyForReportOnly, dedupeSortedStrings(append(reasons, "readiness:typed_requirements_satisfied"))
}

func contractConfirmationState(contract *ProposedActionContract) string {
	if contract == nil || contract.ConfirmationRequirement == nil {
		return EvidenceStateUnknown
	}
	return contract.ConfirmationRequirement.EvidenceState
}
func contractConfirmationFreshness(contract *ProposedActionContract) string {
	if contract == nil || contract.ConfirmationRequirement == nil {
		return evidencepolicy.FreshnessStateUnknown
	}
	return contract.ConfirmationRequirement.FreshnessState
}
func contractApprovalState(contract *ProposedActionContract) string {
	if contract == nil || contract.ApprovalRequirement == nil {
		return EvidenceStateUnknown
	}
	return contract.ApprovalRequirement.EvidenceState
}
func contractApprovalFreshness(contract *ProposedActionContract) string {
	if contract == nil || contract.ApprovalRequirement == nil {
		return evidencepolicy.FreshnessStateUnknown
	}
	return contract.ApprovalRequirement.FreshnessState
}
func contractCompensationState(contract *ProposedActionContract) string {
	if contract == nil || contract.CompensationRequirement == nil {
		return EvidenceStateUnknown
	}
	return contract.CompensationRequirement.EvidenceState
}
func contractCompensationFreshness(contract *ProposedActionContract) string {
	if contract == nil || contract.CompensationRequirement == nil {
		return evidencepolicy.FreshnessStateUnknown
	}
	return contract.CompensationRequirement.FreshnessState
}

func proposedContractEvidenceState(value string) string {
	if ValidEvidenceState(value) {
		return strings.TrimSpace(value)
	}
	return EvidenceStateUnknown
}
func proposedContractFreshnessState(value string) string {
	switch strings.TrimSpace(value) {
	case evidencepolicy.FreshnessStateFresh, evidencepolicy.FreshnessStateStale, evidencepolicy.FreshnessStateExpired, evidencepolicy.FreshnessStateUnknown:
		return strings.TrimSpace(value)
	default:
		return evidencepolicy.FreshnessStateUnknown
	}
}
func proposedContractEvidenceRefs(composition ComposedActionPath) []string {
	return dedupeSortedStrings(append(append(append([]string(nil), composition.EvidenceRefs...), composition.ProofRefs...), composition.SourceDecisionRefs...))
}
func firstPrefixedRef(values []string, prefix string) string {
	for _, value := range dedupeSortedStrings(values) {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), strings.ToLower(prefix)) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (composition ComposedActionPath) SourceDigestsForContract() []string {
	return proposedSourceDigests(composition)
}

func cloneProposedActionRequirements(in []ProposedActionRequirement) []ProposedActionRequirement {
	out := append([]ProposedActionRequirement(nil), in...)
	for idx := range out {
		out[idx].EvidenceRefs = append([]string(nil), in[idx].EvidenceRefs...)
		out[idx].ReasonCodes = append([]string(nil), in[idx].ReasonCodes...)
	}
	return out
}
func cloneProposedActionPreconditions(in []ProposedActionPrecondition) []ProposedActionPrecondition {
	out := append([]ProposedActionPrecondition(nil), in...)
	for idx := range out {
		out[idx].AcceptableProducers = append([]string(nil), in[idx].AcceptableProducers...)
		out[idx].EvidenceRefs = append([]string(nil), in[idx].EvidenceRefs...)
		out[idx].ReasonCodes = append([]string(nil), in[idx].ReasonCodes...)
	}
	return out
}
func proposedActionRequirementKey(requirement ProposedActionRequirement) string {
	return strings.Join([]string{requirement.RequirementID, requirement.Kind, requirement.RequiredConstraint, requirement.ObservedValue, requirement.EvidenceState, requirement.FreshnessState, strings.Join(requirement.EvidenceRefs, ","), strings.Join(requirement.ReasonCodes, ",")}, "|")
}
func proposedActionPreconditionKey(precondition ProposedActionPrecondition) string {
	return strings.Join([]string{precondition.RequirementID, precondition.Kind, precondition.RequiredConstraint, precondition.ObservedValue, precondition.ObservedResult, strings.Join(precondition.AcceptableProducers, ","), precondition.MaxAge, precondition.EvidenceState, precondition.FreshnessState, strings.Join(precondition.EvidenceRefs, ","), strings.Join(precondition.ReasonCodes, ",")}, "|")
}
