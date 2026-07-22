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
	originatingIntent := firstMatchingRef(refs, "task:", "intent:")
	requesters := matchingRefs(refs, "requester:human:", "requester:service:")
	roles := matchingRefs(refs, "agent_role:")
	delegationRoots := matchingRefs(refs, "delegation_root:")
	for _, stage := range composition.Stages {
		if strings.TrimSpace(stage.ParentAuthorityRef) != "" {
			delegationRoots = append(delegationRoots, strings.TrimSpace(stage.ParentAuthorityRef))
		}
	}
	for _, transition := range composition.Transitions {
		if strings.TrimSpace(transition.ParentAuthorityRef) != "" {
			delegationRoots = append(delegationRoots, strings.TrimSpace(transition.ParentAuthorityRef))
		}
	}
	policyAuthorities := matchingRefs(refs, "policy:", "gait:policy:")
	credentialSubjects := matchingRefs(refs, "credential_subject:", "binding_subject:", "provenance_subject:")
	businessOwners := matchingRefs(refs, "owner:business:")
	affectedSystemOwners := matchingRefs(refs, "owner:system:")
	separationOfDuties := matchingRefs(refs, "sod:")
	delegationRoots = dedupeSortedStrings(delegationRoots)

	items := []ProposedActionRequirement{
		proposedAuthorityRequirement(composition, "originating_intent", "originating_task_or_intent:required", originatingIntent, state, freshness, refs),
		proposedAuthorityRequirement(composition, "requester_identity", "requester_identity:required", strings.Join(requesters, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "business_owner", "business_owner:required", strings.Join(businessOwners, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "affected_system_owner", "affected_system_owner:required", strings.Join(affectedSystemOwners, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "permitted_agent_role", "permitted_agent_role:required", strings.Join(roles, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "policy_authority", "policy_authority:required", strings.Join(policyAuthorities, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "delegation_root", "delegation_root:required", strings.Join(delegationRoots, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "credential_subject_constraint", "credential_subject:required", strings.Join(credentialSubjects, ","), state, freshness, refs),
		proposedAuthorityRequirement(composition, "separation_of_duties", "requester_must_not_approve", strings.Join(separationOfDuties, ","), state, freshness, refs),
	}
	for idx := range items {
		if strings.TrimSpace(items[idx].ObservedValue) == "" {
			items[idx].EvidenceState = EvidenceStateUnknown
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "authority:"+items[idx].Kind+":missing"))
		}
		if authorityRequirementContradictory(items[idx].Kind, refs) {
			items[idx].EvidenceState = EvidenceStateContradictory
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "authority:"+items[idx].Kind+":contradictory"))
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

func authorityRequirementContradictory(kind string, refs []string) bool {
	switch strings.TrimSpace(kind) {
	case "requester_identity":
		return len(matchingRefs(refs, "requester:human:", "requester:service:")) > 1
	case "business_owner":
		return len(matchingRefs(refs, "owner:business:")) > 1
	case "affected_system_owner":
		return len(matchingRefs(refs, "owner:system:")) > 1
	case "policy_authority":
		return len(matchingRefs(refs, "policy:", "gait:policy:")) > 1
	case "delegation_root":
		return containsPrefixedRef(refs, "delegation:contradictory", "delegation:excessive_child_authority")
	case "credential_subject_constraint":
		return containsPrefixedRef(refs, "credential_subject:shared:", "credential:shared", "credential_subject:contradictory")
	case "separation_of_duties":
		return containsPrefixedRef(refs, "sod:conflict", "sod:self_approval")
	default:
		return false
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
	validationContract := firstMatchingRef(refs, "validation_contract:", "validation:")
	effectContract := firstMatchingRef(refs, "effect_contract:", "effect:")
	requiredCheck := firstMatchingRef(refs, "check:")
	producer := firstMatchingRef(refs, "producer:")
	sandbox := firstMatchingRef(refs, "sandbox:")
	forbiddenEffect := firstMatchingRef(refs, "forbidden_effect:")
	credentialMode := proposedCredentialMode(composition)
	if containsPrefixedRef(refs, "authority_standing:true", "credential:standing") {
		credentialMode = "standing"
	}
	items := []ProposedActionPrecondition{
		proposedPrecondition(composition, "validation_contract", "validation_contract:required", validationContract, observedRefResult(validationContract), []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "effect_contract", "effect_contract:required", effectContract, observedRefResult(effectContract), []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "required_check", "check:required", requiredCheck, observedRefResult(requiredCheck), []string{"ci", "gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "producer", "producer:approved", producer, observedRefResult(producer), []string{"ci", "gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "freshness", "fresh", freshness, freshness, []string{"evidence_policy"}, state, freshness, refs),
		proposedPrecondition(composition, "environment", "environment:declared", environment, environment, []string{"control_declaration", "gait_policy"}, state, freshness, refs),
		proposedPrecondition(composition, "target", "target:bounded", firstNonEmptyString(firstMatchingRef(refs, "target_observed:"), target), target, []string{"action_path"}, state, freshness, refs),
		proposedPrecondition(composition, "sandbox", "sandbox:required", sandbox, observedRefResult(sandbox), []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "policy_digest", "policy_digest:required", policyDigest, policyDigest, []string{"gait_policy", "control_declaration"}, state, freshness, refs),
		proposedPrecondition(composition, "credential_mode", "credential_mode:"+proposedCredentialMode(composition), credentialMode, credentialMode, []string{"credential_authority"}, state, freshness, refs),
		proposedPrecondition(composition, "expected_effect", "effect:"+strings.TrimSpace(composition.OutcomeClass), strings.TrimSpace(composition.OutcomeClass), strings.TrimSpace(composition.OutcomeClass), []string{"action_path"}, state, freshness, refs),
		proposedPrecondition(composition, "forbidden_effect", "effect:not_unbounded", forbiddenEffect, observedRefResult(forbiddenEffect), []string{"gait_policy", "control_declaration"}, state, freshness, refs),
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
		if preconditionContradictory(items[idx], composition, refs) {
			items[idx].EvidenceState = EvidenceStateContradictory
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "precondition:"+items[idx].Kind+":contradictory"))
		} else if preconditionUnverified(items[idx], composition, refs) {
			items[idx].EvidenceState = EvidenceStateUnknown
			items[idx].ReasonCodes = dedupeSortedStrings(append(items[idx].ReasonCodes, "precondition:"+items[idx].Kind+":unverified"))
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

func observedRefResult(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, result := range []string{"contradictory", "failed", "unsupported", "unavailable", "stale", "expired", "verified", "passed", "declared"} {
		if strings.HasSuffix(lower, ":"+result) {
			return result
		}
	}
	if lower == "" {
		return ""
	}
	return "declared"
}

func preconditionContradictory(item ProposedActionPrecondition, composition ComposedActionPath, refs []string) bool {
	result := strings.ToLower(strings.TrimSpace(item.ObservedResult))
	switch result {
	case "contradictory", "failed", "unsupported", "unavailable", "expired":
		return true
	}
	switch item.Kind {
	case "credential_mode":
		return strings.TrimSpace(item.ObservedValue) != "" && strings.TrimSpace(item.ObservedValue) != proposedCredentialMode(composition)
	case "environment":
		environment := strings.ToLower(strings.TrimSpace(item.ObservedValue))
		return environment != "" && environment != "unknown" && !supportedActionContractEnvironment(environment)
	case "target":
		observed := strings.TrimPrefix(strings.TrimSpace(item.ObservedValue), "target_observed:")
		return observed == "" || observed != strings.TrimSpace(composition.TargetIdentity)
	case "producer":
		return strings.TrimSpace(item.ObservedValue) != "" && !approvedPreconditionProducer(item.ObservedValue)
	case "sandbox":
		return containsPrefixedRef(refs, "sandbox:unsupported", "sandbox:absent", "sandbox:disabled")
	case "policy_digest":
		return strings.TrimSpace(item.ObservedValue) != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(item.ObservedValue)), "sha256:")
	default:
		return false
	}
}

func preconditionUnverified(item ProposedActionPrecondition, _ ComposedActionPath, _ []string) bool {
	switch item.Kind {
	case "required_check":
		return strings.TrimSpace(item.ObservedValue) != "" && item.ObservedResult != "passed" && item.ObservedResult != "verified"
	case "producer":
		return strings.TrimSpace(item.ObservedValue) != "" && !approvedPreconditionProducer(item.ObservedValue)
	default:
		return false
	}
}

func approvedPreconditionProducer(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"producer:ci", "producer:gait_policy", "producer:control_declaration"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+":") {
			return true
		}
	}
	return false
}

func supportedActionContractEnvironment(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "production", "prod", "staging", "stage", "development", "dev", "test", "sandbox", "release", "external", "internal":
		return true
	default:
		return false
	}
}

func proposedConfirmationRequirement(composition ComposedActionPath) *ProposedActionConfirmation {
	required := len(proposedApprovalRequiredTransitions(composition, proposedTransitionsForComposition(composition, "composition_transition"))) > 0
	refs := proposedContractEvidenceRefs(composition)
	confirmationRefs := matchingRefs(refs, "confirmation:")
	state := proposedContractEvidenceState(composition.EvidenceState)
	reasons := []string{"confirmation:" + map[bool]string{true: "required", false: "not_required"}[required]}
	if !required {
		state = EvidenceStateVerified
	} else if len(confirmationRefs) == 0 {
		state = EvidenceStateUnknown
		reasons = append(reasons, "confirmation:evidence_missing")
	} else if containsPrefixedRef(confirmationRefs, "confirmation:rejected", "confirmation:contradictory") {
		state = EvidenceStateContradictory
		reasons = append(reasons, "confirmation:contradictory")
	}
	return &ProposedActionConfirmation{
		Mode:           firstNonEmptyString(map[bool]string{true: "explicit_confirmation", false: "not_required"}[required]),
		Required:       required,
		EvidenceState:  state,
		FreshnessState: proposedContractFreshnessState(composition.FreshnessState),
		EvidenceRefs:   confirmationRefs,
		ReasonCodes:    dedupeSortedStrings(reasons),
	}
}

func proposedApprovalRequirement(composition ComposedActionPath) *ProposedActionApproval {
	required := len(proposedApprovalRequiredTransitions(composition, proposedTransitionsForComposition(composition, "composition_transition"))) > 0
	refs := proposedContractEvidenceRefs(composition)
	approvalRefs := matchingRefs(refs, "approval_receipt:", "approver:", "approval_scope_digest:", "approval:")
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
	approverRefs := matchingRefs(refs, "approver:")
	reasons := []string{"approval:" + map[bool]string{true: "required", false: "not_required"}[required]}
	if required && (!containsPrefixedRef(refs, "approval_receipt:") || len(approverRefs) < minimum) {
		state = EvidenceStateUnknown
		reasons = append(reasons, "approval:evidence_missing")
	}
	if approvalHasSelfApproval(refs) || containsPrefixedRef(refs, "sod:conflict", "sod:self_approval", "approval:contradictory") {
		state = EvidenceStateContradictory
		reasons = append(reasons, "approval:separation_of_duties_conflict")
	}
	freshness := proposedContractFreshnessState(composition.FreshnessState)
	if containsPrefixedRef(refs, "approval:freshness:stale") {
		freshness = evidencepolicy.FreshnessStateStale
	}
	if containsPrefixedRef(refs, "approval:freshness:expired") {
		freshness = evidencepolicy.FreshnessStateExpired
	}
	return &ProposedActionApproval{
		Required:           required,
		ApproverRoles:      proposedCountersigners(composition),
		MinimumApprovals:   minimum,
		SeparationOfDuties: []string{"requester_must_not_approve"},
		ValidityWindow:     "PT24H",
		ReapprovalTriggers: []string{"contract_content_change", "scope_digest_change"},
		EvidenceState:      state,
		FreshnessState:     freshness,
		EvidenceRefs:       approvalRefs,
		ReasonCodes:        dedupeSortedStrings(reasons),
	}
}

func finalizeProposedApprovalScope(contract *ProposedActionContract, composition ComposedActionPath) {
	if contract == nil || contract.ApprovalRequirement == nil || !contract.ApprovalRequirement.Required {
		return
	}
	approval := contract.ApprovalRequirement
	observed := firstMatchingRef(proposedContractEvidenceRefs(composition), "approval_scope_digest:")
	observed = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(observed), "approval_scope_digest:"))
	observed = strings.TrimSpace(strings.TrimPrefix(observed, "sha256:"))
	expected := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(approval.ScopeDigest), "sha256:"))
	switch {
	case observed == "":
		approval.EvidenceState = EvidenceStateUnknown
		approval.ReasonCodes = dedupeSortedStrings(append(approval.ReasonCodes, "approval:scope_digest_missing"))
	case observed != expected:
		approval.EvidenceState = EvidenceStateContradictory
		approval.ReasonCodes = dedupeSortedStrings(append(approval.ReasonCodes, "approval:scope_digest_mismatch", "approval:reapproval_required"))
	}
	if containsPrefixedRef(proposedContractEvidenceRefs(composition), "approval:scope_changed", "approval:reapproval_required") {
		approval.EvidenceState = EvidenceStateContradictory
		approval.ReasonCodes = dedupeSortedStrings(append(approval.ReasonCodes, "approval:reapproval_required"))
	}
}

func approvalHasSelfApproval(refs []string) bool {
	requesters := matchingRefs(refs, "requester:human:", "requester:service:")
	approvers := matchingRefs(refs, "approver:")
	for _, requester := range requesters {
		requesterID := strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(requester), "requester:human:"), "requester:service:")
		for _, approver := range approvers {
			if requesterID != "" && requesterID == strings.TrimPrefix(strings.ToLower(approver), "approver:") {
				return true
			}
		}
	}
	return false
}

func proposedCompensationRequirement(composition ComposedActionPath) *ProposedActionCompensation {
	required := proposedCompensationRequired(composition)
	state := proposedContractEvidenceState(composition.EvidenceState)
	refs := proposedContractEvidenceRefs(composition)
	procedure := firstPrefixedRef(refs, "compensation:")
	verification := firstPrefixedRef(refs, "compensation_verification:")
	reasons := []string{"compensation:" + map[bool]string{true: "required", false: "not_required"}[required]}
	if required && (procedure == "" || verification == "") {
		state = EvidenceStateUnknown
		reasons = append(reasons, "compensation:evidence_missing")
	}
	if !required {
		state = EvidenceStateVerified
	}
	kind := firstNonEmptyString(map[bool]string{true: "documented_recovery", false: "not_required"}[required])
	if explicitKind := firstMatchingRef(refs, "compensation_kind:"); explicitKind != "" {
		kind = strings.TrimPrefix(strings.ToLower(explicitKind), "compensation_kind:")
		if kind != "documented_recovery" && kind != "rollback" && kind != "restore" {
			state = EvidenceStateContradictory
			reasons = append(reasons, "compensation:unsupported_kind")
		}
	}
	if containsPrefixedRef(refs, "irreversible:true") {
		kind = "irreversible_escalation"
		state = EvidenceStateContradictory
		reasons = append(reasons, "compensation:irreversible_action")
	}
	if containsPrefixedRef(refs, "compensation:unavailable", "compensation:contradictory", "compensation_verification:unavailable", "compensation_verification:failed", "compensation_verification:contradictory") {
		state = EvidenceStateContradictory
		reasons = append(reasons, "compensation:unavailable")
	}
	return &ProposedActionCompensation{
		Required:             required,
		Kind:                 kind,
		ProcedureRef:         procedure,
		Target:               strings.TrimSpace(composition.TargetIdentity),
		ExecutionWindow:      "PT24H",
		VerificationRequired: required,
		AcceptableProducers:  []string{"gait_policy", "control_declaration"},
		EvidenceState:        state,
		FreshnessState:       proposedContractFreshnessState(composition.FreshnessState),
		EvidenceRefs:         dedupeSortedStrings(append(matchingRefs(refs, "compensation:"), verification)),
		ReasonCodes:          dedupeSortedStrings(reasons),
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
	return firstMatchingRef(values, prefix)
}

func firstMatchingRef(values []string, prefixes ...string) string {
	matches := matchingRefs(values, prefixes...)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func matchingRefs(values []string, prefixes ...string) []string {
	out := []string{}
	for _, value := range dedupeSortedStrings(values) {
		trimmed := strings.TrimSpace(value)
		lower := strings.ToLower(trimmed)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lower, strings.ToLower(strings.TrimSpace(prefix))) {
				out = append(out, trimmed)
				break
			}
		}
	}
	return dedupeSortedStrings(out)
}

func containsPrefixedRef(values []string, prefixes ...string) bool {
	return len(matchingRefs(values, prefixes...)) > 0
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
