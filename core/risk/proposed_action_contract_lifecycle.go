package risk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

const (
	LifecycleObservationProposalCreation  = "proposal_creation"
	LifecycleObservationActivationRequest = "gait_activation_request"
	LifecycleObservationActivationReceipt = "gait_activation_receipt"
	LifecycleObservationRejection         = "gait_rejection"
	LifecycleObservationSupersession      = "supersession"
	LifecycleObservationExecution         = "gait_execution"
	LifecycleObservationEffect            = "gait_effect"
	LifecycleObservationAxymVerification  = "axym_verification"
)

// BuildProposedActionContractRevision constructs a successor only when the
// caller provides a validated predecessor. Without predecessor evidence callers
// must use BuildProposedActionContract, which deterministically emits revision 1.
func BuildProposedActionContractRevision(composition ComposedActionPath, predecessor *ProposedActionContract, observations []ProposedActionLifecycleObservation) (*ProposedActionContract, error) {
	if predecessor == nil {
		return nil, fmt.Errorf("proposed Action Contract successor requires an explicit predecessor")
	}
	if predecessor.Revision < 1 || strings.TrimSpace(predecessor.ContractFamilyID) == "" || strings.TrimSpace(predecessor.ContractContentDigest) == "" || strings.TrimSpace(predecessor.ContractID) == "" {
		return nil, fmt.Errorf("predecessor is missing immutable revision identity")
	}
	contract := BuildProposedActionContract(composition)
	if contract == nil {
		return nil, fmt.Errorf("proposed Action Contract successor requires a composition")
	}
	if strings.TrimSpace(contract.ContractFamilyID) != strings.TrimSpace(predecessor.ContractFamilyID) {
		return nil, fmt.Errorf("predecessor family %q does not match successor family %q", predecessor.ContractFamilyID, contract.ContractFamilyID)
	}
	contract.Revision = predecessor.Revision + 1
	contract.SupersedesRef = strings.TrimSpace(predecessor.ContractID)
	contract.LifecycleObservations = NormalizeProposedActionLifecycleObservations(observations)
	RefreshProposedActionContractIdentity(contract)
	if err := ValidateProposedActionContractRevision(contract, predecessor); err != nil {
		return nil, err
	}
	return contract, nil
}

// ValidateProposedActionContractRevision rejects inferred, skipped, forked, or
// mutable revision links. Lifecycle observations are intentionally excluded
// from this immutable content validation.
func ValidateProposedActionContractRevision(contract *ProposedActionContract, predecessor *ProposedActionContract) error {
	if contract == nil {
		return fmt.Errorf("proposed Action Contract is required")
	}
	if strings.TrimSpace(contract.ContractVersion) != ProposedActionContractVersionV3 {
		return fmt.Errorf("revision validation requires contract version 3")
	}
	if contract.Revision < 1 {
		return fmt.Errorf("revision must be positive")
	}
	if strings.TrimSpace(contract.ContractFamilyID) == "" || strings.TrimSpace(contract.ContractContentDigest) == "" || strings.TrimSpace(contract.ContractID) == "" {
		return fmt.Errorf("revision requires contract identity fields")
	}
	if err := validateProposedActionContractIdentity(contract, "contract"); err != nil {
		return err
	}
	if predecessor == nil {
		if contract.Revision != 1 || strings.TrimSpace(contract.SupersedesRef) != "" {
			return fmt.Errorf("revision %d requires an explicit predecessor", contract.Revision)
		}
		return nil
	}
	if predecessor.Revision < 1 || strings.TrimSpace(predecessor.ContractFamilyID) == "" || strings.TrimSpace(predecessor.ContractContentDigest) == "" || strings.TrimSpace(predecessor.ContractID) == "" {
		return fmt.Errorf("invalid predecessor identity")
	}
	if err := validateProposedActionContractIdentity(predecessor, "predecessor"); err != nil {
		return err
	}
	if strings.TrimSpace(contract.ContractFamilyID) != strings.TrimSpace(predecessor.ContractFamilyID) {
		return fmt.Errorf("predecessor family mismatch")
	}
	if contract.Revision != predecessor.Revision+1 {
		return fmt.Errorf("revision must increment exactly by one")
	}
	if strings.TrimSpace(contract.SupersedesRef) != strings.TrimSpace(predecessor.ContractID) {
		return fmt.Errorf("successor supersedes_ref must equal predecessor contract_id")
	}
	if strings.TrimSpace(predecessor.ContractContentDigest) == "" {
		return fmt.Errorf("predecessor content digest is required")
	}
	normalized := CloneProposedActionContract(contract)
	normalized.Revision = predecessor.Revision
	normalized.SupersedesRef = predecessor.SupersedesRef
	RefreshProposedActionContractIdentity(normalized)
	if normalized.ContractContentDigest == predecessor.ContractContentDigest {
		return fmt.Errorf("successor must contain an immutable content change")
	}
	return nil
}

func validateProposedActionContractIdentity(contract *ProposedActionContract, label string) error {
	clone := CloneProposedActionContract(contract)
	RefreshProposedActionContractIdentity(clone)
	if clone.ContractFamilyID != contract.ContractFamilyID || clone.ContractContentDigest != contract.ContractContentDigest || clone.ContractID != contract.ContractID {
		return fmt.Errorf("%s immutable identity does not match its content", label)
	}
	return nil
}

func NormalizeProposedActionLifecycleObservations(in []ProposedActionLifecycleObservation) []ProposedActionLifecycleObservation {
	if len(in) == 0 {
		return nil
	}
	byID := map[string]ProposedActionLifecycleObservation{}
	for _, item := range in {
		item.Kind = strings.TrimSpace(item.Kind)
		item.Producer = strings.TrimSpace(item.Producer)
		item.EvidenceState = proposedContractEvidenceState(item.EvidenceState)
		item.FreshnessState = proposedContractFreshnessState(item.FreshnessState)
		item.ObservedAt = strings.TrimSpace(item.ObservedAt)
		item.EvidenceRefs = dedupeSortedStrings(item.EvidenceRefs)
		item.ProofRefs = dedupeSortedStrings(item.ProofRefs)
		item.ReasonCodes = dedupeSortedStrings(item.ReasonCodes)
		if !validLifecycleObservationKind(item.Kind) || item.Producer == "" {
			item.EvidenceState = EvidenceStateContradictory
			item.ReasonCodes = dedupeSortedStrings(append(item.ReasonCodes, "lifecycle:invalid_observation"))
		}
		item.ObservationID = "pacl-" + stableProposedContractHash(strings.Join([]string{item.Kind, item.Producer, strings.Join(item.EvidenceRefs, ","), strings.Join(item.ProofRefs, ",")}, "|"))
		if existing, ok := byID[item.ObservationID]; ok {
			existing.EvidenceState = mergeLifecycleEvidenceState(existing.EvidenceState, item.EvidenceState)
			existing.FreshnessState = mergeLifecycleFreshnessState(existing.FreshnessState, item.FreshnessState)
			existing.EvidenceRefs = dedupeSortedStrings(append(existing.EvidenceRefs, item.EvidenceRefs...))
			existing.ProofRefs = dedupeSortedStrings(append(existing.ProofRefs, item.ProofRefs...))
			existing.ReasonCodes = dedupeSortedStrings(append(existing.ReasonCodes, item.ReasonCodes...))
			byID[item.ObservationID] = existing
			continue
		}
		byID[item.ObservationID] = item
	}
	out := make([]ProposedActionLifecycleObservation, 0, len(byID))
	for _, item := range byID {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ObservationID < out[j].ObservationID })
	hasActivation, hasRejection := false, false
	for _, item := range out {
		switch item.Kind {
		case LifecycleObservationActivationReceipt:
			hasActivation = true
		case LifecycleObservationRejection:
			hasRejection = true
		}
	}
	if hasActivation && hasRejection {
		for idx := range out {
			if out[idx].Kind != LifecycleObservationActivationReceipt && out[idx].Kind != LifecycleObservationRejection {
				continue
			}
			out[idx].EvidenceState = EvidenceStateContradictory
			out[idx].ReasonCodes = dedupeSortedStrings(append(out[idx].ReasonCodes, "lifecycle:contradictory_downstream_state"))
		}
	}
	return out
}

func validLifecycleObservationKind(value string) bool {
	switch strings.TrimSpace(value) {
	case LifecycleObservationProposalCreation, LifecycleObservationActivationRequest, LifecycleObservationActivationReceipt, LifecycleObservationRejection, LifecycleObservationSupersession, LifecycleObservationExecution, LifecycleObservationEffect, LifecycleObservationAxymVerification:
		return true
	default:
		return false
	}
}

func mergeLifecycleEvidenceState(left string, right string) string {
	if left == EvidenceStateContradictory || right == EvidenceStateContradictory {
		return EvidenceStateContradictory
	}
	if left == EvidenceStateUnknown || right == EvidenceStateUnknown {
		return EvidenceStateUnknown
	}
	if left == EvidenceStateInferred || right == EvidenceStateInferred {
		return EvidenceStateInferred
	}
	if left == EvidenceStateDeclared || right == EvidenceStateDeclared {
		return EvidenceStateDeclared
	}
	return EvidenceStateVerified
}

func mergeLifecycleFreshnessState(left string, right string) string {
	for _, value := range []string{left, right} {
		if value == evidencepolicy.FreshnessStateExpired {
			return evidencepolicy.FreshnessStateExpired
		}
	}
	for _, value := range []string{left, right} {
		if value == evidencepolicy.FreshnessStateStale {
			return evidencepolicy.FreshnessStateStale
		}
	}
	for _, value := range []string{left, right} {
		if value == evidencepolicy.FreshnessStateUnknown {
			return evidencepolicy.FreshnessStateUnknown
		}
	}
	return evidencepolicy.FreshnessStateFresh
}

func cloneProposedActionLifecycleObservations(in []ProposedActionLifecycleObservation) []ProposedActionLifecycleObservation {
	out := append([]ProposedActionLifecycleObservation(nil), in...)
	for idx := range out {
		out[idx].EvidenceRefs = append([]string(nil), in[idx].EvidenceRefs...)
		out[idx].ProofRefs = append([]string(nil), in[idx].ProofRefs...)
		out[idx].ReasonCodes = append([]string(nil), in[idx].ReasonCodes...)
	}
	return out
}
