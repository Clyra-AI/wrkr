package ingest

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func normalizeActionContractLifecycleRecord(record *Record) error {
	if record == nil {
		return nil
	}
	hasLifecyclePayload := record.ActionContractEvent != "" || record.ActionContractArtifactRef != "" || record.Producer != "" || record.EvidenceState != "" || len(record.ReasonCodes) > 0
	if record.ContractRevision < 0 {
		return fmt.Errorf("action contract lifecycle evidence contract_revision must be positive")
	}
	if !hasLifecyclePayload {
		return nil
	}
	if record.ProposedActionContractRef == "" && (record.ContractFamilyID == "" || record.ContractRevision < 1) {
		return fmt.Errorf("action contract lifecycle evidence requires proposed_action_contract_ref or contract_family_id with positive contract_revision")
	}
	if !validImportedLifecycleEvent(record.ActionContractEvent) {
		return fmt.Errorf("unsupported Action Contract lifecycle event %q", record.ActionContractEvent)
	}
	record.Producer = strings.ToLower(record.Producer)
	if (record.Producer != "gait" && record.Producer != "axym") || !producerOwnsLifecycleEvent(record.Producer, record.ActionContractEvent) {
		return fmt.Errorf("producer %q is not authoritative for Action Contract lifecycle event %q", record.Producer, record.ActionContractEvent)
	}
	if record.EvidenceState == "" {
		record.EvidenceState = risk.EvidenceStateDeclared
	}
	if !risk.ValidEvidenceState(record.EvidenceState) {
		return fmt.Errorf("invalid Action Contract lifecycle evidence_state %q", record.EvidenceState)
	}
	return nil
}

func validImportedLifecycleEvent(value string) bool {
	switch value {
	case risk.LifecycleObservationActivationRequest,
		risk.LifecycleObservationActivationReceipt,
		risk.LifecycleObservationRejection,
		risk.LifecycleObservationSupersession,
		risk.LifecycleObservationExecution,
		risk.LifecycleObservationEffect,
		risk.LifecycleObservationAxymVerification:
		return true
	default:
		return false
	}
}

func producerOwnsLifecycleEvent(producer, event string) bool {
	if event == risk.LifecycleObservationAxymVerification {
		return producer == "axym"
	}
	return producer == "gait"
}

// ApplyActionContractLifecycleEvidence returns a detached snapshot projection.
// It records imported Gait/Axym evidence without mutating saved state or the
// immutable proposed Action Contract identity.
func ApplyActionContractLifecycleEvidence(snapshot state.Snapshot, bundle Bundle) state.Snapshot {
	if snapshot.RiskReport == nil || len(snapshot.RiskReport.ComposedActionPaths) == 0 || len(bundle.Records) == 0 {
		return snapshot
	}
	report := *snapshot.RiskReport
	report.ComposedActionPaths = applyLifecycleToCompositions(report.ComposedActionPaths, bundle)
	if report.ComposedActionPathToControlFirst != nil {
		choice := *report.ComposedActionPathToControlFirst
		projected := applyLifecycleToCompositions([]risk.ComposedActionPath{choice.Path}, bundle)
		if len(projected) == 1 {
			choice.Path = projected[0]
		}
		report.ComposedActionPathToControlFirst = &choice
	}
	snapshot.RiskReport = &report
	return snapshot
}

func applyLifecycleToCompositions(compositions []risk.ComposedActionPath, bundle Bundle) []risk.ComposedActionPath {
	out := append([]risk.ComposedActionPath(nil), compositions...)
	for idx := range out {
		contract := risk.CloneProposedActionContract(out[idx].ProposedActionContract)
		if contract == nil {
			continue
		}
		observations := append([]risk.ProposedActionLifecycleObservation(nil), contract.LifecycleObservations...)
		refs := append([]string(nil), out[idx].ProposedActionContractRefs...)
		for _, record := range bundle.Records {
			if !lifecycleRecordMatchesContract(record, contract) {
				continue
			}
			evidenceRefs := append([]string(nil), record.EvidenceRefs...)
			for _, ref := range []string{record.RecordID, record.ActionContractArtifactRef, record.ProposedActionContractRef, record.ContractFamilyID} {
				if strings.TrimSpace(ref) != "" {
					evidenceRefs = append(evidenceRefs, strings.TrimSpace(ref))
				}
			}
			proofRefs := []string{}
			if record.ProofRef != "" {
				proofRefs = append(proofRefs, record.ProofRef)
			}
			observations = append(observations, risk.ProposedActionLifecycleObservation{
				Kind:                       record.ActionContractEvent,
				Producer:                   record.Producer,
				EvidenceState:              record.EvidenceState,
				FreshnessState:             record.FreshnessState,
				ObservedAt:                 record.ObservedAt,
				EvidenceRefs:               evidenceRefs,
				ActionContractArtifactRefs: mergeStrings(record.ActionContractArtifactRef),
				ProofRefs:                  proofRefs,
				ReasonCodes:                append([]string(nil), record.ReasonCodes...),
			})
			refs = append(refs, contract.ContractID, contract.ContractFamilyID, "revision:"+strconv.Itoa(contract.Revision), record.ActionContractArtifactRef, record.RecordID)
		}
		contract.LifecycleObservations = risk.NormalizeProposedActionLifecycleObservations(observations)
		out[idx].ProposedActionContract = contract
		out[idx].ProposedActionContractRefs = mergeStrings(refs...)
	}
	return out
}

func lifecycleRecordMatchesContract(record Record, contract *risk.ProposedActionContract) bool {
	if contract == nil || record.ActionContractEvent == "" {
		return false
	}
	if record.ProposedActionContractRef != "" && record.ProposedActionContractRef != contract.ContractID {
		return false
	}
	if record.ContractFamilyID != "" && record.ContractFamilyID != contract.ContractFamilyID {
		return false
	}
	if record.ContractRevision > 0 && record.ContractRevision != contract.Revision {
		return false
	}
	return record.ProposedActionContractRef != "" || (record.ContractFamilyID != "" && record.ContractRevision > 0)
}
