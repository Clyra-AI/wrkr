package state

import (
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestSnapshotRoundTripPreservesActionContractRevisionAndLifecycleEvidence(t *testing.T) {
	t.Parallel()
	composition := risk.ComposedActionPath{
		CompositionID: "cap-state-contract", OutcomeClass: "release_publish", TargetIdentity: "release:state", TargetClass: risk.TargetClassReleaseAdjacent,
		EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, RecommendedControl: risk.RecommendedControlApprovalRequired,
		Stages: []risk.CompositionStage{{StageID: "source", Role: risk.CompositionStageRoleSource}, {StageID: "sink", Role: risk.CompositionStageRoleDestructiveSink}},
	}
	contract := risk.BuildProposedActionContract(composition)
	contract.LifecycleObservations = risk.NormalizeProposedActionLifecycleObservations([]risk.ProposedActionLifecycleObservation{{
		Kind: risk.LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"gait:receipt"},
	}})
	composition.ProposedActionContract = contract
	composition.ProposedActionContractRefs = []string{contract.ContractID}
	path := filepath.Join(t.TempDir(), "state.json")
	if err := Save(path, Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	got := loaded.RiskReport.ComposedActionPaths[0].ProposedActionContract
	if got.Revision != 1 || len(got.LifecycleObservations) != 1 || got.LifecycleObservations[0].Producer != "gait" {
		t.Fatalf("expected lifecycle-ready contract state round trip, got %+v", got)
	}
}
