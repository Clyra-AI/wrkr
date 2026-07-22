package ingest

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestActionContractLifecycleImportedEvidenceProjectsWithoutMutatingIdentity(t *testing.T) {
	composition := risk.ComposedActionPath{
		CompositionID: "cap-ingest-lifecycle", OutcomeClass: "production_deploy", TargetIdentity: "prod", EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh,
		Stages: []risk.CompositionStage{{StageID: "source", Role: risk.CompositionStageRoleSource}, {StageID: "sink", Role: risk.CompositionStageRolePrivilegedSink}},
	}
	composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
	beforeID, beforeDigest := composition.ProposedActionContract.ContractID, composition.ProposedActionContract.ContractContentDigest
	generatedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	bundle, err := Normalize(Bundle{GeneratedAt: generatedAt.Format(time.RFC3339), Records: []Record{
		{RecordKind: RecordKindExternalControl, SourceType: "signed_declaration", Source: "gait-export", ObservedAt: generatedAt.Add(-time.Minute).Format(time.RFC3339), EvidenceClass: EvidenceClassApproval, ProposedActionContractRef: beforeID, ContractFamilyID: composition.ProposedActionContract.ContractFamilyID, ContractRevision: 1, ActionContractArtifactRef: "paca-gait-receipt", ActionContractEvent: risk.LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: risk.EvidenceStateVerified, ProofRef: "proof:gait"},
		{RecordKind: RecordKindExternalControl, SourceType: "signed_declaration", Source: "axym-export", ObservedAt: generatedAt.Format(time.RFC3339), EvidenceClass: EvidenceClassProofVerify, ProposedActionContractRef: beforeID, ContractRevision: 1, ActionContractArtifactRef: "axym:bundle:1", ActionContractEvent: risk.LifecycleObservationAxymVerification, Producer: "axym", EvidenceState: risk.EvidenceStateVerified, ProofRef: "proof:axym"},
	}})
	if err != nil {
		t.Fatalf("normalize lifecycle bundle: %v", err)
	}
	projected := ApplyActionContractLifecycleEvidence(state.Snapshot{RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}, bundle)
	got := projected.RiskReport.ComposedActionPaths[0].ProposedActionContract
	if got.ContractID != beforeID || got.ContractContentDigest != beforeDigest {
		t.Fatalf("imported lifecycle evidence mutated immutable identity: %+v", got)
	}
	if len(got.LifecycleObservations) != 2 {
		t.Fatalf("expected Gait and Axym observations, got %+v", got.LifecycleObservations)
	}
	if len(composition.ProposedActionContract.LifecycleObservations) != 0 {
		t.Fatal("projection mutated the caller snapshot")
	}
}

func TestActionContractLifecycleRejectsWrongProducerAndMissingContractCorrelation(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	for _, record := range []Record{
		{Source: "bad", ObservedAt: now, EvidenceClass: EvidenceClassApproval, ActionContractEvent: risk.LifecycleObservationActivationReceipt, Producer: "axym", ProposedActionContractRef: "pac-bad"},
		{Source: "bad", ObservedAt: now, EvidenceClass: EvidenceClassApproval, ActionContractEvent: risk.LifecycleObservationActivationReceipt, Producer: "gait"},
	} {
		if _, err := Normalize(Bundle{GeneratedAt: now, Records: []Record{record}}); err == nil {
			t.Fatalf("expected invalid lifecycle record to fail closed: %+v", record)
		}
	}
}

func TestActionContractLifecycleRecordIDsPreserveLegacyShape(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	bundle, err := Normalize(Bundle{GeneratedAt: now, Records: []Record{
		{Source: "demo-app", ObservedAt: now, EvidenceClass: EvidenceClassApproval, PathID: "demo-app"},
		{Source: "gait-export", ObservedAt: now, EvidenceClass: EvidenceClassApproval, ProposedActionContractRef: "pac-123", ActionContractEvent: risk.LifecycleObservationActivationReceipt, Producer: "gait"},
	}})
	if err != nil {
		t.Fatalf("normalize records: %v", err)
	}
	bySource := map[string]Record{}
	for _, record := range bundle.Records {
		bySource[record.Source] = record
	}
	if got, want := bySource["demo-app"].RecordID, "demo-app:approval:"+now; got != want {
		t.Fatalf("legacy record id changed: got %q want %q", got, want)
	}
	if got, want := bySource["gait-export"].RecordID, "pac-123:approval:"+risk.LifecycleObservationActivationReceipt+":"+now; got != want {
		t.Fatalf("lifecycle record id missing event identity: got %q want %q", got, want)
	}
}
