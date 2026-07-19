package risk

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

func TestProposedActionContractRevisionRequiresExplicitValidatedPredecessor(t *testing.T) {
	composition := ComposedActionPath{
		CompositionID:      "cap-revision",
		ResolutionKey:      "rk-revision",
		OutcomeClass:       "production_deploy",
		TargetIdentity:     "prod:revision",
		TargetClass:        TargetClassProductionImpacting,
		EvidenceState:      EvidenceStateVerified,
		FreshnessState:     evidencepolicy.FreshnessStateFresh,
		RecommendedControl: RecommendedControlApprovalRequired,
		Stages:             []CompositionStage{{StageID: "source", Role: CompositionStageRoleSource}, {StageID: "sink", Role: CompositionStageRolePrivilegedSink}},
	}
	first := BuildProposedActionContract(composition)
	if first == nil || first.Revision != 1 || first.SupersedesRef != "" {
		t.Fatalf("expected standalone revision 1, got %+v", first)
	}
	if err := ValidateProposedActionContractRevision(first, nil); err != nil {
		t.Fatalf("revision 1 should validate without invented history: %v", err)
	}
	if _, err := BuildProposedActionContractRevision(composition, nil, nil); err == nil {
		t.Fatal("expected successor without predecessor to fail")
	}

	changed := composition
	changed.EvidenceRefs = []string{"proof:changed"}
	second, err := BuildProposedActionContractRevision(changed, first, []ProposedActionLifecycleObservation{{
		Kind: LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"gait:activation"},
	}})
	if err != nil {
		t.Fatalf("build revision 2: %v", err)
	}
	if second.Revision != 2 || second.SupersedesRef != first.ContractID || second.ContractID == first.ContractID {
		t.Fatalf("expected immutable successor link and identity, first=%+v second=%+v", first, second)
	}
	if err := ValidateProposedActionContractRevision(second, first); err != nil {
		t.Fatalf("successor should validate: %v", err)
	}
	invalid := CloneProposedActionContract(second)
	invalid.Revision = 4
	if err := ValidateProposedActionContractRevision(invalid, first); err == nil {
		t.Fatal("expected skipped revision to fail")
	}
}

func TestProposedActionContractLifecycleDoesNotMutateImmutableContentIdentity(t *testing.T) {
	contract := BuildProposedActionContract(ComposedActionPath{
		CompositionID: "cap-lifecycle", OutcomeClass: "release_publish", TargetIdentity: "release:lifecycle", TargetClass: TargetClassReleaseAdjacent,
		EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, RecommendedControl: RecommendedControlApprovalRequired,
		Stages: []CompositionStage{{StageID: "source", Role: CompositionStageRoleSource}, {StageID: "sink", Role: CompositionStageRoleDestructiveSink}},
	})
	beforeID, beforeDigest, beforeScope := contract.ContractID, contract.ContractContentDigest, contract.ApprovalRequirement.ScopeDigest
	contract.LifecycleObservations = NormalizeProposedActionLifecycleObservations([]ProposedActionLifecycleObservation{{
		Kind: LifecycleObservationAxymVerification, Producer: "axym", EvidenceState: EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"axym:bundle"}, ProofRefs: []string{"proof:verification"},
	}})
	RefreshProposedActionContractIdentity(contract)
	if contract.ContractID != beforeID || contract.ContractContentDigest != beforeDigest || contract.ApprovalRequirement.ScopeDigest != beforeScope {
		t.Fatalf("lifecycle evidence must not mutate immutable content identity: %+v", contract)
	}
	if len(contract.LifecycleObservations) != 1 || !strings.HasPrefix(contract.LifecycleObservations[0].ObservationID, "pacl-") {
		t.Fatalf("expected normalized lifecycle observation, got %+v", contract.LifecycleObservations)
	}
}

func TestProposedActionContractV3TypedRequirementSpineFailsClosedAndCanBecomeReady(t *testing.T) {
	base := ComposedActionPath{
		CompositionID: "cap-v3-spine", PatternID: "code_to_deploy", OutcomeClass: "production_deploy", TargetIdentity: "prod:billing", TargetClass: TargetClassProductionImpacting,
		Environment: "production", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, PolicyCoverageStatus: PolicyCoverageStatusRuntimeProven, RecommendedControl: RecommendedControlApprovalRequired,
		Stages:      []CompositionStage{{StageID: "source", Role: CompositionStageRoleSource, ParentAuthorityRef: "authority:root"}, {StageID: "sink", Role: CompositionStageRolePrivilegedSink}},
		Transitions: []CompositionTransition{{TransitionID: "transition", FromStageID: "source", ToStageID: "sink"}},
	}
	missing := BuildProposedActionContract(base)
	if missing.ContractVersion != ProposedActionContractVersionV3 || len(missing.AuthorityRequirements) != 9 || len(missing.Preconditions) != 12 {
		t.Fatalf("expected complete typed v3 requirement spine, got %+v", missing)
	}
	if missing.ReadinessState == ActionContractReadinessReadyForReportOnly {
		t.Fatalf("missing typed evidence must fail closed, got %+v", missing)
	}

	readyInput := base
	readyInput.EvidenceRefs = []string{
		"owner:business:finance", "owner:system:billing", "sod:requester-not-approver", "validation:deployment", "effect:deploy", "check:tests", "producer:gait_policy", "sandbox:isolated", "compensation:rollback", "forbidden_effect:none",
	}
	readyInput.SourceDecisionRefs = []string{"policy:deploy", "sha256:policy-digest"}
	ready := BuildProposedActionContract(readyInput)
	if ready.ReadinessState != ActionContractReadinessReadyForReportOnly || ready.AuthorityReadinessState != proposedRequirementReady {
		t.Fatalf("fully typed verified evidence should be ready for report only, got %+v", ready)
	}
	if ready.ApprovalRequirement == nil || ready.CompensationRequirement == nil || ready.ApprovalRequirement.ScopeDigest == "" {
		t.Fatalf("expected structured approval and compensation with scope digest, got %+v", ready)
	}
	for _, requirement := range ready.AuthorityRequirements {
		if requirement.EvidenceState != EvidenceStateVerified || requirement.FreshnessState != evidencepolicy.FreshnessStateFresh {
			t.Fatalf("ready authority requirement must retain typed verified evidence, got %+v", requirement)
		}
	}
}
