package risk

import (
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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
	tampered := CloneProposedActionContract(first)
	tampered.ExpectedOutcomeClass = "other"
	if err := ValidateProposedActionContractRevision(tampered, nil); err == nil {
		t.Fatal("expected immutable content mutation under the original identity to fail")
	}
	if _, err := BuildProposedActionContractRevision(composition, first, nil); err == nil {
		t.Fatal("expected an unchanged successor revision to fail")
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

func TestProposedActionContractLifecycleConflictingDownstreamStatesRemainContradictory(t *testing.T) {
	observations := NormalizeProposedActionLifecycleObservations([]ProposedActionLifecycleObservation{
		{Kind: LifecycleObservationActivationReceipt, Producer: "gait", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"gait:receipt"}},
		{Kind: LifecycleObservationRejection, Producer: "gait", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"gait:rejection"}},
		{Kind: LifecycleObservationAxymVerification, Producer: "axym", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"axym:bundle"}},
	})
	if len(observations) != 3 {
		t.Fatalf("expected all authoritative observations to remain visible, got %+v", observations)
	}
	for _, observation := range observations {
		if observation.Kind == LifecycleObservationAxymVerification {
			continue
		}
		if observation.EvidenceState != EvidenceStateContradictory || !containsActionContractString(observation.ReasonCodes, "lifecycle:contradictory_downstream_state") {
			t.Fatalf("activation/rejection conflict must remain contradictory: %+v", observation)
		}
	}
}

func containsActionContractString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
		"task:deploy-billing", "requester:human:alice", "owner:business:finance", "owner:system:billing", "agent_role:deployer", "delegation_root:platform", "credential_subject:deploy-bot", "sod:requester-not-approver",
		"validation_contract:deployment:verified", "effect_contract:deploy:verified", "check:tests:passed", "producer:gait_policy", "sandbox:isolated", "confirmation:confirmed", "approval_receipt:change-42", "approver:bob", "compensation:rollback", "compensation_verification:runbook:verified", "forbidden_effect:none",
	}
	readyInput.SourceDecisionRefs = []string{"policy:deploy", "sha256:policy-digest"}
	draft := BuildProposedActionContract(readyInput)
	readyInput.EvidenceRefs = append(readyInput.EvidenceRefs, "approval_scope_digest:"+strings.TrimPrefix(draft.ApprovalRequirement.ScopeDigest, "sha256:"))
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

func TestAuthorityRequirementsFailClosedAcrossBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ComposedActionPath)
	}{
		{"absent owner", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "owner:business:") }},
		{"conflicting owners", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "owner:business:other") }},
		{"shared credential", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "credential:shared") }},
		{"excessive child authority", func(c *ComposedActionPath) {
			c.EvidenceRefs = append(c.EvidenceRefs, "delegation:excessive_child_authority")
		}},
		{"separation of duties conflict", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "sod:conflict") }},
		{"unknown evidence", func(c *ComposedActionPath) { c.EvidenceState = EvidenceStateUnknown }},
		{"inferred evidence", func(c *ComposedActionPath) { c.EvidenceState = EvidenceStateInferred }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			composition := fullySatisfiedActionContractComposition()
			tc.mutate(&composition)
			contract := buildActionContractWithScope(composition)
			if contract.ReadinessState == ActionContractReadinessReadyForReportOnly {
				t.Fatalf("%s must fail closed: %+v", tc.name, contract)
			}
		})
	}

	for _, requester := range []string{"requester:human:alice", "requester:service:deploy-bot"} {
		t.Run(requester, func(t *testing.T) {
			composition := fullySatisfiedActionContractComposition()
			composition.EvidenceRefs = withoutRefPrefix(composition.EvidenceRefs, "requester:")
			composition.EvidenceRefs = append(composition.EvidenceRefs, requester)
			if contract := buildActionContractWithScope(composition); contract.ReadinessState != ActionContractReadinessReadyForReportOnly {
				t.Fatalf("explicit requester identity should remain report-only ready: %+v", contract)
			}
		})
	}
}

func TestAuthorityRequirementsProjectStructuredPathEvidenceWithoutGrantingIt(t *testing.T) {
	refs := compositionEvidenceRefs([]ActionPath{{
		Purpose: "release approved build", OperationalOwner: "release-platform", PolicyRefs: []string{"gait/release"}, StandingPrivilege: true,
		CredentialProvenance: &agginventory.CredentialProvenance{Subject: "release-bot"},
		AuthorityBindings:    []*agginventory.AuthorityBinding{{Kind: agginventory.AuthorityBindingWorkloadIdentity, Subject: "release-bot"}},
	}})
	for _, want := range []string{"intent:release approved build", "owner:system:release-platform", "policy:gait/release", "provenance_subject:release-bot", "binding_subject:release-bot", "authority_standing:true"} {
		if !containsActionContractString(refs, want) {
			t.Fatalf("structured authority projection missing %q: %v", want, refs)
		}
	}
	composition := fullySatisfiedActionContractComposition()
	composition.EvidenceState = EvidenceStateDeclared
	composition.EvidenceRefs = append(composition.EvidenceRefs, refs...)
	contract := buildActionContractWithScope(composition)
	if contract.ReadinessState == ActionContractReadinessReadyForReportOnly {
		t.Fatalf("declared structured evidence must remain an observation, not a grant: %+v", contract)
	}
}

func TestPreconditionsFailClosedAndPreserveRequiredObservedSeparation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ComposedActionPath)
	}{
		{"missing check", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "check:") }},
		{"stale check", func(c *ComposedActionPath) { replaceRefPrefix(&c.EvidenceRefs, "check:", "check:tests:stale") }},
		{"failed check", func(c *ComposedActionPath) { replaceRefPrefix(&c.EvidenceRefs, "check:", "check:tests:failed") }},
		{"unknown producer", func(c *ComposedActionPath) { replaceRefPrefix(&c.EvidenceRefs, "producer:", "producer:unknown") }},
		{"absent validation contract", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "validation_contract:") }},
		{"absent effect contract", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "effect_contract:") }},
		{"unsupported environment", func(c *ComposedActionPath) { c.Environment = "moon" }},
		{"target mismatch", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "target_observed:prod:other") }},
		{"missing sandbox", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "sandbox:") }},
		{"standing credential", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "credential:standing") }},
		{"contradictory evidence", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "sandbox:unsupported") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			composition := fullySatisfiedActionContractComposition()
			tc.mutate(&composition)
			contract := buildActionContractWithScope(composition)
			if contract.ReadinessState == ActionContractReadinessReadyForReportOnly {
				t.Fatalf("%s must fail closed: %+v", tc.name, contract)
			}
			for _, precondition := range contract.Preconditions {
				if precondition.RequiredConstraint == "" {
					t.Fatalf("required constraint must remain explicit: %+v", precondition)
				}
			}
		})
	}
	if contract := buildActionContractWithScope(fullySatisfiedActionContractComposition()); contract.ReadinessState != ActionContractReadinessReadyForReportOnly {
		t.Fatalf("fully satisfied typed preconditions should be ready for report only: %+v", contract)
	}
}

func TestConfirmationApprovalRequirementAndCompensationFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ComposedActionPath)
	}{
		{"absent confirmation", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "confirmation:") }},
		{"insufficient approvers", func(c *ComposedActionPath) { c.RiskTier = RiskTierHigh }},
		{"requester as approver", func(c *ComposedActionPath) { replaceRefPrefix(&c.EvidenceRefs, "approver:", "approver:alice") }},
		{"expired approval", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "approval:freshness:expired") }},
		{"reapproval trigger", func(c *ComposedActionPath) { c.EvidenceRefs = append(c.EvidenceRefs, "approval:scope_changed") }},
		{"missing compensation", func(c *ComposedActionPath) { c.EvidenceRefs = withoutRefPrefix(c.EvidenceRefs, "compensation:") }},
		{"unsupported compensation kind", func(c *ComposedActionPath) {
			c.EvidenceRefs = append(c.EvidenceRefs, "compensation_kind:custom_script")
		}},
		{"unverifiable recovery", func(c *ComposedActionPath) {
			replaceRefPrefix(&c.EvidenceRefs, "compensation_verification:", "compensation_verification:unavailable")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			composition := fullySatisfiedActionContractComposition()
			tc.mutate(&composition)
			contract := buildActionContractWithScope(composition)
			if contract.ReadinessState == ActionContractReadinessReadyForReportOnly {
				t.Fatalf("%s must fail closed: %+v", tc.name, contract)
			}
		})
	}

	t.Run("scope digest mismatch", func(t *testing.T) {
		composition := fullySatisfiedActionContractComposition()
		composition.EvidenceRefs = append(composition.EvidenceRefs, "approval_scope_digest:deadbeef")
		contract := BuildProposedActionContract(composition)
		if contract.ApprovalRequirement.EvidenceState != EvidenceStateContradictory || contract.ReadinessState != ActionContractReadinessBlockedContradict {
			t.Fatalf("scope mismatch must block readiness: %+v", contract)
		}
	})

	if contract := buildActionContractWithScope(fullySatisfiedActionContractComposition()); contract.ReadinessState != ActionContractReadinessReadyForReportOnly {
		t.Fatalf("satisfied structured activation requirements should be ready for report only: %+v", contract)
	}
}

func TestScopeDigestTracksImmutableScopeNotObservationsOrOrdering(t *testing.T) {
	composition := fullySatisfiedActionContractComposition()
	left := BuildProposedActionContract(composition)
	for i, j := 0, len(composition.EvidenceRefs)-1; i < j; i, j = i+1, j-1 {
		composition.EvidenceRefs[i], composition.EvidenceRefs[j] = composition.EvidenceRefs[j], composition.EvidenceRefs[i]
	}
	right := BuildProposedActionContract(composition)
	if left.ApprovalRequirement.ScopeDigest != right.ApprovalRequirement.ScopeDigest {
		t.Fatalf("input order changed scope digest: %s != %s", left.ApprovalRequirement.ScopeDigest, right.ApprovalRequirement.ScopeDigest)
	}
	right.LifecycleObservations = NormalizeProposedActionLifecycleObservations([]ProposedActionLifecycleObservation{{Kind: LifecycleObservationActivationReceipt, Producer: "gait", ObservedAt: "2030-01-01T00:00:00Z", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}})
	RefreshProposedActionContractIdentity(right)
	if left.ApprovalRequirement.ScopeDigest != right.ApprovalRequirement.ScopeDigest {
		t.Fatal("lifecycle observation changed immutable approval scope")
	}
	composition.TargetIdentity = "prod:other"
	changed := BuildProposedActionContract(composition)
	if left.ApprovalRequirement.ScopeDigest == changed.ApprovalRequirement.ScopeDigest {
		t.Fatal("material target scope change must alter approval digest")
	}
}

func fullySatisfiedActionContractComposition() ComposedActionPath {
	return ComposedActionPath{
		CompositionID: "cap-v3-complete", PatternID: "code_to_deploy", OutcomeClass: "production_deploy", TargetIdentity: "prod:billing", TargetClass: TargetClassProductionImpacting,
		Environment: "production", EvidenceState: EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, PolicyCoverageStatus: PolicyCoverageStatusRuntimeProven, RecommendedControl: RecommendedControlApprovalRequired,
		EvidenceRefs: []string{
			"task:deploy-billing", "requester:human:alice", "owner:business:finance", "owner:system:billing", "agent_role:deployer", "delegation_root:platform", "credential_subject:deploy-bot", "sod:requester-not-approver",
			"validation_contract:deployment:verified", "effect_contract:deploy:verified", "check:tests:passed", "producer:gait_policy", "sandbox:isolated", "confirmation:confirmed", "approval_receipt:change-42", "approver:bob", "compensation:rollback", "compensation_verification:runbook:verified", "forbidden_effect:none",
		},
		SourceDecisionRefs: []string{"policy:deploy", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Stages:             []CompositionStage{{StageID: "source", Role: CompositionStageRoleSource, ParentAuthorityRef: "delegation_root:platform"}, {StageID: "sink", Role: CompositionStageRolePrivilegedSink}},
		Transitions:        []CompositionTransition{{TransitionID: "transition", FromStageID: "source", ToStageID: "sink"}},
	}
}

func buildActionContractWithScope(composition ComposedActionPath) *ProposedActionContract {
	composition.EvidenceRefs = withoutRefPrefix(composition.EvidenceRefs, "approval_scope_digest:")
	draft := BuildProposedActionContract(composition)
	composition.EvidenceRefs = append(composition.EvidenceRefs, "approval_scope_digest:"+strings.TrimPrefix(draft.ApprovalRequirement.ScopeDigest, "sha256:"))
	return BuildProposedActionContract(composition)
}

func withoutRefPrefix(values []string, prefix string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !strings.HasPrefix(value, prefix) {
			out = append(out, value)
		}
	}
	return out
}

func replaceRefPrefix(values *[]string, prefix string, replacement string) {
	*values = withoutRefPrefix(*values, prefix)
	*values = append(*values, replacement)
}
