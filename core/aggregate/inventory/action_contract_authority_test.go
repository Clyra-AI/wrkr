package inventory

import (
	"reflect"
	"testing"
)

func TestAuthorityBindingNormalizationIsDeterministicAndPreservesSubjects(t *testing.T) {
	left := NormalizeAuthorityBindings([]*AuthorityBinding{
		{Kind: AuthorityBindingWorkloadIdentity, Provider: " gait ", Subject: " service:deploy ", TargetSystem: "prod", AccessLevel: AuthorityAccessWrite, EvidenceRefs: []string{"evidence:b", "evidence:a"}},
		{Kind: AuthorityBindingCloudRole, Provider: "aws", Subject: "role:release", TargetSystem: "prod", AccessLevel: "invalid"},
	})
	right := NormalizeAuthorityBindings([]*AuthorityBinding{
		{Kind: AuthorityBindingCloudRole, Provider: "aws", Subject: "role:release", TargetSystem: "prod", AccessLevel: "invalid"},
		{Kind: AuthorityBindingWorkloadIdentity, Provider: " gait ", Subject: " service:deploy ", TargetSystem: "prod", AccessLevel: AuthorityAccessWrite, EvidenceRefs: []string{"evidence:a", "evidence:b"}},
	})
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("authority binding order changed normalized projection: left=%+v right=%+v", left, right)
	}
	if len(left) != 2 || left[1].Subject != "service:deploy" || left[0].AccessLevel != AuthorityAccessUnknown {
		t.Fatalf("expected explicit subjects and fail-closed access normalization, got %+v", left)
	}
}

func TestCredentialAuthorityNormalizationKeepsStandingAndJITDistinct(t *testing.T) {
	standing := NormalizeCredentialAuthority(&CredentialAuthority{EvidenceStage: EvidenceStageEffectiveAuthority, ExistenceEvidenceState: AuthorityEvidenceDeclared, BindingEvidenceState: AuthorityEvidenceDeclared, LifetimeEvidenceState: AuthorityEvidenceDeclared, LifetimeKind: CredentialLifetimeStanding, CredentialKind: "token", AccessType: CredentialAccessTypeStanding, CredentialSource: CredentialSourceDirectConfig})
	jit := NormalizeCredentialAuthority(&CredentialAuthority{EvidenceStage: EvidenceStageEffectiveAuthority, ExistenceEvidenceState: AuthorityEvidenceDeclared, BindingEvidenceState: AuthorityEvidenceDeclared, LifetimeEvidenceState: AuthorityEvidenceDeclared, LifetimeKind: CredentialLifetimeJIT, CredentialKind: "token", AccessType: CredentialAccessTypeJIT, CredentialSource: CredentialSourceNonHumanIdentity})
	if standing == nil || jit == nil || !standing.StandingAccess || jit.StandingAccess || !jit.LikelyJIT {
		t.Fatalf("standing and JIT authority must remain distinct: standing=%+v jit=%+v", standing, jit)
	}
	if ok, reasons := StandingPrivilegeFromAuthority(standing); !ok || len(reasons) == 0 {
		t.Fatalf("standing privilege should remain explicit and explainable: ok=%v reasons=%v", ok, reasons)
	}
}

func TestNormalizeCredentialAuthorityDowngradesLegacyUntypedClaims(t *testing.T) {
	authority := NormalizeCredentialAuthority(&CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		StandingAccess:         true,
		AccessType:             CredentialAccessTypeStanding,
	})
	if authority.CredentialPresent || authority.CredentialUsableByPath || authority.StandingAccess {
		t.Fatalf("legacy untyped authority must not promote confirmed claims: %+v", authority)
	}
	if !containsAuthorityReason(authority.ReasonCodes, "legacy_untyped_authority") {
		t.Fatalf("expected legacy downgrade reason, got %v", authority.ReasonCodes)
	}
}

func TestEffectiveStandingAuthorityRequiresEveryTypedPredicate(t *testing.T) {
	base := &CredentialAuthority{
		ExistenceEvidenceState: AuthorityEvidenceDeclared,
		BindingEvidenceState:   AuthorityEvidenceDeclared,
		LifetimeEvidenceState:  AuthorityEvidenceDeclared,
		LifetimeKind:           CredentialLifetimeStanding,
	}
	if !EffectiveStandingAuthority(base) {
		t.Fatal("expected fully declared standing authority to promote")
	}
	base.BindingEvidenceState = AuthorityEvidenceInferred
	if EffectiveStandingAuthority(base) {
		t.Fatal("inferred binding must not promote standing authority")
	}
}

func TestEffectiveStandingAuthorityTruthTableFailsClosed(t *testing.T) {
	t.Parallel()
	states := []string{AuthorityEvidenceVerified, AuthorityEvidenceDeclared, AuthorityEvidenceInferred, AuthorityEvidenceUnknown, AuthorityEvidenceContradictory}
	for _, existence := range states {
		for _, binding := range states {
			for _, lifetime := range states {
				authority := &CredentialAuthority{
					ExistenceEvidenceState: existence,
					BindingEvidenceState:   binding,
					LifetimeEvidenceState:  lifetime,
					LifetimeKind:           CredentialLifetimeStanding,
				}
				got, reasons := EffectiveStandingAuthorityReasons(authority)
				want := authorityStateSupportsClaim(existence) && authorityStateSupportsClaim(binding) && authorityStateSupportsClaim(lifetime)
				if got != want {
					t.Fatalf("truth table mismatch existence=%s binding=%s lifetime=%s got=%v reasons=%v", existence, binding, lifetime, got, reasons)
				}
				if !want && len(reasons) == 0 {
					t.Fatalf("missing failure reasons existence=%s binding=%s lifetime=%s", existence, binding, lifetime)
				}
			}
		}
	}
	if ok, reasons := EffectiveStandingAuthorityReasons(nil); ok || !containsAuthorityReason(reasons, "credential_authority:missing") {
		t.Fatalf("nil authority must fail closed with stable reason, ok=%v reasons=%v", ok, reasons)
	}
}

func containsAuthorityReason(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
