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
	standing := NormalizeCredentialAuthority(&CredentialAuthority{CredentialPresent: true, CredentialKind: "token", AccessType: CredentialAccessTypeStanding, StandingAccess: true, CredentialSource: CredentialSourceDirectConfig})
	jit := NormalizeCredentialAuthority(&CredentialAuthority{CredentialPresent: true, CredentialKind: "token", AccessType: CredentialAccessTypeJIT, LikelyJIT: true, CredentialSource: CredentialSourceNonHumanIdentity})
	if standing == nil || jit == nil || !standing.StandingAccess || jit.StandingAccess || !jit.LikelyJIT {
		t.Fatalf("standing and JIT authority must remain distinct: standing=%+v jit=%+v", standing, jit)
	}
	if ok, reasons := StandingPrivilegeFromAuthority(standing); !ok || len(reasons) == 0 {
		t.Fatalf("standing privilege should remain explicit and explainable: ok=%v reasons=%v", ok, reasons)
	}
}
