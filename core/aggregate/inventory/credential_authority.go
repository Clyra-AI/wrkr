package inventory

import (
	"sort"
	"strings"
)

const (
	EvidenceStageObservation        = "observation"
	EvidenceStageReference          = "reference"
	EvidenceStageBinding            = "binding"
	EvidenceStageEffectiveAuthority = "effective_authority"
	EvidenceStageControl            = "control"
	EvidenceStageProof              = "proof"

	AuthorityEvidenceVerified      = "verified"
	AuthorityEvidenceDeclared      = "declared"
	AuthorityEvidenceInferred      = "inferred"
	AuthorityEvidenceUnknown       = "unknown"
	AuthorityEvidenceContradictory = "contradictory"

	CredentialLifetimeStanding  = "standing"
	CredentialLifetimeJIT       = "jit"
	CredentialLifetimeWorkload  = "workload"
	CredentialLifetimeDelegated = "delegated"
	CredentialLifetimeUnknown   = "unknown"

	CredentialRotationEvidencePresent       = "present"
	CredentialRotationEvidenceMissing       = "missing"
	CredentialRotationEvidenceNotApplicable = "not_applicable"
	CredentialRotationEvidenceUnknown       = "unknown"
	CredentialRotationEvidenceStale         = "stale"

	CredentialSourceWorkflowSecretRef = "workflow_secret_ref"
	CredentialSourceWorkflowBuiltin   = "workflow_builtin_token"
	CredentialSourceNonHumanIdentity  = "non_human_identity"
	CredentialSourceAuthSurface       = "auth_surface"
	CredentialSourceDetectorEvidence  = "detector_evidence" // #nosec G101 -- enum label for evidence provenance, not a credential
	CredentialSourceDirectConfig      = "direct_config"     // #nosec G101 -- enum label for config provenance, not a credential
	CredentialSourceUnknown           = "unknown"
)

type CredentialAuthority struct {
	EvidenceStage                  string   `json:"evidence_stage,omitempty" yaml:"evidence_stage,omitempty"`
	ExistenceEvidenceState         string   `json:"existence_evidence_state,omitempty" yaml:"existence_evidence_state,omitempty"`
	BindingEvidenceState           string   `json:"binding_evidence_state,omitempty" yaml:"binding_evidence_state,omitempty"`
	LifetimeEvidenceState          string   `json:"lifetime_evidence_state,omitempty" yaml:"lifetime_evidence_state,omitempty"`
	LifetimeKind                   string   `json:"lifetime_kind,omitempty" yaml:"lifetime_kind,omitempty"`
	CredentialPresent              bool     `json:"credential_present" yaml:"credential_present"`
	CredentialReferencedByWorkflow bool     `json:"credential_referenced_by_workflow" yaml:"credential_referenced_by_workflow"`
	CredentialUsableByPath         bool     `json:"credential_usable_by_path" yaml:"credential_usable_by_path"`
	CredentialKind                 string   `json:"credential_kind,omitempty" yaml:"credential_kind,omitempty"`
	AccessType                     string   `json:"access_type,omitempty" yaml:"access_type,omitempty"`
	StandingAccess                 bool     `json:"standing_access" yaml:"standing_access"`
	LikelyJIT                      bool     `json:"likely_jit" yaml:"likely_jit"`
	TargetSystem                   string   `json:"target_system,omitempty" yaml:"target_system,omitempty"`
	LikelyScope                    string   `json:"likely_scope,omitempty" yaml:"likely_scope,omitempty"`
	ScopeConfidence                string   `json:"scope_confidence,omitempty" yaml:"scope_confidence,omitempty"`
	RotationEvidenceStatus         string   `json:"rotation_evidence_status,omitempty" yaml:"rotation_evidence_status,omitempty"`
	CredentialSource               string   `json:"credential_source,omitempty" yaml:"credential_source,omitempty"`
	Confidence                     string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	ReasonCodes                    []string `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

func CloneCredentialAuthority(in *CredentialAuthority) *CredentialAuthority {
	if in == nil {
		return nil
	}
	out := *in
	out.EvidenceStage = strings.TrimSpace(out.EvidenceStage)
	out.ExistenceEvidenceState = strings.TrimSpace(out.ExistenceEvidenceState)
	out.BindingEvidenceState = strings.TrimSpace(out.BindingEvidenceState)
	out.LifetimeEvidenceState = strings.TrimSpace(out.LifetimeEvidenceState)
	out.LifetimeKind = strings.TrimSpace(out.LifetimeKind)
	out.CredentialKind = strings.TrimSpace(out.CredentialKind)
	out.AccessType = strings.TrimSpace(out.AccessType)
	out.TargetSystem = strings.TrimSpace(out.TargetSystem)
	out.LikelyScope = strings.TrimSpace(out.LikelyScope)
	out.ScopeConfidence = strings.TrimSpace(out.ScopeConfidence)
	out.RotationEvidenceStatus = strings.TrimSpace(out.RotationEvidenceStatus)
	out.CredentialSource = strings.TrimSpace(out.CredentialSource)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	return &out
}

func CloneCredentialAuthorities(in []*CredentialAuthority) []*CredentialAuthority {
	if len(in) == 0 {
		return nil
	}
	out := make([]*CredentialAuthority, 0, len(in))
	for _, item := range in {
		if cloned := CloneCredentialAuthority(item); cloned != nil {
			out = append(out, cloned)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func NormalizeCredentialAuthority(in *CredentialAuthority) *CredentialAuthority {
	if in == nil {
		return nil
	}
	out := CloneCredentialAuthority(in)
	typed := hasTypedAuthorityEvidence(out)
	out.ExistenceEvidenceState = normalizeAuthorityEvidenceState(out.ExistenceEvidenceState)
	out.BindingEvidenceState = normalizeAuthorityEvidenceState(out.BindingEvidenceState)
	out.LifetimeEvidenceState = normalizeAuthorityEvidenceState(out.LifetimeEvidenceState)
	out.LifetimeKind = normalizeCredentialLifetime(out.LifetimeKind, out.AccessType)
	out.EvidenceStage = normalizeEvidenceStage(out.EvidenceStage)
	out.CredentialKind = normalizeCredentialKind(out.CredentialKind, "")
	out.AccessType = normalizeCredentialAccessType(out.AccessType, out.CredentialKind, "")
	out.CredentialPresent = typed && authorityStateSupportsClaim(out.ExistenceEvidenceState)
	out.CredentialUsableByPath = out.CredentialPresent && authorityStateSupportsClaim(out.BindingEvidenceState)
	out.StandingAccess = out.CredentialUsableByPath && out.LifetimeKind == CredentialLifetimeStanding && authorityStateSupportsClaim(out.LifetimeEvidenceState)
	out.LikelyJIT = out.CredentialUsableByPath && (out.LifetimeKind == CredentialLifetimeJIT || out.LifetimeKind == CredentialLifetimeWorkload)
	out.ScopeConfidence = normalizeCredentialConfidence(out.ScopeConfidence)
	if out.ScopeConfidence == "" {
		out.ScopeConfidence = normalizeCredentialConfidence(out.Confidence)
	}
	out.RotationEvidenceStatus = normalizeRotationEvidenceStatus(out.RotationEvidenceStatus, out.AccessType, out.CredentialKind)
	out.CredentialSource = normalizeCredentialSource(out.CredentialSource)
	out.Confidence = normalizeCredentialConfidence(out.Confidence)
	out.ReasonCodes = mergeCredentialEvidenceBasis(out.ReasonCodes)
	if !typed {
		out.ReasonCodes = mergeCredentialEvidenceBasis(append(out.ReasonCodes, "legacy_untyped_authority"))
	}
	if out.StandingAccess {
		out.EvidenceStage = EvidenceStageEffectiveAuthority
	} else if out.CredentialUsableByPath {
		out.EvidenceStage = EvidenceStageBinding
	} else if out.CredentialReferencedByWorkflow {
		out.EvidenceStage = EvidenceStageReference
	}
	return out
}

func NormalizeCredentialAuthorities(in []*CredentialAuthority) []*CredentialAuthority {
	if len(in) == 0 {
		return nil
	}
	out := make([]*CredentialAuthority, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		normalized := NormalizeCredentialAuthority(item)
		if normalized == nil {
			continue
		}
		key := strings.Join([]string{
			normalized.EvidenceStage,
			normalized.ExistenceEvidenceState,
			normalized.BindingEvidenceState,
			normalized.LifetimeEvidenceState,
			normalized.LifetimeKind,
			strconvBool(normalized.CredentialPresent),
			strconvBool(normalized.CredentialReferencedByWorkflow),
			strconvBool(normalized.CredentialUsableByPath),
			normalized.CredentialKind,
			normalized.AccessType,
			normalized.RotationEvidenceStatus,
			normalized.CredentialSource,
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.Join([]string{out[i].CredentialKind, out[i].AccessType, out[i].CredentialSource, out[i].RotationEvidenceStatus}, "|")
		right := strings.Join([]string{out[j].CredentialKind, out[j].AccessType, out[j].CredentialSource, out[j].RotationEvidenceStatus}, "|")
		return left < right
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func StandingPrivilegeFromAuthority(in *CredentialAuthority) (bool, []string) {
	normalized := NormalizeCredentialAuthority(in)
	if normalized == nil {
		return false, nil
	}
	reasons := []string{}
	standing, promotionReasons := EffectiveStandingAuthorityReasons(normalized)
	if standing {
		reasons = append(reasons, "standing_access:true")
	}
	if normalized.CredentialKind != "" && normalized.CredentialKind != CredentialKindUnknown {
		reasons = append(reasons, "credential_kind:"+normalized.CredentialKind)
	}
	if normalized.AccessType != "" && normalized.AccessType != CredentialAccessTypeUnknown {
		reasons = append(reasons, "access_type:"+normalized.AccessType)
	}
	reasons = append(reasons, normalized.ReasonCodes...)
	if !standing {
		reasons = append(reasons, "effective_authority:unproven")
		reasons = append(reasons, promotionReasons...)
	}
	return standing, mergeCredentialEvidenceBasis(reasons)
}

// EffectiveStandingAuthority is the only predicate permitted to promote a
// credential into a confirmed standing-authority claim.
func EffectiveStandingAuthority(in *CredentialAuthority) bool {
	standing, _ := EffectiveStandingAuthorityReasons(in)
	return standing
}

// MergeCredentialLifetime keeps the lifetime value and the evidence that
// supports it atomic. Conflicting known lifetimes fail closed instead of
// allowing the stronger evidence state to validate an unrelated value.
func MergeCredentialLifetime(current, incoming *CredentialAuthority) (kind, evidenceState string, contradictory bool) {
	current = NormalizeCredentialAuthority(current)
	incoming = NormalizeCredentialAuthority(incoming)
	if current == nil {
		if incoming == nil {
			return CredentialLifetimeUnknown, AuthorityEvidenceUnknown, false
		}
		return incoming.LifetimeKind, incoming.LifetimeEvidenceState, incoming.LifetimeEvidenceState == AuthorityEvidenceContradictory
	}
	if incoming == nil {
		return current.LifetimeKind, current.LifetimeEvidenceState, current.LifetimeEvidenceState == AuthorityEvidenceContradictory
	}
	if current.LifetimeEvidenceState == AuthorityEvidenceContradictory || incoming.LifetimeEvidenceState == AuthorityEvidenceContradictory {
		return CredentialLifetimeUnknown, AuthorityEvidenceContradictory, true
	}

	currentKnown := current.LifetimeKind != CredentialLifetimeUnknown
	incomingKnown := incoming.LifetimeKind != CredentialLifetimeUnknown
	switch {
	case currentKnown && incomingKnown && current.LifetimeKind != incoming.LifetimeKind:
		return CredentialLifetimeUnknown, AuthorityEvidenceContradictory, true
	case currentKnown && incomingKnown:
		return current.LifetimeKind, strongerAuthorityEvidenceState(current.LifetimeEvidenceState, incoming.LifetimeEvidenceState), false
	case currentKnown:
		return current.LifetimeKind, current.LifetimeEvidenceState, false
	case incomingKnown:
		return incoming.LifetimeKind, incoming.LifetimeEvidenceState, false
	default:
		return CredentialLifetimeUnknown, strongerAuthorityEvidenceState(current.LifetimeEvidenceState, incoming.LifetimeEvidenceState), false
	}
}

// EffectiveStandingAuthorityReasons returns stable fail-closed reason codes for
// every missing or contradictory stage in standing-authority promotion.
func EffectiveStandingAuthorityReasons(in *CredentialAuthority) (bool, []string) {
	normalized := NormalizeCredentialAuthority(in)
	if normalized == nil {
		return false, []string{"credential_authority:missing"}
	}
	reasons := []string{}
	if !authorityStateSupportsClaim(normalized.ExistenceEvidenceState) {
		reasons = append(reasons, "credential_existence:"+normalized.ExistenceEvidenceState)
	}
	if !authorityStateSupportsClaim(normalized.BindingEvidenceState) {
		reasons = append(reasons, "credential_binding:"+normalized.BindingEvidenceState)
	}
	if normalized.LifetimeKind != CredentialLifetimeStanding {
		reasons = append(reasons, "credential_lifetime_kind:"+normalized.LifetimeKind)
	}
	if !authorityStateSupportsClaim(normalized.LifetimeEvidenceState) {
		reasons = append(reasons, "credential_lifetime_evidence:"+normalized.LifetimeEvidenceState)
	}
	return len(reasons) == 0, mergeCredentialEvidenceBasis(reasons)
}

func hasTypedAuthorityEvidence(in *CredentialAuthority) bool {
	return strings.TrimSpace(in.EvidenceStage) != "" ||
		strings.TrimSpace(in.ExistenceEvidenceState) != "" ||
		strings.TrimSpace(in.BindingEvidenceState) != "" ||
		strings.TrimSpace(in.LifetimeEvidenceState) != "" ||
		strings.TrimSpace(in.LifetimeKind) != ""
}

func authorityStateSupportsClaim(value string) bool {
	switch normalizeAuthorityEvidenceState(value) {
	case AuthorityEvidenceVerified, AuthorityEvidenceDeclared:
		return true
	default:
		return false
	}
}

func normalizeAuthorityEvidenceState(value string) string {
	switch strings.TrimSpace(value) {
	case AuthorityEvidenceVerified,
		AuthorityEvidenceDeclared,
		AuthorityEvidenceInferred,
		AuthorityEvidenceUnknown,
		AuthorityEvidenceContradictory:
		return strings.TrimSpace(value)
	default:
		return AuthorityEvidenceUnknown
	}
}

func strongerAuthorityEvidenceState(current, incoming string) string {
	rank := map[string]int{
		AuthorityEvidenceUnknown:       1,
		AuthorityEvidenceInferred:      2,
		AuthorityEvidenceDeclared:      3,
		AuthorityEvidenceVerified:      4,
		AuthorityEvidenceContradictory: 5,
	}
	current = normalizeAuthorityEvidenceState(current)
	incoming = normalizeAuthorityEvidenceState(incoming)
	if rank[incoming] > rank[current] {
		return incoming
	}
	return current
}

func normalizeCredentialLifetime(value, accessType string) string {
	switch strings.TrimSpace(value) {
	case CredentialLifetimeStanding,
		CredentialLifetimeJIT,
		CredentialLifetimeWorkload,
		CredentialLifetimeDelegated,
		CredentialLifetimeUnknown:
		return strings.TrimSpace(value)
	}
	switch strings.TrimSpace(accessType) {
	case CredentialAccessTypeStanding, CredentialAccessTypeInherited:
		return CredentialLifetimeStanding
	case CredentialAccessTypeJIT:
		return CredentialLifetimeJIT
	case CredentialAccessTypeWorkload:
		return CredentialLifetimeWorkload
	case CredentialAccessTypeDelegated:
		return CredentialLifetimeDelegated
	default:
		return CredentialLifetimeUnknown
	}
}

func normalizeEvidenceStage(value string) string {
	switch strings.TrimSpace(value) {
	case EvidenceStageObservation,
		EvidenceStageReference,
		EvidenceStageBinding,
		EvidenceStageEffectiveAuthority,
		EvidenceStageControl,
		EvidenceStageProof:
		return strings.TrimSpace(value)
	default:
		return EvidenceStageObservation
	}
}

func normalizeRotationEvidenceStatus(value string, accessType string, credentialKind string) string {
	switch strings.TrimSpace(value) {
	case CredentialRotationEvidencePresent,
		CredentialRotationEvidenceMissing,
		CredentialRotationEvidenceNotApplicable,
		CredentialRotationEvidenceUnknown,
		CredentialRotationEvidenceStale:
		return strings.TrimSpace(value)
	}

	switch normalizeCredentialAccessType(accessType, credentialKind, "") {
	case CredentialAccessTypeJIT, CredentialAccessTypeWorkload, CredentialAccessTypeDelegated:
		return CredentialRotationEvidenceNotApplicable
	case CredentialAccessTypeStanding, CredentialAccessTypeInherited:
		if normalizeCredentialKind(credentialKind, "") == CredentialKindUnknown || normalizeCredentialKind(credentialKind, "") == CredentialKindUnknownDurable {
			return CredentialRotationEvidenceUnknown
		}
		return CredentialRotationEvidenceMissing
	default:
		return CredentialRotationEvidenceUnknown
	}
}

func normalizeCredentialSource(value string) string {
	switch strings.TrimSpace(value) {
	case CredentialSourceWorkflowSecretRef,
		CredentialSourceWorkflowBuiltin,
		CredentialSourceNonHumanIdentity,
		CredentialSourceAuthSurface,
		CredentialSourceDetectorEvidence,
		CredentialSourceDirectConfig:
		return strings.TrimSpace(value)
	default:
		return CredentialSourceUnknown
	}
}

func strconvBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
