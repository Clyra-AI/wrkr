package inventory

import (
	"sort"
	"strings"
)

const (
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
	out.CredentialKind = normalizeCredentialKind(out.CredentialKind, "")
	out.AccessType = normalizeCredentialAccessType(out.AccessType, out.CredentialKind, "")
	out.StandingAccess = inferStandingAccess(out.StandingAccess, out.AccessType, out.CredentialKind, "")
	out.LikelyJIT = inferLikelyJIT(out.LikelyJIT, out.AccessType, out.CredentialKind, "")
	out.ScopeConfidence = normalizeCredentialConfidence(out.ScopeConfidence)
	if out.ScopeConfidence == "" {
		out.ScopeConfidence = normalizeCredentialConfidence(out.Confidence)
	}
	out.RotationEvidenceStatus = normalizeRotationEvidenceStatus(out.RotationEvidenceStatus, out.AccessType, out.CredentialKind)
	out.CredentialSource = normalizeCredentialSource(out.CredentialSource)
	out.Confidence = normalizeCredentialConfidence(out.Confidence)
	out.ReasonCodes = mergeCredentialEvidenceBasis(out.ReasonCodes)
	if out.CredentialPresent {
		switch {
		case out.CredentialReferencedByWorkflow:
			out.CredentialUsableByPath = out.CredentialUsableByPath || false
		case out.CredentialUsableByPath:
			out.CredentialReferencedByWorkflow = false
		}
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
	if normalized.StandingAccess {
		reasons = append(reasons, "standing_access:true")
	}
	if normalized.CredentialKind != "" && normalized.CredentialKind != CredentialKindUnknown {
		reasons = append(reasons, "credential_kind:"+normalized.CredentialKind)
	}
	if normalized.AccessType != "" && normalized.AccessType != CredentialAccessTypeUnknown {
		reasons = append(reasons, "access_type:"+normalized.AccessType)
	}
	reasons = append(reasons, normalized.ReasonCodes...)
	return normalized.StandingAccess, mergeCredentialEvidenceBasis(reasons)
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
