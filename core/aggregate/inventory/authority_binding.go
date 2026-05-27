package inventory

import (
	"sort"
	"strings"
)

const (
	AuthorityBindingCloudRole         = "cloud_role"
	AuthorityBindingKubernetesRBAC    = "kubernetes_rbac"
	AuthorityBindingServiceConnection = "service_connection"
	AuthorityBindingWorkloadIdentity  = "workload_identity"
	AuthorityBindingDeploymentPath    = "deployment_path"
	AuthorityBindingSaaSToken         = "saas_token"

	AuthorityAccessAdmin   = "admin"
	AuthorityAccessWrite   = "write"
	AuthorityAccessRead    = "read"
	AuthorityAccessUnknown = "unknown"
)

type AuthorityBinding struct {
	Kind         string   `json:"kind" yaml:"kind"`
	Provider     string   `json:"provider,omitempty" yaml:"provider,omitempty"`
	Subject      string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	TargetSystem string   `json:"target_system,omitempty" yaml:"target_system,omitempty"`
	Resource     string   `json:"resource,omitempty" yaml:"resource,omitempty"`
	LikelyScope  string   `json:"likely_scope,omitempty" yaml:"likely_scope,omitempty"`
	AccessLevel  string   `json:"access_level,omitempty" yaml:"access_level,omitempty"`
	Environment  string   `json:"environment,omitempty" yaml:"environment,omitempty"`
	Production   bool     `json:"production" yaml:"production"`
	Confidence   string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	ReasonCodes  []string `json:"reason_codes,omitempty" yaml:"reason_codes,omitempty"`
}

func CloneAuthorityBinding(in *AuthorityBinding) *AuthorityBinding {
	if in == nil {
		return nil
	}
	out := *in
	out.Kind = strings.TrimSpace(out.Kind)
	out.Provider = strings.TrimSpace(out.Provider)
	out.Subject = strings.TrimSpace(out.Subject)
	out.TargetSystem = strings.TrimSpace(out.TargetSystem)
	out.Resource = strings.TrimSpace(out.Resource)
	out.LikelyScope = strings.TrimSpace(out.LikelyScope)
	out.AccessLevel = strings.TrimSpace(out.AccessLevel)
	out.Environment = strings.TrimSpace(out.Environment)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.EvidenceRefs = mergeCredentialEvidenceBasis(out.EvidenceRefs)
	out.ReasonCodes = mergeCredentialEvidenceBasis(out.ReasonCodes)
	return &out
}

func CloneAuthorityBindings(in []*AuthorityBinding) []*AuthorityBinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]*AuthorityBinding, 0, len(in))
	for _, item := range in {
		if cloned := CloneAuthorityBinding(item); cloned != nil {
			out = append(out, cloned)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func NormalizeAuthorityBinding(in *AuthorityBinding) *AuthorityBinding {
	if in == nil {
		return nil
	}
	out := CloneAuthorityBinding(in)
	out.Kind = normalizeAuthorityBindingKind(out.Kind)
	out.AccessLevel = normalizeAuthorityAccessLevel(out.AccessLevel)
	out.Confidence = normalizeCredentialConfidence(out.Confidence)
	if out.Confidence == "" {
		out.Confidence = "low"
	}
	return out
}

func NormalizeAuthorityBindings(in []*AuthorityBinding) []*AuthorityBinding {
	if len(in) == 0 {
		return nil
	}
	out := make([]*AuthorityBinding, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		normalized := NormalizeAuthorityBinding(item)
		if normalized == nil {
			continue
		}
		key := strings.Join([]string{
			normalized.Kind,
			normalized.Provider,
			normalized.Subject,
			normalized.TargetSystem,
			normalized.Resource,
			normalized.LikelyScope,
			normalized.AccessLevel,
			normalized.Environment,
			strconvBool(normalized.Production),
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.Join([]string{out[i].Kind, out[i].Provider, out[i].TargetSystem, out[i].AccessLevel, out[i].Subject, out[i].Resource}, "|")
		right := strings.Join([]string{out[j].Kind, out[j].Provider, out[j].TargetSystem, out[j].AccessLevel, out[j].Subject, out[j].Resource}, "|")
		return left < right
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeAuthorityBindingKind(value string) string {
	switch strings.TrimSpace(value) {
	case AuthorityBindingCloudRole,
		AuthorityBindingKubernetesRBAC,
		AuthorityBindingServiceConnection,
		AuthorityBindingWorkloadIdentity,
		AuthorityBindingDeploymentPath,
		AuthorityBindingSaaSToken:
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func normalizeAuthorityAccessLevel(value string) string {
	switch strings.TrimSpace(value) {
	case AuthorityAccessAdmin,
		AuthorityAccessWrite,
		AuthorityAccessRead:
		return strings.TrimSpace(value)
	default:
		return AuthorityAccessUnknown
	}
}
