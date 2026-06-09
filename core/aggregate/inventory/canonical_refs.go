package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

const canonicalStoreVersion = "1"

const (
	mutableEndpointSemanticRefPrefix = "mes-"
	credentialAuthorityRefPrefix     = "cred-"
	authorityBindingRefPrefix        = "ab-"
)

type CanonicalStores struct {
	Version                  string                          `json:"version"`
	MutableEndpointSemantics []MutableEndpointSemanticRecord `json:"mutable_endpoint_semantics,omitempty"`
	CredentialAuthorities    []CredentialAuthorityRecord     `json:"credential_authorities,omitempty"`
	AuthorityBindings        []AuthorityBindingRecord        `json:"authority_bindings,omitempty"`
}

type MutableEndpointSemanticRecord struct {
	RefID string `json:"ref_id"`
	MutableEndpointSemantic
}

type CredentialAuthorityRecord struct {
	RefID string `json:"ref_id"`
	CredentialAuthority
}

type AuthorityBindingRecord struct {
	RefID string `json:"ref_id"`
	AuthorityBinding
}

func ApplyCanonicalStores(inventory *Inventory) {
	if inventory == nil {
		return
	}
	builder := newCanonicalStoreBuilder()

	for idx := range inventory.Tools {
		tool := &inventory.Tools[idx]
		tool.MutableEndpointSemanticRefs = builder.mutableEndpointRefs(tool.MutableEndpointSemantics)
	}

	for idx := range inventory.AgentPrivilegeMap {
		entry := &inventory.AgentPrivilegeMap[idx]
		entry.MutableEndpointSemanticRefs = builder.mutableEndpointRefs(entry.MutableEndpointSemantics)
		entry.CredentialAuthorityRef = builder.credentialAuthorityRef(entry.CredentialAuthority)
		entry.AuthorityBindingRefs = builder.authorityBindingRefs(entry.AuthorityBindings)
	}

	inventory.CanonicalStores = builder.build()
}

type canonicalStoreBuilder struct {
	mutableEndpointSemantics map[string]MutableEndpointSemanticRecord
	credentialAuthorities    map[string]CredentialAuthorityRecord
	authorityBindings        map[string]AuthorityBindingRecord
}

func newCanonicalStoreBuilder() *canonicalStoreBuilder {
	return &canonicalStoreBuilder{
		mutableEndpointSemantics: map[string]MutableEndpointSemanticRecord{},
		credentialAuthorities:    map[string]CredentialAuthorityRecord{},
		authorityBindings:        map[string]AuthorityBindingRecord{},
	}
}

func (b *canonicalStoreBuilder) mutableEndpointRefs(values []MutableEndpointSemantic) []string {
	normalized := NormalizeMutableEndpointSemantics(values)
	if len(normalized) == 0 {
		return nil
	}
	refs := make([]string, 0, len(normalized))
	for _, item := range normalized {
		refID := mutableEndpointSemanticRefID(item)
		if _, ok := b.mutableEndpointSemantics[refID]; !ok {
			b.mutableEndpointSemantics[refID] = MutableEndpointSemanticRecord{
				RefID:                   refID,
				MutableEndpointSemantic: item,
			}
		}
		refs = append(refs, refID)
	}
	sort.Strings(refs)
	return refs
}

func (b *canonicalStoreBuilder) credentialAuthorityRef(value *CredentialAuthority) string {
	normalized := NormalizeCredentialAuthority(value)
	if normalized == nil {
		return ""
	}
	refID := credentialAuthorityRefID(normalized)
	if _, ok := b.credentialAuthorities[refID]; !ok {
		b.credentialAuthorities[refID] = CredentialAuthorityRecord{
			RefID:               refID,
			CredentialAuthority: *normalized,
		}
	}
	return refID
}

func (b *canonicalStoreBuilder) authorityBindingRefs(values []*AuthorityBinding) []string {
	normalized := NormalizeAuthorityBindings(values)
	if len(normalized) == 0 {
		return nil
	}
	refs := make([]string, 0, len(normalized))
	for _, item := range normalized {
		if item == nil {
			continue
		}
		refID := authorityBindingRefID(item)
		if _, ok := b.authorityBindings[refID]; !ok {
			b.authorityBindings[refID] = AuthorityBindingRecord{
				RefID:            refID,
				AuthorityBinding: *item,
			}
		}
		refs = append(refs, refID)
	}
	sort.Strings(refs)
	return refs
}

func (b *canonicalStoreBuilder) build() *CanonicalStores {
	if len(b.mutableEndpointSemantics) == 0 && len(b.credentialAuthorities) == 0 && len(b.authorityBindings) == 0 {
		return nil
	}
	return &CanonicalStores{
		Version:                  canonicalStoreVersion,
		MutableEndpointSemantics: sortCanonicalMutableEndpointRecords(b.mutableEndpointSemantics),
		CredentialAuthorities:    sortCanonicalCredentialAuthorityRecords(b.credentialAuthorities),
		AuthorityBindings:        sortCanonicalAuthorityBindingRecords(b.authorityBindings),
	}
}

func mutableEndpointSemanticRefID(value MutableEndpointSemantic) string {
	normalized := NormalizeMutableEndpointSemantics([]MutableEndpointSemantic{value})
	if len(normalized) == 0 {
		return ""
	}
	item := normalized[0]
	return stableCanonicalRefID(mutableEndpointSemanticRefPrefix, []string{
		item.Semantic,
		item.Confidence,
		item.Surface,
		item.Operation,
		strings.Join(item.EvidenceRefs, ","),
	})
}

func credentialAuthorityRefID(value *CredentialAuthority) string {
	normalized := NormalizeCredentialAuthority(value)
	if normalized == nil {
		return ""
	}
	return stableCanonicalRefID(credentialAuthorityRefPrefix, []string{
		strconvBool(normalized.CredentialPresent),
		strconvBool(normalized.CredentialReferencedByWorkflow),
		strconvBool(normalized.CredentialUsableByPath),
		normalized.CredentialKind,
		normalized.AccessType,
		strconvBool(normalized.StandingAccess),
		strconvBool(normalized.LikelyJIT),
		normalized.TargetSystem,
		normalized.LikelyScope,
		normalized.ScopeConfidence,
		normalized.RotationEvidenceStatus,
		normalized.CredentialSource,
		normalized.Confidence,
		strings.Join(normalized.ReasonCodes, ","),
	})
}

func authorityBindingRefID(value *AuthorityBinding) string {
	normalized := NormalizeAuthorityBinding(value)
	if normalized == nil {
		return ""
	}
	return stableCanonicalRefID(authorityBindingRefPrefix, []string{
		normalized.Kind,
		normalized.Provider,
		normalized.Subject,
		normalized.TargetSystem,
		normalized.Resource,
		normalized.LikelyScope,
		normalized.AccessLevel,
		normalized.Environment,
		strconvBool(normalized.Production),
		normalized.Confidence,
		strings.Join(normalized.EvidenceRefs, ","),
		strings.Join(normalized.ReasonCodes, ","),
	})
}

func stableCanonicalRefID(prefix string, parts []string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return prefix + hex.EncodeToString(sum[:6])
}

func sortCanonicalMutableEndpointRecords(values map[string]MutableEndpointSemanticRecord) []MutableEndpointSemanticRecord {
	if len(values) == 0 {
		return nil
	}
	out := make([]MutableEndpointSemanticRecord, 0, len(values))
	for _, item := range values {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RefID < out[j].RefID
	})
	return out
}

func sortCanonicalCredentialAuthorityRecords(values map[string]CredentialAuthorityRecord) []CredentialAuthorityRecord {
	if len(values) == 0 {
		return nil
	}
	out := make([]CredentialAuthorityRecord, 0, len(values))
	for _, item := range values {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RefID < out[j].RefID
	})
	return out
}

func sortCanonicalAuthorityBindingRecords(values map[string]AuthorityBindingRecord) []AuthorityBindingRecord {
	if len(values) == 0 {
		return nil
	}
	out := make([]AuthorityBindingRecord, 0, len(values))
	for _, item := range values {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RefID < out[j].RefID
	})
	return out
}
