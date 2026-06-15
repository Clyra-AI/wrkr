package inventory

import "strings"

type CanonicalResolver struct {
	mutableEndpointSemantics map[string]MutableEndpointSemantic
	mutableEndpointGroups    map[string]MutableEndpointGroupRecord
	credentialAuthorities    map[string]CredentialAuthority
	authorityBindings        map[string]*AuthorityBinding
}

func NewCanonicalResolver(stores *CanonicalStores) CanonicalResolver {
	resolver := CanonicalResolver{
		mutableEndpointSemantics: map[string]MutableEndpointSemantic{},
		mutableEndpointGroups:    map[string]MutableEndpointGroupRecord{},
		credentialAuthorities:    map[string]CredentialAuthority{},
		authorityBindings:        map[string]*AuthorityBinding{},
	}
	if stores == nil {
		return resolver
	}
	for _, item := range stores.MutableEndpointSemantics {
		refID := strings.TrimSpace(item.RefID)
		if refID == "" {
			continue
		}
		normalized := NormalizeMutableEndpointSemantics([]MutableEndpointSemantic{item.MutableEndpointSemantic})
		if len(normalized) == 0 {
			continue
		}
		resolver.mutableEndpointSemantics[refID] = normalized[0]
	}
	for _, item := range stores.MutableEndpointGroups {
		groupID := strings.TrimSpace(item.GroupID)
		if groupID == "" {
			continue
		}
		copyItem := item
		copyItem.RefIDs = uniqueSortedEndpointRefs(copyItem.RefIDs)
		copyItem.RouteGroups = uniqueSortedEndpointRefs(copyItem.RouteGroups)
		copyItem.OperationCounts = cloneEndpointOperationCounts(copyItem.OperationCounts)
		copyItem.RefSamples = cloneEndpointRefSamples(copyItem.RefSamples)
		if copyItem.RefCount == 0 {
			copyItem.RefCount = len(copyItem.RefIDs)
		}
		resolver.mutableEndpointGroups[groupID] = copyItem
	}
	for _, item := range stores.CredentialAuthorities {
		refID := strings.TrimSpace(item.RefID)
		if refID == "" {
			continue
		}
		normalized := NormalizeCredentialAuthority(&item.CredentialAuthority)
		if normalized == nil {
			continue
		}
		resolver.credentialAuthorities[refID] = *normalized
	}
	for _, item := range stores.AuthorityBindings {
		refID := strings.TrimSpace(item.RefID)
		if refID == "" {
			continue
		}
		normalized := NormalizeAuthorityBinding(&item.AuthorityBinding)
		if normalized == nil {
			continue
		}
		resolver.authorityBindings[refID] = normalized
	}
	return resolver
}

func (r CanonicalResolver) ResolveMutableEndpointGroupRefs(groupID string, fallback []string) []string {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return uniqueSortedEndpointRefs(fallback)
	}
	item, ok := r.mutableEndpointGroups[groupID]
	if !ok || len(item.RefIDs) == 0 {
		return uniqueSortedEndpointRefs(fallback)
	}
	return append([]string(nil), item.RefIDs...)
}

func (r CanonicalResolver) ResolveMutableEndpointGroupProjection(group EndpointRefGroupProjection) EndpointRefGroupProjection {
	groupID := strings.TrimSpace(group.EndpointRefGroupID)
	if groupID == "" {
		return group
	}
	item, ok := r.mutableEndpointGroups[groupID]
	if !ok {
		return group
	}
	out := group
	if out.EndpointRefCount == 0 {
		out.EndpointRefCount = item.RefCount
	}
	if len(out.EndpointRouteGroups) == 0 {
		out.EndpointRouteGroups = append([]string(nil), item.RouteGroups...)
	}
	if len(out.EndpointOperationCounts) == 0 {
		out.EndpointOperationCounts = cloneEndpointOperationCounts(item.OperationCounts)
	}
	if len(out.EndpointRefSamples) == 0 {
		out.EndpointRefSamples = cloneEndpointRefSamples(item.RefSamples)
	}
	return out
}

func (r CanonicalResolver) ResolveMutableEndpointSemantics(refs []string, fallback []MutableEndpointSemantic) []MutableEndpointSemantic {
	if len(refs) == 0 {
		return NormalizeMutableEndpointSemantics(fallback)
	}
	out := make([]MutableEndpointSemantic, 0, len(refs))
	for _, refID := range refs {
		item, ok := r.mutableEndpointSemantics[strings.TrimSpace(refID)]
		if !ok {
			continue
		}
		out = append(out, item)
	}
	if len(out) == 0 {
		return NormalizeMutableEndpointSemantics(fallback)
	}
	return NormalizeMutableEndpointSemantics(out)
}

func (r CanonicalResolver) HasMutableEndpointSemanticRefs(refs []string) bool {
	if len(refs) == 0 {
		return false
	}
	for _, refID := range refs {
		if _, ok := r.mutableEndpointSemantics[strings.TrimSpace(refID)]; !ok {
			return false
		}
	}
	return true
}

func (r CanonicalResolver) ResolveCredentialAuthority(ref string, fallback *CredentialAuthority) *CredentialAuthority {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return CloneCredentialAuthority(fallback)
	}
	item, ok := r.credentialAuthorities[ref]
	if !ok {
		return CloneCredentialAuthority(fallback)
	}
	return CloneCredentialAuthority(&item)
}

func (r CanonicalResolver) HasCredentialAuthorityRef(ref string) bool {
	if strings.TrimSpace(ref) == "" {
		return false
	}
	_, ok := r.credentialAuthorities[strings.TrimSpace(ref)]
	return ok
}

func (r CanonicalResolver) ResolveAuthorityBindings(refs []string, fallback []*AuthorityBinding) []*AuthorityBinding {
	if len(refs) == 0 {
		return NormalizeAuthorityBindings(fallback)
	}
	out := make([]*AuthorityBinding, 0, len(refs))
	for _, refID := range refs {
		item, ok := r.authorityBindings[strings.TrimSpace(refID)]
		if !ok {
			continue
		}
		out = append(out, CloneAuthorityBindings([]*AuthorityBinding{item})...)
	}
	if len(out) == 0 {
		return NormalizeAuthorityBindings(fallback)
	}
	return NormalizeAuthorityBindings(out)
}

func (r CanonicalResolver) HasAuthorityBindingRefs(refs []string) bool {
	if len(refs) == 0 {
		return false
	}
	for _, refID := range refs {
		if _, ok := r.authorityBindings[strings.TrimSpace(refID)]; !ok {
			return false
		}
	}
	return true
}

func CanonicalMutableEndpointRefs(values []MutableEndpointSemantic) []string {
	return newCanonicalStoreBuilder().mutableEndpointRefs(values)
}

func CanonicalCredentialAuthorityRef(value *CredentialAuthority) string {
	return newCanonicalStoreBuilder().credentialAuthorityRef(value)
}

func CanonicalAuthorityBindingRefs(values []*AuthorityBinding) []string {
	return newCanonicalStoreBuilder().authorityBindingRefs(values)
}

func BackfillCanonicalProjectionRefs(in *Inventory) {
	if in == nil {
		return
	}
	for idx := range in.Tools {
		tool := &in.Tools[idx]
		if len(tool.MutableEndpointSemanticRefs) == 0 && len(tool.MutableEndpointSemantics) > 0 {
			tool.MutableEndpointSemanticRefs = CanonicalMutableEndpointRefs(tool.MutableEndpointSemantics)
		}
	}
	for idx := range in.AgentPrivilegeMap {
		entry := &in.AgentPrivilegeMap[idx]
		if len(entry.MutableEndpointSemanticRefs) == 0 && len(entry.MutableEndpointSemantics) > 0 {
			entry.MutableEndpointSemanticRefs = CanonicalMutableEndpointRefs(entry.MutableEndpointSemantics)
		}
		if strings.TrimSpace(entry.CredentialAuthorityRef) == "" && entry.CredentialAuthority != nil {
			entry.CredentialAuthorityRef = CanonicalCredentialAuthorityRef(entry.CredentialAuthority)
		}
		if len(entry.AuthorityBindingRefs) == 0 && len(entry.AuthorityBindings) > 0 {
			entry.AuthorityBindingRefs = CanonicalAuthorityBindingRefs(entry.AuthorityBindings)
		}
	}
}

func EnsureCanonicalStores(in *Inventory) {
	if in == nil {
		return
	}
	BackfillCanonicalProjectionRefs(in)
	if in.CanonicalStores != nil {
		return
	}
	if !inventoryHasInlineCanonicalDetails(in) {
		return
	}
	ApplyCanonicalStores(in)
}

func AugmentCanonicalStores(in *Inventory, mutableEndpointGroups [][]MutableEndpointSemantic, credentialAuthorities []*CredentialAuthority, authorityBindingGroups [][]*AuthorityBinding) {
	if in == nil {
		return
	}
	builder := newCanonicalStoreBuilder()
	seedCanonicalStoreBuilder(builder, in.CanonicalStores)
	for _, group := range mutableEndpointGroups {
		builder.mutableEndpointRefs(group)
		builder.mutableEndpointGroup(nil, group)
	}
	for _, authority := range credentialAuthorities {
		builder.credentialAuthorityRef(authority)
	}
	for _, group := range authorityBindingGroups {
		builder.authorityBindingRefs(group)
	}
	in.CanonicalStores = builder.build()
}

func HydrateCanonicalProjectionDetails(in *Inventory) {
	if in == nil {
		return
	}
	EnsureCanonicalStores(in)
	resolver := NewCanonicalResolver(in.CanonicalStores)
	for idx := range in.Tools {
		tool := &in.Tools[idx]
		if len(tool.MutableEndpointSemantics) == 0 && len(tool.MutableEndpointSemanticRefs) > 0 {
			tool.MutableEndpointSemantics = resolver.ResolveMutableEndpointSemantics(tool.MutableEndpointSemanticRefs, nil)
		}
	}
	for idx := range in.AgentPrivilegeMap {
		entry := &in.AgentPrivilegeMap[idx]
		if len(entry.MutableEndpointSemantics) == 0 && len(entry.MutableEndpointSemanticRefs) > 0 {
			entry.MutableEndpointSemantics = resolver.ResolveMutableEndpointSemantics(entry.MutableEndpointSemanticRefs, nil)
		}
		if entry.CredentialAuthority == nil && strings.TrimSpace(entry.CredentialAuthorityRef) != "" {
			entry.CredentialAuthority = resolver.ResolveCredentialAuthority(entry.CredentialAuthorityRef, nil)
		}
		if len(entry.AuthorityBindings) == 0 && len(entry.AuthorityBindingRefs) > 0 {
			entry.AuthorityBindings = resolver.ResolveAuthorityBindings(entry.AuthorityBindingRefs, nil)
		}
	}
}

func StripCanonicalProjectionDetails(in *Inventory) {
	if in == nil {
		return
	}
	for idx := range in.Tools {
		if len(in.Tools[idx].MutableEndpointSemanticRefs) > 0 {
			in.Tools[idx].MutableEndpointSemantics = nil
		}
	}
	for idx := range in.AgentPrivilegeMap {
		entry := &in.AgentPrivilegeMap[idx]
		if len(entry.MutableEndpointSemanticRefs) > 0 {
			entry.MutableEndpointSemantics = nil
		}
		if strings.TrimSpace(entry.CredentialAuthorityRef) != "" {
			entry.CredentialAuthority = nil
		}
		if len(entry.AuthorityBindingRefs) > 0 {
			entry.AuthorityBindings = nil
		}
	}
}

func BackfillMutableEndpointGroupProjection(group EndpointRefGroupProjection, refs []string, semantics []MutableEndpointSemantic) EndpointRefGroupProjection {
	if strings.TrimSpace(group.EndpointRefGroupID) != "" &&
		group.EndpointRefCount > 0 &&
		(len(group.EndpointRouteGroups) > 0 || len(group.EndpointOperationCounts) > 0 || len(group.EndpointRefSamples) > 0) {
		return group
	}
	if len(refs) == 0 && len(semantics) == 0 {
		return group
	}
	built := BuildMutableEndpointGroupProjection(refs, semantics)
	if built.EndpointRefGroupID == "" {
		return group
	}
	if strings.TrimSpace(group.EndpointRefGroupID) != "" {
		built.EndpointRefGroupID = strings.TrimSpace(group.EndpointRefGroupID)
	}
	if group.EndpointRefCount > 0 {
		built.EndpointRefCount = group.EndpointRefCount
	}
	if len(group.EndpointRouteGroups) > 0 {
		built.EndpointRouteGroups = append([]string(nil), group.EndpointRouteGroups...)
	}
	if len(group.EndpointOperationCounts) > 0 {
		built.EndpointOperationCounts = cloneEndpointOperationCounts(group.EndpointOperationCounts)
	}
	if len(group.EndpointRefSamples) > 0 {
		built.EndpointRefSamples = cloneEndpointRefSamples(group.EndpointRefSamples)
	}
	return built
}

func inventoryHasInlineCanonicalDetails(in *Inventory) bool {
	if in == nil {
		return false
	}
	for _, tool := range in.Tools {
		if len(tool.MutableEndpointSemantics) > 0 {
			return true
		}
	}
	for _, entry := range in.AgentPrivilegeMap {
		if len(entry.MutableEndpointSemantics) > 0 || entry.CredentialAuthority != nil || len(entry.AuthorityBindings) > 0 {
			return true
		}
	}
	return false
}

func seedCanonicalStoreBuilder(builder *canonicalStoreBuilder, stores *CanonicalStores) {
	if builder == nil || stores == nil {
		return
	}
	for _, item := range stores.MutableEndpointSemantics {
		if strings.TrimSpace(item.RefID) == "" {
			continue
		}
		builder.mutableEndpointSemantics[item.RefID] = item
	}
	for _, item := range stores.MutableEndpointGroups {
		if strings.TrimSpace(item.GroupID) == "" {
			continue
		}
		builder.mutableEndpointGroups[item.GroupID] = item
	}
	for _, item := range stores.CredentialAuthorities {
		if strings.TrimSpace(item.RefID) == "" {
			continue
		}
		builder.credentialAuthorities[item.RefID] = item
	}
	for _, item := range stores.AuthorityBindings {
		if strings.TrimSpace(item.RefID) == "" {
			continue
		}
		builder.authorityBindings[item.RefID] = item
	}
}
