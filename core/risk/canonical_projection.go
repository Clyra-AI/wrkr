package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func BackfillCanonicalProjectionRefs(paths []ActionPath, inventory *agginventory.Inventory) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	if inventory != nil {
		agginventory.EnsureCanonicalStores(inventory)
	}
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		copyPath := path
		copyPath.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(copyPath.EndpointRefGroupProjection, copyPath.MutableEndpointSemanticRefs, copyPath.MutableEndpointSemantics)
		if len(copyPath.MutableEndpointSemanticRefs) == 0 && len(copyPath.MutableEndpointSemantics) > 0 {
			copyPath.MutableEndpointSemanticRefs = agginventory.CanonicalMutableEndpointRefs(copyPath.MutableEndpointSemantics)
		}
		if strings.TrimSpace(copyPath.CredentialAuthorityRef) == "" && copyPath.CredentialAuthority != nil {
			copyPath.CredentialAuthorityRef = agginventory.CanonicalCredentialAuthorityRef(copyPath.CredentialAuthority)
		}
		if len(copyPath.AuthorityBindingRefs) == 0 && len(copyPath.AuthorityBindings) > 0 {
			copyPath.AuthorityBindingRefs = agginventory.CanonicalAuthorityBindingRefs(copyPath.AuthorityBindings)
		}
		out = append(out, copyPath)
	}
	return out
}

func HydrateCanonicalProjectionDetails(paths []ActionPath, inventory *agginventory.Inventory) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	resolver := agginventory.NewCanonicalResolver(nil)
	if inventory != nil {
		agginventory.EnsureCanonicalStores(inventory)
		resolver = agginventory.NewCanonicalResolver(inventory.CanonicalStores)
	}
	out := make([]ActionPath, 0, len(paths))
	for _, path := range BackfillCanonicalProjectionRefs(paths, inventory) {
		copyPath := path
		copyPath.EndpointRefGroupProjection = resolver.ResolveMutableEndpointGroupProjection(copyPath.EndpointRefGroupProjection)
		if strings.TrimSpace(copyPath.EndpointRefGroupID) != "" && copyPath.EndpointRefCount > len(copyPath.MutableEndpointSemanticRefs) {
			copyPath.MutableEndpointSemanticRefs = resolver.ResolveMutableEndpointGroupRefs(copyPath.EndpointRefGroupID, copyPath.MutableEndpointSemanticRefs)
		}
		if len(copyPath.MutableEndpointSemantics) == 0 && len(copyPath.MutableEndpointSemanticRefs) > 0 {
			copyPath.MutableEndpointSemantics = resolver.ResolveMutableEndpointSemantics(copyPath.MutableEndpointSemanticRefs, nil)
		}
		if copyPath.CredentialAuthority == nil && strings.TrimSpace(copyPath.CredentialAuthorityRef) != "" {
			copyPath.CredentialAuthority = resolver.ResolveCredentialAuthority(copyPath.CredentialAuthorityRef, nil)
		}
		if len(copyPath.AuthorityBindings) == 0 && len(copyPath.AuthorityBindingRefs) > 0 {
			copyPath.AuthorityBindings = resolver.ResolveAuthorityBindings(copyPath.AuthorityBindingRefs, nil)
		}
		out = append(out, copyPath)
	}
	return out
}

func StripCanonicalProjectionDetails(paths []ActionPath) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		copyPath := path
		copyPath.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(copyPath.EndpointRefGroupProjection, copyPath.MutableEndpointSemanticRefs, copyPath.MutableEndpointSemantics)
		if len(copyPath.MutableEndpointSemanticRefs) > 0 {
			copyPath.MutableEndpointSemanticRefs = agginventory.BoundedMutableEndpointSemanticRefs(copyPath.MutableEndpointSemanticRefs, copyPath.MutableEndpointSemantics)
			copyPath.MutableEndpointSemantics = nil
		}
		if strings.TrimSpace(copyPath.CredentialAuthorityRef) != "" {
			copyPath.CredentialAuthority = nil
		}
		if len(copyPath.AuthorityBindingRefs) > 0 {
			copyPath.AuthorityBindings = nil
		}
		out = append(out, copyPath)
	}
	return out
}

func BackfillActionPathToControlFirstCanonicalProjectionRefs(in *ActionPathToControlFirst, inventory *agginventory.Inventory) *ActionPathToControlFirst {
	if in == nil {
		return nil
	}
	paths := BackfillCanonicalProjectionRefs([]ActionPath{in.Path}, inventory)
	if len(paths) == 0 {
		return &ActionPathToControlFirst{Summary: in.Summary}
	}
	return &ActionPathToControlFirst{
		Summary: in.Summary,
		Path:    paths[0],
	}
}

func HydrateActionPathToControlFirstCanonicalDetails(in *ActionPathToControlFirst, inventory *agginventory.Inventory) *ActionPathToControlFirst {
	if in == nil {
		return nil
	}
	paths := HydrateCanonicalProjectionDetails([]ActionPath{in.Path}, inventory)
	if len(paths) == 0 {
		return &ActionPathToControlFirst{Summary: in.Summary}
	}
	return &ActionPathToControlFirst{
		Summary: in.Summary,
		Path:    paths[0],
	}
}

func StripActionPathToControlFirstCanonicalProjectionDetails(in *ActionPathToControlFirst) *ActionPathToControlFirst {
	if in == nil {
		return nil
	}
	paths := StripCanonicalProjectionDetails([]ActionPath{in.Path})
	if len(paths) == 0 {
		return &ActionPathToControlFirst{Summary: in.Summary}
	}
	return &ActionPathToControlFirst{
		Summary: in.Summary,
		Path:    paths[0],
	}
}
