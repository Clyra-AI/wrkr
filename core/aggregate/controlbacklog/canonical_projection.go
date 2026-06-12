package controlbacklog

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func BackfillCanonicalProjectionRefs(in *Backlog) *Backlog {
	if in == nil {
		return nil
	}
	copyBacklog := *in
	copyBacklog.Items = append([]Item(nil), in.Items...)
	for idx := range copyBacklog.Items {
		item := &copyBacklog.Items[idx]
		if strings.TrimSpace(item.CredentialAuthorityRef) == "" && item.CredentialAuthority != nil {
			item.CredentialAuthorityRef = agginventory.CanonicalCredentialAuthorityRef(item.CredentialAuthority)
		}
		if len(item.AuthorityBindingRefs) == 0 && len(item.AuthorityBindings) > 0 {
			item.AuthorityBindingRefs = agginventory.CanonicalAuthorityBindingRefs(item.AuthorityBindings)
		}
	}
	return &copyBacklog
}

func HydrateCanonicalProjectionDetails(in *Backlog, inventory *agginventory.Inventory) *Backlog {
	if in == nil {
		return nil
	}
	resolver := agginventory.NewCanonicalResolver(nil)
	if inventory != nil {
		agginventory.EnsureCanonicalStores(inventory)
		resolver = agginventory.NewCanonicalResolver(inventory.CanonicalStores)
	}
	copyBacklog := *in
	copyBacklog.Items = append([]Item(nil), in.Items...)
	for idx := range copyBacklog.Items {
		item := &copyBacklog.Items[idx]
		if item.CredentialAuthority == nil && strings.TrimSpace(item.CredentialAuthorityRef) != "" {
			item.CredentialAuthority = resolver.ResolveCredentialAuthority(item.CredentialAuthorityRef, nil)
		}
		if len(item.AuthorityBindings) == 0 && len(item.AuthorityBindingRefs) > 0 {
			item.AuthorityBindings = resolver.ResolveAuthorityBindings(item.AuthorityBindingRefs, nil)
		}
	}
	return &copyBacklog
}

func StripCanonicalProjectionDetails(in *Backlog) *Backlog {
	if in == nil {
		return nil
	}
	copyBacklog := *in
	copyBacklog.Items = append([]Item(nil), in.Items...)
	for idx := range copyBacklog.Items {
		item := &copyBacklog.Items[idx]
		if strings.TrimSpace(item.CredentialAuthorityRef) != "" {
			item.CredentialAuthority = nil
		}
		if len(item.AuthorityBindingRefs) > 0 {
			item.AuthorityBindings = nil
		}
	}
	return &copyBacklog
}
