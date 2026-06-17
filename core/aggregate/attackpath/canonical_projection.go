package attackpath

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func BackfillCanonicalProjectionRefs(in *ControlPathGraph) *ControlPathGraph {
	if in == nil {
		return nil
	}
	copyGraph := *in
	copyGraph.Nodes = append([]ControlPathNode(nil), in.Nodes...)
	copyGraph.Edges = append([]ControlPathEdge(nil), in.Edges...)
	for idx := range copyGraph.Nodes {
		node := &copyGraph.Nodes[idx]
		node.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(node.EndpointRefGroupProjection, node.MutableEndpointSemanticRefs, node.MutableEndpointSemantics)
		if len(node.MutableEndpointSemanticRefs) == 0 && len(node.MutableEndpointSemantics) > 0 {
			node.MutableEndpointSemanticRefs = agginventory.CanonicalMutableEndpointRefs(node.MutableEndpointSemantics)
		}
		if strings.TrimSpace(node.CredentialAuthorityRef) == "" && node.CredentialAuthority != nil {
			node.CredentialAuthorityRef = agginventory.CanonicalCredentialAuthorityRef(node.CredentialAuthority)
		}
		if len(node.AuthorityBindingRefs) == 0 && len(node.AuthorityBindings) > 0 {
			node.AuthorityBindingRefs = agginventory.CanonicalAuthorityBindingRefs(node.AuthorityBindings)
		}
	}
	return &copyGraph
}

func StripCanonicalProjectionDetails(in *ControlPathGraph) *ControlPathGraph {
	if in == nil {
		return nil
	}
	copyGraph := *in
	copyGraph.Nodes = append([]ControlPathNode(nil), in.Nodes...)
	copyGraph.Edges = append([]ControlPathEdge(nil), in.Edges...)
	for idx := range copyGraph.Nodes {
		node := &copyGraph.Nodes[idx]
		node.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(node.EndpointRefGroupProjection, node.MutableEndpointSemanticRefs, node.MutableEndpointSemantics)
		if len(node.MutableEndpointSemanticRefs) > 0 {
			node.MutableEndpointSemanticRefs = agginventory.BoundedMutableEndpointSemanticRefs(node.MutableEndpointSemanticRefs, node.MutableEndpointSemantics)
			node.MutableEndpointSemantics = nil
		}
		if strings.TrimSpace(node.CredentialAuthorityRef) != "" {
			node.CredentialAuthority = nil
		}
		if len(node.AuthorityBindingRefs) > 0 {
			node.AuthorityBindings = nil
		}
	}
	return &copyGraph
}
