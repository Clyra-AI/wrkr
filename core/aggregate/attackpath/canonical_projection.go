package attackpath

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

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
