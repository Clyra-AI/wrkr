package attackpath

import "strings"

func StripCanonicalProjectionDetails(in *ControlPathGraph) *ControlPathGraph {
	if in == nil {
		return nil
	}
	copyGraph := *in
	copyGraph.Nodes = append([]ControlPathNode(nil), in.Nodes...)
	copyGraph.Edges = append([]ControlPathEdge(nil), in.Edges...)
	for idx := range copyGraph.Nodes {
		node := &copyGraph.Nodes[idx]
		if len(node.MutableEndpointSemanticRefs) > 0 {
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
