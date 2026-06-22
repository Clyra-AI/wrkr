package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

const (
	maxOutputEvidenceRefs       = 64
	maxOutputEndpointOperations = 32
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
		copyPath = stripActionPathOutputEvidenceDetails(copyPath)
		out = append(out, copyPath)
	}
	return out
}

func stripActionPathOutputEvidenceDetails(path ActionPath) ActionPath {
	path.ControlEvidenceRefs = boundedOutputEvidenceRefs(path.ControlEvidenceRefs)
	path.ConstraintEvidenceRefs = boundedOutputEvidenceRefs(path.ConstraintEvidenceRefs)
	path.TargetClassEvidenceRefs = boundedOutputEvidenceRefs(path.TargetClassEvidenceRefs)
	path.ActionPathTypeEvidenceRefs = boundedOutputEvidenceRefs(path.ActionPathTypeEvidenceRefs)
	path.PolicyEvidenceRefs = boundedOutputEvidenceRefs(path.PolicyEvidenceRefs)
	path.AutonomyTierEvidenceRefs = boundedOutputEvidenceRefs(path.AutonomyTierEvidenceRefs)
	path.RiskClassificationValidationRefs = boundedOutputEvidenceRefs(path.RiskClassificationValidationRefs)
	path.StateLocationRefs = boundedOutputEvidenceRefs(path.StateLocationRefs)
	path.StateDigestRefs = boundedOutputEvidenceRefs(path.StateDigestRefs)
	path.EvidencePacketRefs = boundedOutputEvidenceRefs(path.EvidencePacketRefs)
	path.AttackPathRefs = boundedOutputEvidenceRefs(path.AttackPathRefs)
	path.SourceFindingKeys = boundedOutputEvidenceRefs(path.SourceFindingKeys)
	path.WorkflowChainRefs = boundedOutputEvidenceRefs(path.WorkflowChainRefs)
	path.DecisionTraceRefs = boundedOutputEvidenceRefs(path.DecisionTraceRefs)
	path.MatchedProductionTargets = dedupeSortedStrings(path.MatchedProductionTargets)

	path.EvidenceDecisions = append([]evidencepolicy.Decision(nil), path.EvidenceDecisions...)
	for idx := range path.EvidenceDecisions {
		path.EvidenceDecisions[idx] = cloneEvidenceDecision(path.EvidenceDecisions[idx])
		path.EvidenceDecisions[idx].SelectedEvidenceRefs = boundedOutputEvidenceRefs(path.EvidenceDecisions[idx].SelectedEvidenceRefs)
		for detailIdx := range path.EvidenceDecisions[idx].RejectedCandidates {
			path.EvidenceDecisions[idx].RejectedCandidates[detailIdx].EvidenceRefs = boundedOutputEvidenceRefs(path.EvidenceDecisions[idx].RejectedCandidates[detailIdx].EvidenceRefs)
		}
	}
	path.Contradictions = cloneContradictionsForOutput(path.Contradictions)
	for idx := range path.Contradictions {
		path.Contradictions[idx].EvidenceRefs = boundedOutputEvidenceRefs(path.Contradictions[idx].EvidenceRefs)
	}

	path.HighStakesPresets = CloneHighStakesPresets(path.HighStakesPresets)
	for idx := range path.HighStakesPresets {
		path.HighStakesPresets[idx].EvidenceRefs = boundedOutputEvidenceRefs(path.HighStakesPresets[idx].EvidenceRefs)
	}
	path.ClosureRequirements = CloneClosureRequirements(path.ClosureRequirements)
	for idx := range path.ClosureRequirements {
		path.ClosureRequirements[idx].ClosureRefs = boundedOutputEvidenceRefs(path.ClosureRequirements[idx].ClosureRefs)
	}
	if path.ProductionContext != nil {
		path.ProductionContext = CloneProductionContext(path.ProductionContext)
		path.ProductionContext.EvidenceRefs = boundedOutputEvidenceRefs(path.ProductionContext.EvidenceRefs)
		path.ProductionContext.MutableEndpointOperations = boundedOutputStrings(path.ProductionContext.MutableEndpointOperations, maxOutputEndpointOperations)
	}
	if path.AgenticDeliverySystemChange != nil {
		path.AgenticDeliverySystemChange = CloneAgenticDeliverySystemChange(path.AgenticDeliverySystemChange)
		path.AgenticDeliverySystemChange.EvidenceRefs = boundedOutputEvidenceRefs(path.AgenticDeliverySystemChange.EvidenceRefs)
		path.AgenticDeliverySystemChange.ReachableTargets = boundedOutputStrings(path.AgenticDeliverySystemChange.ReachableTargets, maxOutputEndpointOperations)
	}
	if path.DecisionPrecedent != nil {
		path.DecisionPrecedent = CloneDecisionPrecedent(path.DecisionPrecedent)
		path.DecisionPrecedent.EvidenceRefs = boundedOutputEvidenceRefs(path.DecisionPrecedent.EvidenceRefs)
	}
	if path.ActionLineage != nil {
		path.ActionLineage = CloneActionLineage(path.ActionLineage)
		for idx := range path.ActionLineage.Segments {
			path.ActionLineage.Segments[idx].EvidenceRefs = boundedOutputEvidenceRefs(path.ActionLineage.Segments[idx].EvidenceRefs)
		}
	}
	return path
}

func boundedOutputEvidenceRefs(values []string) []string {
	return boundedOutputStrings(values, maxOutputEvidenceRefs)
}

func boundedOutputStrings(values []string, limit int) []string {
	values = dedupeSortedStrings(values)
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]string(nil), values[:limit]...)
}

func cloneContradictionsForOutput(contradictions []evidencepolicy.Contradiction) []evidencepolicy.Contradiction {
	if len(contradictions) == 0 {
		return nil
	}
	out := append([]evidencepolicy.Contradiction(nil), contradictions...)
	for idx := range out {
		out[idx].EvidenceRefs = append([]string(nil), out[idx].EvidenceRefs...)
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
