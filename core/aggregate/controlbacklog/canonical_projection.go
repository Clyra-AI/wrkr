package controlbacklog

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	maxBacklogOutputEvidenceRefs       = 64
	maxBacklogOutputEndpointOperations = 32
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
		stripItemOutputEvidenceDetails(item)
	}
	return &copyBacklog
}

func stripItemOutputEvidenceDetails(item *Item) {
	if item == nil {
		return
	}
	item.OwnershipEvidence = boundedOutputEvidenceRefs(item.OwnershipEvidence)
	item.ControlEvidenceRefs = boundedOutputEvidenceRefs(item.ControlEvidenceRefs)
	item.ConstraintEvidenceRefs = boundedOutputEvidenceRefs(item.ConstraintEvidenceRefs)
	item.TargetClassEvidenceRefs = boundedOutputEvidenceRefs(item.TargetClassEvidenceRefs)
	item.ActionPathTypeEvidenceRefs = boundedOutputEvidenceRefs(item.ActionPathTypeEvidenceRefs)
	item.EvidenceBasis = boundedOutputEvidenceRefs(item.EvidenceBasis)
	item.AutonomyTierEvidenceRefs = boundedOutputEvidenceRefs(item.AutonomyTierEvidenceRefs)
	item.RiskClassificationValidationRefs = boundedOutputEvidenceRefs(item.RiskClassificationValidationRefs)
	item.PolicyEvidenceRefs = boundedOutputEvidenceRefs(item.PolicyEvidenceRefs)
	item.PolicyRefs = boundedOutputEvidenceRefs(item.PolicyRefs)
	item.LinkedFindingIDs = boundedOutputEvidenceRefs(item.LinkedFindingIDs)
	item.LinkedControlPathNodeIDs = boundedOutputEvidenceRefs(item.LinkedControlPathNodeIDs)
	item.LinkedControlPathEdgeIDs = boundedOutputEvidenceRefs(item.LinkedControlPathEdgeIDs)

	item.EvidenceDecisions = append([]evidencepolicy.Decision(nil), item.EvidenceDecisions...)
	for idx := range item.EvidenceDecisions {
		item.EvidenceDecisions[idx] = cloneEvidenceDecision(item.EvidenceDecisions[idx])
		item.EvidenceDecisions[idx].SelectedEvidenceRefs = boundedOutputEvidenceRefs(item.EvidenceDecisions[idx].SelectedEvidenceRefs)
		for detailIdx := range item.EvidenceDecisions[idx].RejectedCandidates {
			item.EvidenceDecisions[idx].RejectedCandidates[detailIdx].EvidenceRefs = boundedOutputEvidenceRefs(item.EvidenceDecisions[idx].RejectedCandidates[detailIdx].EvidenceRefs)
		}
	}
	item.Contradictions = cloneContradictionsForOutput(item.Contradictions)
	for idx := range item.Contradictions {
		item.Contradictions[idx].EvidenceRefs = boundedOutputEvidenceRefs(item.Contradictions[idx].EvidenceRefs)
	}
	if item.GovernanceDisposition != nil {
		copyDisposition := *item.GovernanceDisposition
		copyDisposition.EvidenceRefs = boundedOutputEvidenceRefs(copyDisposition.EvidenceRefs)
		item.GovernanceDisposition = &copyDisposition
	}
	item.ClosureRequirements = risk.CloneClosureRequirements(item.ClosureRequirements)
	for idx := range item.ClosureRequirements {
		item.ClosureRequirements[idx].ClosureRefs = boundedOutputEvidenceRefs(item.ClosureRequirements[idx].ClosureRefs)
	}
	if item.DecisionPrecedent != nil {
		item.DecisionPrecedent = risk.CloneDecisionPrecedent(item.DecisionPrecedent)
		item.DecisionPrecedent.EvidenceRefs = boundedOutputEvidenceRefs(item.DecisionPrecedent.EvidenceRefs)
	}
	item.HighStakesPresets = risk.CloneHighStakesPresets(item.HighStakesPresets)
	for idx := range item.HighStakesPresets {
		item.HighStakesPresets[idx].EvidenceRefs = boundedOutputEvidenceRefs(item.HighStakesPresets[idx].EvidenceRefs)
	}
	if item.ProductionContext != nil {
		item.ProductionContext = risk.CloneProductionContext(item.ProductionContext)
		item.ProductionContext.EvidenceRefs = boundedOutputEvidenceRefs(item.ProductionContext.EvidenceRefs)
		item.ProductionContext.MutableEndpointOperations = boundedOutputStrings(item.ProductionContext.MutableEndpointOperations, maxBacklogOutputEndpointOperations)
	}
	item.SecurityTestRecipes = cloneSecurityTestRecipesForOutput(item.SecurityTestRecipes)
	for idx := range item.SecurityTestRecipes {
		item.SecurityTestRecipes[idx].EvidenceRefs = boundedOutputEvidenceRefs(item.SecurityTestRecipes[idx].EvidenceRefs)
	}
}

func boundedOutputEvidenceRefs(values []string) []string {
	return boundedOutputStrings(values, maxBacklogOutputEvidenceRefs)
}

func cloneEvidenceDecision(in evidencepolicy.Decision) evidencepolicy.Decision {
	out := in
	out.SelectedEvidenceRefs = append([]string(nil), in.SelectedEvidenceRefs...)
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	out.ConflictReasonCodes = append([]string(nil), in.ConflictReasonCodes...)
	if len(in.RejectedCandidates) > 0 {
		out.RejectedCandidates = make([]evidencepolicy.Candidate, 0, len(in.RejectedCandidates))
		for _, item := range in.RejectedCandidates {
			copyItem := item
			copyItem.EvidenceRefs = append([]string(nil), item.EvidenceRefs...)
			copyItem.ReasonCodes = append([]string(nil), item.ReasonCodes...)
			out.RejectedCandidates = append(out.RejectedCandidates, copyItem)
		}
	}
	return out
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

func cloneSecurityTestRecipesForOutput(recipes []SecurityTestRecipe) []SecurityTestRecipe {
	if len(recipes) == 0 {
		return nil
	}
	out := append([]SecurityTestRecipe(nil), recipes...)
	for idx := range out {
		out[idx].Preconditions = append([]string(nil), out[idx].Preconditions...)
		out[idx].RequiredApprovals = append([]string(nil), out[idx].RequiredApprovals...)
		out[idx].EvidenceRefs = append([]string(nil), out[idx].EvidenceRefs...)
	}
	return out
}

func boundedOutputStrings(values []string, limit int) []string {
	values = uniqueSortedStrings(values)
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]string(nil), values[:limit]...)
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
