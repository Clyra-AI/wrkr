package report

import (
	"fmt"
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	AgentActionBOMPrimarySelectionDefaultTopPath    = "default_top_path"
	AgentActionBOMPrimarySelectionExplicitFocusPath = "explicit_focus_path"
)

type AgentActionBOMPrimaryView struct {
	PathID                    string                          `json:"path_id"`
	SelectionReason           string                          `json:"selection_reason"`
	PathMap                   AgentActionBOMPrimaryPathMap    `json:"path_map"`
	ControlResolutionState    string                          `json:"control_resolution_state,omitempty"`
	ApprovalEvidenceState     string                          `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState        string                          `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState        string                          `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState      string                          `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState       string                          `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState   string                          `json:"credential_evidence_state,omitempty"`
	AutonomyTier              string                          `json:"autonomy_tier,omitempty"`
	DelegationReadinessState  string                          `json:"delegation_readiness_state,omitempty"`
	RecommendedControl        string                          `json:"recommended_control,omitempty"`
	EvidenceCompletenessLabel string                          `json:"evidence_completeness_label,omitempty"`
	EvidenceCompletenessScore int                             `json:"evidence_completeness_score,omitempty"`
	UnresolvedEvidence        []string                        `json:"unresolved_evidence,omitempty"`
	TodayPath                 *risk.GovernedPathView          `json:"today_path,omitempty"`
	RecommendedGovernedPath   *risk.GovernedPathView          `json:"recommended_governed_path,omitempty"`
	RecommendedActionContract *risk.RecommendedActionContract `json:"recommended_action_contract,omitempty"`
	WorkflowChainRefs         []string                        `json:"workflow_chain_refs,omitempty"`
	GraphRefs                 AgentActionBOMGraphRefs         `json:"graph_refs,omitempty"`
	ProofRefs                 []string                        `json:"proof_refs,omitempty"`
	EvidencePacketRefs        []string                        `json:"evidence_packet_refs,omitempty"`
	AppendixRefs              []string                        `json:"appendix_refs,omitempty"`
}

type AgentActionBOMPrimaryPathMap struct {
	Tool       string `json:"tool,omitempty"`
	RepoPR     string `json:"repo_pr,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	Credential string `json:"credential,omitempty"`
	Action     string `json:"action,omitempty"`
	Target     string `json:"target,omitempty"`
}

type agentActionBOMFocusError struct {
	pathID string
	reason string
}

func (e *agentActionBOMFocusError) Error() string {
	if e == nil {
		return ""
	}
	switch e.reason {
	case "missing":
		return fmt.Sprintf("focus path %q was not found in agent_action_bom.items", e.pathID)
	case "ambiguous":
		return fmt.Sprintf("focus path %q matched multiple agent_action_bom items", e.pathID)
	case "context_only":
		return fmt.Sprintf("focus path %q is context-only evidence and cannot drive a focused workflow BOM", e.pathID)
	case "ineligible":
		return fmt.Sprintf("focus path %q is not an eligible workflow BOM path", e.pathID)
	default:
		return fmt.Sprintf("focus path %q is invalid", e.pathID)
	}
}

func IsAgentActionBOMFocusError(err error) bool {
	_, ok := err.(*agentActionBOMFocusError)
	return ok
}

func selectAgentActionBOMPrimaryView(bom *AgentActionBOM, focusPathID string) error {
	if bom == nil {
		return nil
	}

	trimmedFocus := strings.TrimSpace(focusPathID)
	switch {
	case trimmedFocus == "":
		selected := defaultAgentActionBOMPrimaryItem(bom.Items)
		if selected == nil {
			bom.Summary.PrimaryView = nil
			return nil
		}
		bom.Summary.PrimaryView = buildAgentActionBOMPrimaryView(bom, *selected, AgentActionBOMPrimarySelectionDefaultTopPath)
		return nil
	default:
		matches := []AgentActionBOMItem{}
		for _, item := range bom.Items {
			if strings.TrimSpace(item.PathID) == trimmedFocus {
				matches = append(matches, item)
			}
		}
		switch len(matches) {
		case 0:
			return &agentActionBOMFocusError{pathID: trimmedFocus, reason: "missing"}
		case 1:
			if !agentActionBOMItemEligibleForPrimaryView(matches[0]) {
				reason := "ineligible"
				if strings.TrimSpace(matches[0].ConfidenceLane) == risk.ConfidenceLaneContextOnly {
					reason = "context_only"
				}
				return &agentActionBOMFocusError{pathID: trimmedFocus, reason: reason}
			}
			bom.Summary.PrimaryView = buildAgentActionBOMPrimaryView(bom, matches[0], AgentActionBOMPrimarySelectionExplicitFocusPath)
			return nil
		default:
			return &agentActionBOMFocusError{pathID: trimmedFocus, reason: "ambiguous"}
		}
	}
}

func defaultAgentActionBOMPrimaryItem(items []AgentActionBOMItem) *AgentActionBOMItem {
	for idx := range items {
		if agentActionBOMItemEligibleForPrimaryView(items[idx]) {
			return &items[idx]
		}
	}
	return nil
}

func agentActionBOMItemEligibleForPrimaryView(item AgentActionBOMItem) bool {
	if strings.TrimSpace(item.PathID) == "" {
		return false
	}
	if strings.TrimSpace(item.ExclusionReason) != "" {
		return false
	}
	if strings.TrimSpace(item.ConfidenceLane) == risk.ConfidenceLaneContextOnly {
		return false
	}
	return true
}

func buildAgentActionBOMPrimaryView(bom *AgentActionBOM, item AgentActionBOMItem, selectionReason string) *AgentActionBOMPrimaryView {
	view := &AgentActionBOMPrimaryView{
		PathID:                    strings.TrimSpace(item.PathID),
		SelectionReason:           strings.TrimSpace(selectionReason),
		PathMap:                   buildAgentActionBOMPrimaryPathMap(item),
		ControlResolutionState:    strings.TrimSpace(item.ControlResolutionState),
		ApprovalEvidenceState:     strings.TrimSpace(item.ApprovalEvidenceState),
		OwnerEvidenceState:        strings.TrimSpace(item.OwnerEvidenceState),
		ProofEvidenceState:        strings.TrimSpace(item.ProofEvidenceState),
		RuntimeEvidenceState:      strings.TrimSpace(item.RuntimeEvidenceState),
		TargetEvidenceState:       strings.TrimSpace(item.TargetEvidenceState),
		CredentialEvidenceState:   strings.TrimSpace(item.CredentialEvidenceState),
		AutonomyTier:              strings.TrimSpace(item.AutonomyTier),
		DelegationReadinessState:  strings.TrimSpace(item.DelegationReadinessState),
		RecommendedControl:        strings.TrimSpace(item.RecommendedControl),
		UnresolvedEvidence:        primaryViewUnresolvedEvidence(item),
		TodayPath:                 risk.CloneGovernedPathView(item.TodayPath),
		RecommendedGovernedPath:   risk.CloneGovernedPathView(item.RecommendedGovernedPath),
		RecommendedActionContract: risk.CloneRecommendedActionContract(item.RecommendedActionContract),
		WorkflowChainRefs:         cloneStrings(item.WorkflowChainRefs),
		GraphRefs: AgentActionBOMGraphRefs{
			NodeIDs: cloneStrings(item.GraphRefs.NodeIDs),
			EdgeIDs: cloneStrings(item.GraphRefs.EdgeIDs),
		},
		ProofRefs:          cloneStrings(item.ProofRefs),
		EvidencePacketRefs: cloneStrings(item.EvidencePacketRefs),
		AppendixRefs:       primaryViewAppendixRefs(bom, item),
	}
	if item.EvidenceCompleteness != nil {
		view.EvidenceCompletenessLabel = strings.TrimSpace(item.EvidenceCompleteness.Label)
		view.EvidenceCompletenessScore = item.EvidenceCompleteness.TotalScore
	}
	return view
}

func buildAgentActionBOMPrimaryPathMap(item AgentActionBOMItem) AgentActionBOMPrimaryPathMap {
	return AgentActionBOMPrimaryPathMap{
		Tool:       firstNonEmptyValue(strings.TrimSpace(item.AgentID), strings.TrimSpace(item.ToolType)),
		RepoPR:     primaryViewRepoPR(item),
		Workflow:   strings.TrimSpace(item.Location),
		Credential: primaryViewCredential(item),
		Action:     primaryViewAction(item),
		Target:     primaryViewTarget(item),
	}
}

func primaryViewRepoPR(item AgentActionBOMItem) string {
	parts := []string{}
	if repo := strings.TrimSpace(item.Repo); repo != "" {
		parts = append(parts, repo)
	}
	if item.IntroducedBy != nil {
		if ref := strings.TrimSpace(item.IntroducedBy.Reference); ref != "" {
			parts = append(parts, ref)
		}
	}
	return strings.Join(parts, " / ")
}

func primaryViewCredential(item AgentActionBOMItem) string {
	if item.CredentialAuthority != nil {
		parts := []string{}
		if kind := strings.TrimSpace(item.CredentialAuthority.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if target := strings.TrimSpace(item.CredentialAuthority.TargetSystem); target != "" {
			parts = append(parts, target)
		}
		if scope := strings.TrimSpace(item.CredentialAuthority.LikelyScope); scope != "" {
			parts = append(parts, scope)
		}
		switch {
		case item.CredentialAuthority.StandingAccess:
			parts = append(parts, "standing")
		case item.CredentialAuthority.LikelyJIT:
			parts = append(parts, "jit")
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	if item.CredentialProvenance != nil {
		parts := []string{}
		if kind := strings.TrimSpace(item.CredentialProvenance.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if target := strings.TrimSpace(item.CredentialProvenance.TargetSystem); target != "" {
			parts = append(parts, target)
		}
		if scope := strings.TrimSpace(item.CredentialProvenance.LikelyScope); scope != "" {
			parts = append(parts, scope)
		}
		if len(parts) > 0 {
			return strings.Join(parts, " ")
		}
	}
	if item.CredentialAccess {
		return "credential_access_present"
	}
	return "no_visible_credential"
}

func primaryViewAction(item AgentActionBOMItem) string {
	if len(item.ActionClasses) > 0 {
		return strings.Join(uniqueSortedStrings(item.ActionClasses), ",")
	}
	return strings.TrimSpace(item.ActionPathType)
}

func primaryViewTarget(item AgentActionBOMItem) string {
	if len(item.MatchedProductionTargets) > 0 {
		return strings.Join(uniqueSortedStrings(item.MatchedProductionTargets), ",")
	}
	return strings.TrimSpace(item.TargetClass)
}

func primaryViewUnresolvedEvidence(item AgentActionBOMItem) []string {
	out := []string{}
	if item.ApprovalEvidenceState == risk.EvidenceStateUnknown || item.ApprovalEvidenceState == risk.EvidenceStateContradictory {
		out = append(out, "approval")
	}
	if item.OwnerEvidenceState == risk.EvidenceStateUnknown || item.OwnerEvidenceState == risk.EvidenceStateContradictory {
		out = append(out, "owner")
	}
	if item.ProofEvidenceState == risk.EvidenceStateUnknown || item.ProofEvidenceState == risk.EvidenceStateContradictory {
		out = append(out, "proof")
	}
	if item.ControlResolutionState == risk.ControlResolutionStateNoVisibleControl || item.ControlResolutionState == risk.ControlResolutionStateContradictoryControl {
		out = append(out, "control")
	}
	if item.RuntimeEvidenceAbsenceStatus == risk.RuntimeEvidenceAbsenceMissingForClaim || item.RuntimeEvidenceAbsenceStatus == risk.RuntimeEvidenceAbsenceMissingRequired {
		out = append(out, "runtime")
	}
	if state := strings.TrimSpace(item.EvidencePacketMissingEvidenceState); state == "missing" || state == "partial" {
		out = append(out, "evidence_packet")
	}
	return uniqueSortedStrings(out)
}

func primaryViewAppendixRefs(bom *AgentActionBOM, item AgentActionBOMItem) []string {
	refs := []string{"bom_items"}
	if bom != nil && bom.ScanQuality != nil {
		refs = append(refs, "scan_quality", "detector_diagnostics")
	}
	if len(item.GraphRefs.NodeIDs) > 0 || len(item.GraphRefs.EdgeIDs) > 0 {
		refs = append(refs, "graph_refs")
	}
	if len(item.ProofRefs) > 0 || (bom != nil && len(bom.ProofRefs) > 0) {
		refs = append(refs, "proof_refs")
	}
	if len(item.EvidencePacketRefs) > 0 {
		refs = append(refs, "evidence_packets")
	}
	if len(item.WorkflowChainRefs) > 0 {
		refs = append(refs, "workflow_chains")
	}
	return uniqueSortedStrings(refs)
}
