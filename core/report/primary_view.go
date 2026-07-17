package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	AgentActionBOMPrimarySelectionDefaultTopPath    = "default_top_path"
	AgentActionBOMPrimarySelectionExplicitFocusPath = "explicit_focus_path"
)

type AgentActionBOMPrimaryView struct {
	PathID                      string                            `json:"path_id"`
	SelectionReason             string                            `json:"selection_reason"`
	PathMap                     AgentActionBOMPrimaryPathMap      `json:"path_map"`
	ControlResolutionState      string                            `json:"control_resolution_state,omitempty"`
	BoundaryLabel               string                            `json:"boundary_label,omitempty"`
	ApprovalEvidenceState       string                            `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState          string                            `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState          string                            `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState        string                            `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState         string                            `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState     string                            `json:"credential_evidence_state,omitempty"`
	AutonomyTier                string                            `json:"autonomy_tier,omitempty"`
	DelegationReadinessState    string                            `json:"delegation_readiness_state,omitempty"`
	RecommendedControl          string                            `json:"recommended_control,omitempty"`
	RiskTier                    string                            `json:"risk_tier,omitempty"`
	EvidenceCompletenessLabel   string                            `json:"evidence_completeness_label,omitempty"`
	EvidenceCompletenessScore   int                               `json:"evidence_completeness_score,omitempty"`
	UnresolvedEvidence          []string                          `json:"unresolved_evidence,omitempty"`
	RecommendedNextActions      []string                          `json:"recommended_next_actions,omitempty"`
	CoverageStatus              string                            `json:"coverage_status,omitempty"`
	CoverageReasons             []string                          `json:"coverage_reasons,omitempty"`
	CoverageImpact              string                            `json:"coverage_impact,omitempty"`
	TodayPath                   *risk.GovernedPathView            `json:"today_path,omitempty"`
	RecommendedGovernedPath     *risk.GovernedPathView            `json:"recommended_governed_path,omitempty"`
	RecommendedActionContract   *risk.RecommendedActionContract   `json:"recommended_action_contract,omitempty"`
	CompositionID               string                            `json:"composition_id,omitempty"`
	CompositionStageMap         []AgentActionBOMCompositionStage  `json:"composition_stage_map,omitempty"`
	CredentialSummary           string                            `json:"credential_summary,omitempty"`
	DelegationSummary           string                            `json:"delegation_summary,omitempty"`
	TargetSummary               string                            `json:"target_summary,omitempty"`
	CurrentCoverage             string                            `json:"current_coverage,omitempty"`
	ProposedControl             string                            `json:"proposed_control,omitempty"`
	ExpectedOutcome             string                            `json:"expected_outcome,omitempty"`
	ProposedActionContract      *risk.ProposedActionContract      `json:"proposed_action_contract,omitempty"`
	ClosureRequirements         []risk.ClosureRequirement         `json:"closure_requirements,omitempty"`
	AgenticDeliverySystemChange *risk.AgenticDeliverySystemChange `json:"agentic_delivery_system_change,omitempty"`
	RuntimeProvider             string                            `json:"runtime_provider,omitempty"`
	RuntimeHost                 string                            `json:"runtime_host,omitempty"`
	RuntimeKind                 string                            `json:"runtime_kind,omitempty"`
	ModelProvider               string                            `json:"model_provider,omitempty"`
	ModelVersion                string                            `json:"model_version,omitempty"`
	ExecutionEnvironment        string                            `json:"execution_environment,omitempty"`
	StateRetentionStatus        string                            `json:"state_retention_status,omitempty"`
	AgentIdentity               *risk.AgentIdentity               `json:"agent_identity,omitempty"`
	DecisionPrecedent           *risk.DecisionPrecedent           `json:"decision_precedent,omitempty"`
	DeliveryControlContext      *risk.DeliveryControlContext      `json:"delivery_control_context,omitempty"`
	WorkflowChainRefs           []string                          `json:"workflow_chain_refs,omitempty"`
	CompositionIDs              []string                          `json:"composition_ids,omitempty"`
	ProposedActionContractRefs  []string                          `json:"proposed_action_contract_refs,omitempty"`
	GraphRefs                   AgentActionBOMGraphRefs           `json:"graph_refs,omitempty"`
	ProofRefs                   []string                          `json:"proof_refs,omitempty"`
	EvidencePacketRefs          []string                          `json:"evidence_packet_refs,omitempty"`
	DecisionTraceRefs           []string                          `json:"decision_trace_refs,omitempty"`
	AppendixRefs                []string                          `json:"appendix_refs,omitempty"`
}

type AgentActionBOMCompositionStage struct {
	StageID       string   `json:"stage_id"`
	Role          string   `json:"role"`
	PathID        string   `json:"path_id,omitempty"`
	ToolType      string   `json:"tool_type,omitempty"`
	Location      string   `json:"location,omitempty"`
	ActionClasses []string `json:"action_classes,omitempty"`
	TargetClass   string   `json:"target_class,omitempty"`
	EvidenceState string   `json:"evidence_state,omitempty"`
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
	switch trimmedFocus {
	case "":
		selected := defaultAgentActionBOMPrimaryCompositionItem(bom)
		if selected == nil {
			selected = defaultAgentActionBOMPrimaryItem(bom.Items)
		}
		if selected == nil {
			selected = defaultAgentActionBOMPrimaryItem(bom.focusSourceItems)
		}
		if selected == nil {
			bom.Summary.PrimaryView = nil
			return nil
		}
		sourceItem := primaryViewSourceItem(bom, *selected)
		bom.Summary.PrimaryView = buildAgentActionBOMPrimaryView(bom, sourceItem, AgentActionBOMPrimarySelectionDefaultTopPath)
		ensureAgentActionBOMPrimaryItemVisible(bom, sourceItem)
		return nil
	default:
		matches := agentActionBOMItemsByPathID(bom.Items, trimmedFocus)
		if len(matches) == 0 {
			matches = agentActionBOMItemsByPathID(bom.focusSourceItems, trimmedFocus)
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
			sourceItem := primaryViewSourceItem(bom, matches[0])
			bom.Summary.PrimaryView = buildAgentActionBOMPrimaryView(bom, sourceItem, AgentActionBOMPrimarySelectionExplicitFocusPath)
			ensureAgentActionBOMPrimaryItemVisible(bom, sourceItem)
			return nil
		default:
			return &agentActionBOMFocusError{pathID: trimmedFocus, reason: "ambiguous"}
		}
	}
}

func agentActionBOMItemsByPathID(items []AgentActionBOMItem, pathID string) []AgentActionBOMItem {
	trimmedPathID := strings.TrimSpace(pathID)
	if trimmedPathID == "" {
		return nil
	}
	matches := []AgentActionBOMItem{}
	for _, item := range items {
		if strings.TrimSpace(item.PathID) == trimmedPathID {
			matches = append(matches, item)
		}
	}
	return matches
}

func primaryViewSourceItem(bom *AgentActionBOM, item AgentActionBOMItem) AgentActionBOMItem {
	if bom == nil || len(bom.focusSourceItems) == 0 {
		return item
	}
	pathID := strings.TrimSpace(item.PathID)
	if pathID == "" {
		return item
	}
	for _, source := range bom.focusSourceItems {
		if strings.TrimSpace(source.PathID) == pathID {
			return source
		}
	}
	return item
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
	if !bomItemEligible(item) {
		return false
	}
	return bomItemPromotableActionPath(item)
}

func ensureAgentActionBOMPrimaryItemVisible(bom *AgentActionBOM, item AgentActionBOMItem) {
	if bom == nil {
		return
	}
	pathID := strings.TrimSpace(item.PathID)
	if pathID == "" {
		return
	}
	visible := canonicalVisibleAgentActionBOMItem(item)
	for idx := range bom.Items {
		if strings.TrimSpace(bom.Items[idx].PathID) != pathID {
			continue
		}
		bom.Items[idx] = visible
		return
	}
	if len(bom.Items) == 0 {
		bom.Items = []AgentActionBOMItem{visible}
		return
	}
	bom.Items[len(bom.Items)-1] = visible
}

func canonicalVisibleAgentActionBOMItem(item AgentActionBOMItem) AgentActionBOMItem {
	bom := &AgentActionBOM{Items: []AgentActionBOMItem{item}}
	stripped := stripAgentActionBOMCanonicalProjectionDetails(backfillAgentActionBOMCanonicalProjectionRefs(bom))
	if stripped == nil || len(stripped.Items) != 1 {
		return item
	}
	return stripped.Items[0]
}

func buildAgentActionBOMPrimaryView(bom *AgentActionBOM, item AgentActionBOMItem, selectionReason string) *AgentActionBOMPrimaryView {
	view := &AgentActionBOMPrimaryView{
		PathID:                      strings.TrimSpace(item.PathID),
		SelectionReason:             strings.TrimSpace(selectionReason),
		PathMap:                     buildAgentActionBOMPrimaryPathMap(item),
		ControlResolutionState:      strings.TrimSpace(item.ControlResolutionState),
		BoundaryLabel:               strings.TrimSpace(item.BoundaryLabel),
		ApprovalEvidenceState:       strings.TrimSpace(item.ApprovalEvidenceState),
		OwnerEvidenceState:          strings.TrimSpace(item.OwnerEvidenceState),
		ProofEvidenceState:          strings.TrimSpace(item.ProofEvidenceState),
		RuntimeEvidenceState:        strings.TrimSpace(item.RuntimeEvidenceState),
		TargetEvidenceState:         strings.TrimSpace(item.TargetEvidenceState),
		CredentialEvidenceState:     strings.TrimSpace(item.CredentialEvidenceState),
		AutonomyTier:                strings.TrimSpace(item.AutonomyTier),
		DelegationReadinessState:    strings.TrimSpace(item.DelegationReadinessState),
		RecommendedControl:          strings.TrimSpace(item.RecommendedControl),
		RiskTier:                    strings.TrimSpace(item.RiskTier),
		UnresolvedEvidence:          primaryViewUnresolvedEvidence(item),
		RecommendedNextActions:      primaryViewRecommendedNextActions(item),
		TodayPath:                   risk.CloneGovernedPathView(item.TodayPath),
		RecommendedGovernedPath:     risk.CloneGovernedPathView(item.RecommendedGovernedPath),
		RecommendedActionContract:   risk.CloneRecommendedActionContract(item.RecommendedActionContract),
		AgenticDeliverySystemChange: risk.CloneAgenticDeliverySystemChange(item.AgenticDeliverySystemChange),
		RuntimeProvider:             strings.TrimSpace(item.RuntimeProvider),
		RuntimeHost:                 strings.TrimSpace(item.RuntimeHost),
		RuntimeKind:                 strings.TrimSpace(item.RuntimeKind),
		ModelProvider:               strings.TrimSpace(item.ModelProvider),
		ModelVersion:                strings.TrimSpace(item.ModelVersion),
		ExecutionEnvironment:        strings.TrimSpace(item.ExecutionEnvironment),
		StateRetentionStatus:        strings.TrimSpace(item.StateRetentionStatus),
		AgentIdentity:               risk.CloneAgentIdentity(item.AgentIdentity),
		DecisionPrecedent:           risk.CloneDecisionPrecedent(item.DecisionPrecedent),
		DeliveryControlContext:      risk.CloneDeliveryControlContext(item.DeliveryControlContext),
		WorkflowChainRefs:           cloneStrings(item.WorkflowChainRefs),
		CompositionIDs:              cloneStrings(item.CompositionIDs),
		ProposedActionContractRefs:  cloneStrings(item.ProposedActionContractRefs),
		GraphRefs: AgentActionBOMGraphRefs{
			NodeIDs: cloneStrings(item.GraphRefs.NodeIDs),
			EdgeIDs: cloneStrings(item.GraphRefs.EdgeIDs),
		},
		ProofRefs:          cloneStrings(item.ProofRefs),
		EvidencePacketRefs: cloneStrings(item.EvidencePacketRefs),
		DecisionTraceRefs:  cloneStrings(item.DecisionTraceRefs),
		AppendixRefs:       primaryViewAppendixRefs(bom, item),
	}
	if item.EvidenceCompleteness != nil {
		view.EvidenceCompletenessLabel = strings.TrimSpace(item.EvidenceCompleteness.Label)
		view.EvidenceCompletenessScore = item.EvidenceCompleteness.TotalScore
	}
	applyPrimaryViewComposition(view, primaryViewCompositionForItem(bom, item))
	view.CoverageStatus, view.CoverageReasons, view.CoverageImpact = primaryViewCoverage(bom, item)
	return view
}

func defaultAgentActionBOMPrimaryCompositionItem(bom *AgentActionBOM) *AgentActionBOMItem {
	composition := defaultAgentActionBOMPrimaryComposition(bom)
	if composition == nil {
		return nil
	}
	if item := primaryItemForComposition(bom.Items, *composition); item != nil {
		return item
	}
	return primaryItemForComposition(bom.focusSourceItems, *composition)
}

func defaultAgentActionBOMPrimaryComposition(bom *AgentActionBOM) *risk.ComposedActionPath {
	if bom == nil || len(bom.ComposedActionPaths) == 0 {
		return nil
	}
	if len(bom.Items) > 0 && len(bom.ComposedActionPaths) > len(bom.Items) {
		return nil
	}
	candidates := make([]risk.ComposedActionPath, 0, len(bom.ComposedActionPaths))
	for _, composition := range bom.ComposedActionPaths {
		if strings.TrimSpace(composition.CompositionID) == "" {
			continue
		}
		candidates = append(candidates, composition)
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return primaryCompositionLess(candidates[i], candidates[j])
	})
	return &candidates[0]
}

func primaryItemForComposition(items []AgentActionBOMItem, composition risk.ComposedActionPath) *AgentActionBOMItem {
	pathIDs := map[string]struct{}{}
	for _, pathID := range composition.PathIDs {
		if trimmed := strings.TrimSpace(pathID); trimmed != "" {
			pathIDs[trimmed] = struct{}{}
		}
	}
	compositionID := strings.TrimSpace(composition.CompositionID)
	for _, pathID := range uniqueSortedStrings(composition.PathIDs) {
		for idx := range items {
			if strings.TrimSpace(items[idx].PathID) != pathID || !agentActionBOMItemEligibleForPrimaryView(items[idx]) {
				continue
			}
			return &items[idx]
		}
	}
	for idx := range items {
		if !agentActionBOMItemEligibleForPrimaryView(items[idx]) {
			continue
		}
		if _, ok := pathIDs[strings.TrimSpace(items[idx].PathID)]; ok {
			return &items[idx]
		}
		if primaryViewContainsString(items[idx].CompositionIDs, compositionID) {
			return &items[idx]
		}
	}
	return nil
}

func primaryViewContainsString(values []string, want string) bool {
	trimmedWant := strings.TrimSpace(want)
	if trimmedWant == "" {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) == trimmedWant {
			return true
		}
	}
	return false
}

func primaryViewCompositionForItem(bom *AgentActionBOM, item AgentActionBOMItem) *risk.ComposedActionPath {
	if bom == nil || len(bom.ComposedActionPaths) == 0 {
		return nil
	}
	candidates := []risk.ComposedActionPath{}
	itemPathID := strings.TrimSpace(item.PathID)
	itemCompositionIDs := map[string]struct{}{}
	for _, compositionID := range item.CompositionIDs {
		if trimmed := strings.TrimSpace(compositionID); trimmed != "" {
			itemCompositionIDs[trimmed] = struct{}{}
		}
	}
	for _, composition := range bom.ComposedActionPaths {
		compositionID := strings.TrimSpace(composition.CompositionID)
		if _, ok := itemCompositionIDs[compositionID]; ok {
			candidates = append(candidates, composition)
			continue
		}
		for _, pathID := range composition.PathIDs {
			if strings.TrimSpace(pathID) == itemPathID && itemPathID != "" {
				candidates = append(candidates, composition)
				break
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		return primaryCompositionLess(candidates[i], candidates[j])
	})
	return &candidates[0]
}

func primaryCompositionLess(left, right risk.ComposedActionPath) bool {
	if primaryRiskTierRank(left.RiskTier) != primaryRiskTierRank(right.RiskTier) {
		return primaryRiskTierRank(left.RiskTier) < primaryRiskTierRank(right.RiskTier)
	}
	if primaryRecommendedControlRank(left.RecommendedControl) != primaryRecommendedControlRank(right.RecommendedControl) {
		return primaryRecommendedControlRank(left.RecommendedControl) < primaryRecommendedControlRank(right.RecommendedControl)
	}
	if primaryTargetClassRank(left.TargetClass) != primaryTargetClassRank(right.TargetClass) {
		return primaryTargetClassRank(left.TargetClass) < primaryTargetClassRank(right.TargetClass)
	}
	if len(left.ClosureRequirements) != len(right.ClosureRequirements) {
		return len(left.ClosureRequirements) > len(right.ClosureRequirements)
	}
	if strings.TrimSpace(left.PolicyCoverageStatus) != strings.TrimSpace(right.PolicyCoverageStatus) {
		return strings.TrimSpace(left.PolicyCoverageStatus) < strings.TrimSpace(right.PolicyCoverageStatus)
	}
	return strings.TrimSpace(left.CompositionID) < strings.TrimSpace(right.CompositionID)
}

func primaryRiskTierRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.RiskTierCritical:
		return 0
	case risk.RiskTierHigh:
		return 1
	case risk.RiskTierMedium:
		return 2
	case risk.RiskTierLow:
		return 3
	default:
		return 4
	}
}

func primaryRecommendedControlRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.RecommendedControlBlock:
		return 0
	case risk.RecommendedControlBlockStandingCredential:
		return 1
	case risk.RecommendedControlProofRequired:
		return 2
	case risk.RecommendedControlJITCredentialRequired:
		return 3
	case risk.RecommendedControlApprovalRequired:
		return 4
	case risk.RecommendedControlSecurityReview:
		return 5
	case risk.RecommendedControlOwnerReview:
		return 6
	case risk.RecommendedControlAllow:
		return 7
	default:
		return 8
	}
}

func primaryTargetClassRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.TargetClassProductionImpacting:
		return 0
	case risk.TargetClassReleaseAdjacent:
		return 1
	case risk.TargetClassCustomerDataAdjacent:
		return 2
	case risk.TargetClassInternalTooling:
		return 3
	case risk.TargetClassDeveloperProductivity:
		return 4
	case risk.TargetClassTestDemoSandbox:
		return 5
	default:
		return 6
	}
}

func applyPrimaryViewComposition(view *AgentActionBOMPrimaryView, composition *risk.ComposedActionPath) {
	if view == nil || composition == nil {
		return
	}
	view.CompositionID = strings.TrimSpace(composition.CompositionID)
	view.CompositionStageMap = primaryCompositionStageMap(*composition)
	view.CredentialSummary = primaryCompositionCredentialSummary(*composition)
	view.DelegationSummary = primaryCompositionDelegationSummary(*composition)
	view.TargetSummary = primaryCompositionTargetSummary(*composition)
	view.CurrentCoverage = primaryCompositionCoverageSummary(*composition)
	view.ProposedControl = strings.TrimSpace(composition.RecommendedControl)
	view.ExpectedOutcome = firstNonEmptyValue(strings.TrimSpace(composition.OutcomeClass), strings.TrimSpace(composition.DurableOutcomeKey))
	view.ProposedActionContract = risk.CloneProposedActionContract(composition.ProposedActionContract)
	if view.ProposedActionContract != nil && strings.TrimSpace(view.ExpectedOutcome) == "" {
		view.ExpectedOutcome = strings.TrimSpace(view.ProposedActionContract.ExpectedOutcomeClass)
	}
	view.ClosureRequirements = risk.CloneClosureRequirements(composition.ClosureRequirements)
	view.CompositionIDs = uniqueSortedStrings(append(view.CompositionIDs, composition.CompositionID))
	view.WorkflowChainRefs = uniqueSortedStrings(append(view.WorkflowChainRefs, composition.WorkflowChainRefs...))
	view.ProposedActionContractRefs = uniqueSortedStrings(append(view.ProposedActionContractRefs, composition.ProposedActionContractRefs...))
	view.ProofRefs = uniqueSortedStrings(append(view.ProofRefs, composition.ProofRefs...))
}

func primaryCompositionStageMap(composition risk.ComposedActionPath) []AgentActionBOMCompositionStage {
	if len(composition.Stages) == 0 {
		return nil
	}
	out := make([]AgentActionBOMCompositionStage, 0, len(composition.Stages))
	for _, stage := range composition.Stages {
		out = append(out, AgentActionBOMCompositionStage{
			StageID:       strings.TrimSpace(stage.StageID),
			Role:          strings.TrimSpace(stage.Role),
			PathID:        strings.TrimSpace(stage.PathID),
			ToolType:      strings.TrimSpace(stage.ToolType),
			Location:      strings.TrimSpace(stage.Location),
			ActionClasses: uniqueSortedStrings(stage.ActionClasses),
			TargetClass:   strings.TrimSpace(stage.TargetClass),
			EvidenceState: strings.TrimSpace(stage.EvidenceState),
		})
	}
	return out
}

func primaryCompositionCredentialSummary(composition risk.ComposedActionPath) string {
	if composition.ProposedActionContract != nil {
		if mode := strings.TrimSpace(composition.ProposedActionContract.RequiredCredentialMode); mode != "" {
			return mode
		}
	}
	for _, stage := range composition.Stages {
		for _, actionClass := range stage.ActionClasses {
			if strings.Contains(strings.ToLower(strings.TrimSpace(actionClass)), "credential") || strings.Contains(strings.ToLower(strings.TrimSpace(actionClass)), "secret") {
				return strings.TrimSpace(actionClass)
			}
		}
	}
	return ""
}

func primaryCompositionDelegationSummary(composition risk.ComposedActionPath) string {
	if composition.ProposedActionContract != nil && composition.ProposedActionContract.MaximumDelegationDepth > 0 {
		return fmt.Sprintf("max_delegation_depth=%d", composition.ProposedActionContract.MaximumDelegationDepth)
	}
	return ""
}

func primaryCompositionTargetSummary(composition risk.ComposedActionPath) string {
	return strings.Join(uniqueSortedStrings([]string{
		strings.TrimSpace(composition.AffectedAsset),
		strings.TrimSpace(composition.TargetIdentity),
		strings.TrimSpace(composition.TargetClass),
	}), " ")
}

func primaryCompositionCoverageSummary(composition risk.ComposedActionPath) string {
	parts := []string{}
	if policy := strings.TrimSpace(composition.PolicyCoverageStatus); policy != "" {
		parts = append(parts, "policy="+policy)
	}
	if evidence := strings.TrimSpace(composition.EvidenceState); evidence != "" {
		parts = append(parts, "evidence="+evidence)
	}
	if absence := strings.TrimSpace(composition.RuntimeEvidenceAbsenceStatus); absence != "" {
		parts = append(parts, "runtime="+absence)
	}
	if composition.GaitCoverage != nil {
		if status := strings.TrimSpace(composition.GaitCoverage.PolicyDecision.Status); status != "" {
			parts = append(parts, "gait_policy_decision="+status)
		}
		if status := strings.TrimSpace(composition.GaitCoverage.ActionOutcome.Status); status != "" {
			parts = append(parts, "gait_action_outcome="+status)
		}
	}
	return strings.Join(uniqueSortedStrings(parts), " ")
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
		switch {
		case item.CredentialProvenance.StandingAccess:
			parts = append(parts, "standing")
		case item.CredentialProvenance.LikelyJIT:
			parts = append(parts, "jit")
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
	if len(item.RecommendedNextAction) > 0 || item.RecommendedActionContract != nil {
		refs = append(refs, "recommended_actions")
	}
	if len(item.ClosureActions) > 0 {
		refs = append(refs, "closure_actions")
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
	if len(item.DecisionTraceRefs) > 0 {
		refs = append(refs, "decision_traces")
	}
	return uniqueSortedStrings(refs)
}

func primaryViewRecommendedNextActions(item AgentActionBOMItem) []string {
	actions := make([]string, 0, 4)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		actions = append(actions, value)
	}

	if action := blockedStandingCredentialNextAction(item); action != "" {
		add(action)
	}
	if item.RecommendedActionContract != nil {
		add(item.RecommendedActionContract.RequiredApproval)
		add(item.RecommendedActionContract.RequiredProof)
		add(item.RecommendedActionContract.RequiredAuthority)
		add(item.RecommendedActionContract.ValidationStep)
	}
	for _, action := range item.ClosureActions {
		add(action.Title)
	}
	if len(actions) == 0 {
		add(firstSentence(item.Remediation))
	}
	actions = uniquePreserveOrderStrings(actions)
	if len(actions) > 3 {
		actions = append([]string(nil), actions[:3]...)
	}
	return actions
}

func uniquePreserveOrderStrings(values []string) []string {
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
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func primaryViewCoverage(bom *AgentActionBOM, item AgentActionBOMItem) (string, []string, string) {
	if bom == nil || bom.ScanQuality == nil {
		return scanquality.AbsenceStatusNotScanned, []string{"scan_quality:unavailable"}, "Coverage metadata was unavailable; negative claims remain scoped to available evidence."
	}

	org := strings.TrimSpace(item.Org)
	repo := strings.TrimSpace(item.Repo)
	if primaryViewUsesMCPQualifiedCoverage(item) {
		if claim := primaryViewRepoAbsenceClaim(bom.ScanQuality, org, repo); claim != nil {
			return primaryViewCoverageStatusFromAbsence(claim.Status), cloneStrings(claim.Reasons), firstNonEmptyValue(strings.TrimSpace(claim.Impact), "Coverage metadata was unavailable; negative claims remain scoped to available evidence.")
		}
	}

	signals := scanquality.CompletenessSignalsForRepo(bom.ScanQuality, org, repo)
	if signals.ReducedCoverage {
		impact := scanquality.BuildCompactCoverageSummary(bom.ScanQuality).ImpactStatement
		return scanquality.CoverageConfidenceReduced, cloneStrings(signals.Reasons), impact
	}
	if primaryViewRepoHasCoverageData(bom.ScanQuality, org, repo) {
		impact := scanquality.BuildCompactCoverageSummary(bom.ScanQuality).ImpactStatement
		return scanquality.CoverageConfidenceComplete, nil, impact
	}
	return scanquality.AbsenceStatusNotScanned, []string{"scan_quality:unavailable"}, "Coverage metadata was unavailable; negative claims remain scoped to available evidence."
}

func primaryViewUsesMCPQualifiedCoverage(item AgentActionBOMItem) bool {
	toolType := strings.ToLower(strings.TrimSpace(item.ToolType))
	if strings.Contains(toolType, "mcp") {
		return true
	}
	return len(item.ReachableServers) > 0 || len(item.ReachableAPIs) > 0
}

func primaryViewRepoAbsenceClaim(report *scanquality.Report, org string, repo string) *scanquality.AbsenceClaim {
	if report == nil {
		return nil
	}
	var selected *scanquality.AbsenceClaim
	for _, claim := range report.AbsenceClaims {
		if strings.TrimSpace(claim.Surface) != scanquality.SurfaceMCPServer {
			continue
		}
		if strings.TrimSpace(claim.Org) != strings.TrimSpace(org) || strings.TrimSpace(claim.Repo) != strings.TrimSpace(repo) {
			continue
		}
		if selected == nil || primaryViewCoverageStatusRank(claim.Status) < primaryViewCoverageStatusRank(selected.Status) {
			copyClaim := claim
			selected = &copyClaim
		}
	}
	return selected
}

func primaryViewRepoHasCoverageData(report *scanquality.Report, org string, repo string) bool {
	if report == nil {
		return false
	}
	for _, detector := range report.Detectors {
		if strings.TrimSpace(detector.Org) == strings.TrimSpace(org) && strings.TrimSpace(detector.Repo) == strings.TrimSpace(repo) {
			return true
		}
	}
	for _, issue := range report.ParseErrors {
		if strings.TrimSpace(issue.Org) == strings.TrimSpace(org) && strings.TrimSpace(issue.Repo) == strings.TrimSpace(repo) {
			return true
		}
	}
	for _, claim := range report.AbsenceClaims {
		if strings.TrimSpace(claim.Org) == strings.TrimSpace(org) && strings.TrimSpace(claim.Repo) == strings.TrimSpace(repo) {
			return true
		}
	}
	return false
}

func primaryViewCoverageStatusFromAbsence(status string) string {
	switch strings.TrimSpace(status) {
	case scanquality.AbsenceStatusUnsupportedSurface:
		return scanquality.AbsenceStatusUnsupportedSurface
	case scanquality.AbsenceStatusNotScanned:
		return scanquality.AbsenceStatusNotScanned
	case scanquality.AbsenceStatusNotFoundCompleteCoverage:
		return scanquality.CoverageConfidenceComplete
	default:
		return scanquality.CoverageConfidenceReduced
	}
}

func primaryViewCoverageStatusRank(status string) int {
	switch strings.TrimSpace(status) {
	case scanquality.AbsenceStatusNotScanned:
		return 0
	case scanquality.AbsenceStatusCandidateParseFailed:
		return 1
	case scanquality.AbsenceStatusUnsupportedSurface:
		return 2
	case scanquality.AbsenceStatusNotFoundReducedCoverage:
		return 3
	case scanquality.AbsenceStatusNotFoundCompleteCoverage:
		return 4
	default:
		return 5
	}
}

func firstSentence(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, sep := range []string{". ", ".\n"} {
		if idx := strings.Index(value, sep); idx >= 0 {
			return strings.TrimSpace(value[:idx+1])
		}
	}
	return value
}
