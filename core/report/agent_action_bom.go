package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	scorecore "github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
)

const AgentActionBOMSchemaVersion = "v1"

type AgentActionBOM struct {
	BOMID                string                  `json:"bom_id"`
	SchemaVersion        string                  `json:"schema_version"`
	GeneratedAt          string                  `json:"generated_at"`
	ShareProfile         string                  `json:"share_profile,omitempty"`
	ShareProfileMetadata *ShareProfileMetadata   `json:"share_profile_metadata,omitempty"`
	Summary              AgentActionBOMSummary   `json:"summary"`
	ScanQuality          *scanquality.Report     `json:"scan_quality,omitempty"`
	Items                []AgentActionBOMItem    `json:"items,omitempty"`
	GraphRefs            AgentActionBOMGraphRefs `json:"graph_refs,omitempty"`
	EvidenceRefs         []string                `json:"evidence_refs,omitempty"`
	ProofRefs            []string                `json:"proof_refs,omitempty"`
}

type AgentActionBOMSummary struct {
	TotalItems                   int                     `json:"total_items"`
	ControlFirstItems            int                     `json:"control_first_items"`
	StandingPrivilegeItems       int                     `json:"standing_privilege_items"`
	StaticCredentialItems        int                     `json:"static_credential_items"`
	ProductionTargetItems        int                     `json:"production_target_items"`
	ApprovalEvidenceUnknownItems int                     `json:"approval_evidence_unknown_items,omitempty"`
	ControlEvidenceUnknownItems  int                     `json:"control_evidence_unknown_items,omitempty"`
	OwnerEvidenceUnknownItems    int                     `json:"owner_evidence_unknown_items,omitempty"`
	ProofEvidenceUnknownItems    int                     `json:"proof_evidence_unknown_items,omitempty"`
	MissingApprovalItems         int                     `json:"missing_approval_items"`
	MissingPolicyItems           int                     `json:"missing_policy_items"`
	MissingProofItems            int                     `json:"missing_proof_items"`
	RuntimeProvenItems           int                     `json:"runtime_proven_items"`
	UnresolvedOwnerItems         int                     `json:"unresolved_owner_items"`
	ConfirmedActionPathItems     int                     `json:"confirmed_action_path_items,omitempty"`
	LikelyActionPathItems        int                     `json:"likely_action_path_items,omitempty"`
	SemanticReviewCandidateItems int                     `json:"semantic_review_candidate_items,omitempty"`
	ContextOnlyItems             int                     `json:"context_only_items,omitempty"`
	EmptyStateStatus             string                  `json:"empty_state_status,omitempty"`
	EmptyStateReasons            []string                `json:"empty_state_reasons,omitempty"`
	ScanScope                    *ScanScopeSummary       `json:"scan_scope,omitempty"`
	SourcePrivacy                *sourceprivacy.Contract `json:"source_privacy,omitempty"`
	OperationalExposure          *scorecore.AxisSummary  `json:"operational_exposure,omitempty"`
	GovernanceReadiness          *scorecore.AxisSummary  `json:"governance_readiness,omitempty"`
	CoverageConfidence           string                  `json:"coverage_confidence,omitempty"`
}

type AgentActionBOMItem struct {
	PathID                   string                                 `json:"path_id"`
	AgentID                  string                                 `json:"agent_id,omitempty"`
	ToolFamilyID             string                                 `json:"tool_family_id,omitempty"`
	ToolInstanceID           string                                 `json:"tool_instance_id,omitempty"`
	Org                      string                                 `json:"org"`
	Repo                     string                                 `json:"repo"`
	ToolType                 string                                 `json:"tool_type"`
	Location                 string                                 `json:"location,omitempty"`
	Purpose                  string                                 `json:"purpose,omitempty"`
	PurposeSource            string                                 `json:"purpose_source,omitempty"`
	PurposeConfidence        string                                 `json:"purpose_confidence,omitempty"`
	Version                  string                                 `json:"version,omitempty"`
	VersionSource            string                                 `json:"version_source,omitempty"`
	ConfigFingerprint        string                                 `json:"config_fingerprint,omitempty"`
	ConfigSource             string                                 `json:"config_source,omitempty"`
	Owner                    string                                 `json:"owner,omitempty"`
	OwnerSource              string                                 `json:"owner_source,omitempty"`
	OwnershipStatus          string                                 `json:"ownership_status,omitempty"`
	OwnershipState           string                                 `json:"ownership_state,omitempty"`
	ControlResolutionState   string                                 `json:"control_resolution_state,omitempty"`
	ControlResolutionReasons []string                               `json:"control_resolution_reasons,omitempty"`
	ControlEvidenceRefs      []string                               `json:"control_evidence_refs,omitempty"`
	ApprovalEvidenceState    string                                 `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState       string                                 `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState       string                                 `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState     string                                 `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState      string                                 `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState  string                                 `json:"credential_evidence_state,omitempty"`
	CredentialAccess         bool                                   `json:"credential_access"`
	Credentials              []*agginventory.CredentialProvenance   `json:"credentials,omitempty"`
	CredentialProvenance     *agginventory.CredentialProvenance     `json:"credential_provenance,omitempty"`
	CredentialAuthority      *agginventory.CredentialAuthority      `json:"credential_authority,omitempty"`
	PathContext              *agginventory.PathContext              `json:"path_context,omitempty"`
	StandingPrivilege        bool                                   `json:"standing_privilege,omitempty"`
	StandingPrivilegeReasons []string                               `json:"standing_privilege_reasons,omitempty"`
	ControlState             string                                 `json:"control_state,omitempty"`
	ControlStateReasons      []string                               `json:"control_state_reasons,omitempty"`
	RiskZone                 string                                 `json:"risk_zone,omitempty"`
	RiskZoneReasons          []string                               `json:"risk_zone_reasons,omitempty"`
	ReviewBurden             string                                 `json:"review_burden,omitempty"`
	ReviewBurdenReasons      []string                               `json:"review_burden_reasons,omitempty"`
	ConfidenceLane           string                                 `json:"confidence_lane,omitempty"`
	ConfidenceLaneReasons    []string                               `json:"confidence_lane_reasons,omitempty"`
	ActionClasses            []string                               `json:"action_classes,omitempty"`
	ActionReasons            []string                               `json:"action_reasons,omitempty"`
	MutableEndpointSemantics []agginventory.MutableEndpointSemantic `json:"mutable_endpoint_semantics,omitempty"`
	ProductionWrite          bool                                   `json:"production_write,omitempty"`
	ProductionTargetStatus   string                                 `json:"production_target_status,omitempty"`
	MatchedProductionTargets []string                               `json:"matched_production_targets,omitempty"`
	ApprovalGap              bool                                   `json:"approval_gap"`
	ApprovalGapReasons       []string                               `json:"approval_gap_reasons,omitempty"`
	PolicyStatus             string                                 `json:"policy_status,omitempty"`
	PolicyRefs               []string                               `json:"policy_refs,omitempty"`
	PolicyMissingReasons     []string                               `json:"policy_missing_reasons,omitempty"`
	PolicyStatusReasons      []string                               `json:"policy_status_reasons,omitempty"`
	PolicyConfidence         string                                 `json:"policy_confidence,omitempty"`
	PolicyEvidenceRefs       []string                               `json:"policy_evidence_refs,omitempty"`
	ProofCoverage            string                                 `json:"proof_coverage,omitempty"`
	ProofRefs                []string                               `json:"proof_refs,omitempty"`
	RuntimeEvidenceStatus    string                                 `json:"runtime_evidence_status,omitempty"`
	RuntimeEvidenceClasses   []string                               `json:"runtime_evidence_classes,omitempty"`
	RuntimeEvidenceRefs      []string                               `json:"runtime_evidence_refs,omitempty"`
	GaitCoverage             *risk.GaitCoverage                     `json:"gait_coverage,omitempty"`
	Confidence               string                                 `json:"confidence,omitempty"`
	EvidenceStrength         string                                 `json:"evidence_strength,omitempty"`
	InventoryRisk            string                                 `json:"inventory_risk,omitempty"`
	ControlPriority          string                                 `json:"control_priority,omitempty"`
	RiskTier                 string                                 `json:"risk_tier,omitempty"`
	RecommendedNextAction    string                                 `json:"recommended_next_action,omitempty"`
	Queue                    string                                 `json:"queue,omitempty"`
	FindingVisibility        string                                 `json:"finding_visibility,omitempty"`
	Remediation              string                                 `json:"remediation,omitempty"`
	AttackPathRefs           []string                               `json:"attack_path_refs,omitempty"`
	SourceFindingKeys        []string                               `json:"source_finding_keys,omitempty"`
	ExclusionReason          string                                 `json:"exclusion_reason,omitempty"`
	GraphRefs                AgentActionBOMGraphRefs                `json:"graph_refs,omitempty"`
	EvidenceRefs             []string                               `json:"evidence_refs,omitempty"`
	Reachability             []AgentActionBOMReachability           `json:"reachability,omitempty"`
	ReachableServers         []AgentActionBOMReachability           `json:"reachable_servers,omitempty"`
	ReachableTools           []AgentActionBOMReachability           `json:"reachable_tools,omitempty"`
	ReachableEndpoints       []AgentActionBOMReachability           `json:"reachable_endpoints,omitempty"`
	ReachableTargets         []AgentActionBOMReachability           `json:"reachable_targets,omitempty"`
	ReachableAPIs            []AgentActionBOMReachability           `json:"reachable_apis,omitempty"`
	ReachableAgents          []AgentActionBOMReachability           `json:"reachable_agents,omitempty"`
	IntroducedBy             *attribution.Result                    `json:"introduced_by,omitempty"`
	ActionLineage            *risk.ActionLineage                    `json:"action_lineage,omitempty"`
}

type AgentActionBOMGraphRefs struct {
	NodeIDs []string `json:"node_ids,omitempty"`
	EdgeIDs []string `json:"edge_ids,omitempty"`
}

type AgentActionBOMReachability struct {
	Surface      string                   `json:"surface"`
	Name         string                   `json:"name,omitempty"`
	Capabilities []string                 `json:"capabilities,omitempty"`
	TrustDepth   *agginventory.TrustDepth `json:"trust_depth,omitempty"`
	EvidenceRefs []string                 `json:"evidence_refs,omitempty"`
}

type pathProofCoverage struct {
	Status string
}

const (
	proofCoverageCovered       = "covered"
	proofCoverageMissing       = "missing"
	proofCoverageChainAttached = "chain_attached"
)

func BuildAgentActionBOM(summary Summary) *AgentActionBOM {
	return buildAgentActionBOM(summary, nil)
}

func buildAgentActionBOM(summary Summary, findings []model.Finding) *AgentActionBOM {
	if len(summary.ActionPaths) == 0 {
		return nil
	}

	backlogByPath := backlogItemsByPath(summary.ControlBacklog)
	graphRefsByPath, graphRefs := controlPathGraphRefs(summary.ControlPathGraph)
	runtimeByPath := runtimeEvidenceByPath(summary.RuntimeEvidence)
	reachabilityByPath := reachabilityByPathID(summary.ActionPaths, findings)
	signalsByPath := pathSignalsByPathID(summary.ActionPaths, findings)
	proofCoverageByPath := proofCoverageByPath(summary.ActionPaths, summary.controlProofStatus)
	globalProofRefs := proofRefs(summary.Proof)

	items := make([]AgentActionBOMItem, 0, len(summary.ActionPaths))
	for _, path := range summary.ActionPaths {
		path = risk.ProjectActionPath(path)
		pathID := strings.TrimSpace(path.PathID)
		itemGraphRefs := graphRefsByPath[pathID]
		runtimeItem := runtimeByPath[pathID]
		backlogItem := backlogByPath[pathID]
		reachability := append([]AgentActionBOMReachability(nil), reachabilityByPath[pathID]...)
		reachableServers, reachableTools, reachableEndpoints, reachableTargets, reachableAPIs, reachableAgents := namedReachability(reachability)
		proofCoverage := fallbackProofCoverage(summary.Proof)
		if coverage, ok := proofCoverageByPath[pathID]; ok {
			proofCoverage = coverage.Status
		}
		policyStatus := firstNonEmptyValue(path.PolicyCoverageStatus, risk.PolicyCoverageStatusNone)
		switch strings.TrimSpace(runtimeItem.Status) {
		case ingest.CorrelationStatusMatched:
			if containsEvidenceClass(runtimeItem.EvidenceClasses, ingest.EvidenceClassPolicyDecision) {
				policyStatus = risk.PolicyCoverageStatusRuntimeProven
			}
		case ingest.CorrelationStatusConflict:
			policyStatus = risk.PolicyCoverageStatusConflict
		case ingest.CorrelationStatusStale:
			policyStatus = risk.PolicyCoverageStatusStale
		}
		signal := signalsByPath[pathID]
		item := AgentActionBOMItem{
			PathID:                   pathID,
			AgentID:                  strings.TrimSpace(path.AgentID),
			ToolFamilyID:             strings.TrimSpace(path.ToolFamilyID),
			ToolInstanceID:           strings.TrimSpace(path.ToolInstanceID),
			Org:                      strings.TrimSpace(path.Org),
			Repo:                     strings.TrimSpace(path.Repo),
			ToolType:                 strings.TrimSpace(path.ToolType),
			Location:                 strings.TrimSpace(path.Location),
			Purpose:                  strings.TrimSpace(path.Purpose),
			PurposeSource:            strings.TrimSpace(path.PurposeSource),
			PurposeConfidence:        strings.TrimSpace(path.PurposeConfidence),
			Version:                  strings.TrimSpace(path.Version),
			VersionSource:            strings.TrimSpace(path.VersionSource),
			ConfigFingerprint:        strings.TrimSpace(path.ConfigFingerprint),
			ConfigSource:             strings.TrimSpace(path.ConfigSource),
			Owner:                    strings.TrimSpace(path.OperationalOwner),
			OwnerSource:              strings.TrimSpace(path.OwnerSource),
			OwnershipStatus:          strings.TrimSpace(path.OwnershipStatus),
			OwnershipState:           strings.TrimSpace(path.OwnershipState),
			ControlResolutionState:   strings.TrimSpace(path.ControlResolutionState),
			ControlResolutionReasons: append([]string(nil), path.ControlResolutionReasons...),
			ControlEvidenceRefs:      append([]string(nil), path.ControlEvidenceRefs...),
			ApprovalEvidenceState:    strings.TrimSpace(path.ApprovalEvidenceState),
			OwnerEvidenceState:       strings.TrimSpace(path.OwnerEvidenceState),
			ProofEvidenceState:       strings.TrimSpace(path.ProofEvidenceState),
			RuntimeEvidenceState:     strings.TrimSpace(path.RuntimeEvidenceState),
			TargetEvidenceState:      strings.TrimSpace(path.TargetEvidenceState),
			CredentialEvidenceState:  strings.TrimSpace(path.CredentialEvidenceState),
			CredentialAccess:         path.CredentialAccess,
			Credentials:              agginventory.CloneCredentialProvenances(path.Credentials),
			CredentialProvenance:     agginventory.CloneCredentialProvenance(path.CredentialProvenance),
			CredentialAuthority:      agginventory.CloneCredentialAuthority(path.CredentialAuthority),
			PathContext:              agginventory.ClonePathContext(path.PathContext),
			StandingPrivilege:        path.StandingPrivilege,
			StandingPrivilegeReasons: append([]string(nil), path.StandingPrivilegeReasons...),
			ControlState:             strings.TrimSpace(path.ControlState),
			ControlStateReasons:      append([]string(nil), path.ControlStateReasons...),
			RiskZone:                 strings.TrimSpace(path.RiskZone),
			RiskZoneReasons:          append([]string(nil), path.RiskZoneReasons...),
			ReviewBurden:             strings.TrimSpace(path.ReviewBurden),
			ReviewBurdenReasons:      append([]string(nil), path.ReviewBurdenReasons...),
			ConfidenceLane:           strings.TrimSpace(path.ConfidenceLane),
			ConfidenceLaneReasons:    append([]string(nil), path.ConfidenceLaneReasons...),
			ActionClasses:            append([]string(nil), path.ActionClasses...),
			ActionReasons:            append([]string(nil), path.ActionReasons...),
			MutableEndpointSemantics: agginventory.CloneMutableEndpointSemantics(path.MutableEndpointSemantics),
			ProductionWrite:          path.ProductionWrite,
			ProductionTargetStatus:   strings.TrimSpace(path.ProductionTargetStatus),
			MatchedProductionTargets: append([]string(nil), path.MatchedProductionTargets...),
			ApprovalGap:              path.ApprovalGap,
			ApprovalGapReasons:       append([]string(nil), path.ApprovalGapReasons...),
			PolicyStatus:             policyStatus,
			ProofCoverage:            proofCoverage,
			ProofRefs:                proofRefsForPath(path, summary.controlProofStatus),
			RuntimeEvidenceStatus:    runtimeItem.Status,
			RuntimeEvidenceClasses:   append([]string(nil), runtimeItem.EvidenceClasses...),
			RuntimeEvidenceRefs:      append([]string(nil), runtimeItem.RecordIDs...),
			GaitCoverage:             risk.CloneGaitCoverage(path.GaitCoverage),
			Confidence:               signal.Confidence,
			EvidenceStrength:         signal.EvidenceStrength,
			InventoryRisk:            inventoryRiskForPath(path),
			ControlPriority:          controlPriorityForPath(path),
			RiskTier:                 riskTierForPath(path),
			RecommendedNextAction:    strings.TrimSpace(path.RecommendedAction),
			Queue:                    firstNonEmptyValue(strings.TrimSpace(backlogItem.Queue), queueForControlPriority(controlPriorityForPath(path))),
			FindingVisibility:        firstNonEmptyValue(strings.TrimSpace(backlogItem.FindingVisibility), visibilityForQueue(firstNonEmptyValue(strings.TrimSpace(backlogItem.Queue), queueForControlPriority(controlPriorityForPath(path))))),
			Remediation:              firstNonEmptyValue(strings.TrimSpace(backlogItem.Remediation), risk.RemediationForActionPath(path)),
			AttackPathRefs:           append([]string(nil), path.AttackPathRefs...),
			SourceFindingKeys:        append([]string(nil), path.SourceFindingKeys...),
			GraphRefs:                itemGraphRefs,
			Reachability:             reachability,
			ReachableServers:         reachableServers,
			ReachableTools:           reachableTools,
			ReachableEndpoints:       reachableEndpoints,
			ReachableTargets:         reachableTargets,
			ReachableAPIs:            reachableAPIs,
			ReachableAgents:          reachableAgents,
			PolicyRefs:               append([]string(nil), path.PolicyRefs...),
			PolicyMissingReasons:     append([]string(nil), path.PolicyMissingReasons...),
			PolicyStatusReasons:      append([]string(nil), path.PolicyStatusReasons...),
			PolicyConfidence:         strings.TrimSpace(path.PolicyConfidence),
			PolicyEvidenceRefs:       append([]string(nil), path.PolicyEvidenceRefs...),
			IntroducedBy:             attribution.Merge(path.IntroducedBy, nil),
			ActionLineage:            risk.CloneActionLineage(path.ActionLineage),
		}
		switch proofCoverage {
		case proofCoverageCovered:
			if item.ProofEvidenceState != risk.EvidenceStateContradictory {
				if len(item.ProofRefs) > 0 {
					item.ProofEvidenceState = risk.EvidenceStateVerified
				} else {
					item.ProofEvidenceState = risk.EvidenceStateInferred
				}
			}
		case proofCoverageChainAttached:
			if strings.TrimSpace(item.ProofEvidenceState) == "" {
				item.ProofEvidenceState = risk.EvidenceStateInferred
			}
		case proofCoverageMissing:
			if strings.TrimSpace(item.ProofEvidenceState) == "" {
				item.ProofEvidenceState = risk.EvidenceStateUnknown
			}
		}
		item.ActionLineage = decorateLineageForBOM(item.ActionLineage, item)
		item.EvidenceRefs = itemEvidenceRefs(path, backlogItem, runtimeItem, itemGraphRefs)
		items = append(items, item)
	}
	items = append(items, excludedTopAttackPathItems(summary)...)
	counts := summarizeAgentActionBOMItems(items, summary.ActionPaths, summary.ScanQuality)
	counts.ScanScope = cloneScanScope(summary.ScanScope)
	counts.SourcePrivacy = normalizedSourcePrivacy(summary.SourcePrivacy)
	counts.OperationalExposure = cloneAxisSummary(summary.OperationalExposure)
	counts.GovernanceReadiness = cloneAxisSummary(summary.GovernanceReadiness)
	counts.CoverageConfidence = coverageConfidenceLabel(summary.ScanQuality)

	return &AgentActionBOM{
		BOMID:                agentActionBOMID(summary, items),
		SchemaVersion:        AgentActionBOMSchemaVersion,
		GeneratedAt:          summary.GeneratedAt,
		ShareProfile:         summary.ShareProfile,
		ShareProfileMetadata: cloneShareProfileMetadata(summary.ShareProfileMetadata),
		Summary:              counts,
		ScanQuality:          cloneScanQualityReport(summary.ScanQuality),
		Items:                items,
		GraphRefs:            graphRefs,
		EvidenceRefs:         summaryEvidenceRefs(items),
		ProofRefs:            globalProofRefs,
	}
}

func buildAgentActionBOMFromSnapshot(summary Summary, snapshot state.Snapshot) *AgentActionBOM {
	return buildAgentActionBOM(summary, snapshot.Findings)
}

func agentActionBOMID(summary Summary, items []AgentActionBOMItem) string {
	parts := []string{SummaryVersion, strings.TrimSpace(summary.Proof.HeadHash)}
	for _, item := range items {
		parts = append(parts, strings.TrimSpace(item.PathID), strings.TrimSpace(item.Org), strings.TrimSpace(item.Repo))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "bom-" + hex.EncodeToString(sum[:6])
}

func backlogItemsByPath(backlog *controlbacklog.Backlog) map[string]controlbacklog.Item {
	out := map[string]controlbacklog.Item{}
	if backlog == nil {
		return out
	}
	for _, item := range backlog.Items {
		if strings.TrimSpace(item.LinkedActionPathID) == "" {
			continue
		}
		out[strings.TrimSpace(item.LinkedActionPathID)] = item
	}
	return out
}

func controlPathGraphRefs(graph *aggattack.ControlPathGraph) (map[string]AgentActionBOMGraphRefs, AgentActionBOMGraphRefs) {
	byPath := map[string]AgentActionBOMGraphRefs{}
	if graph == nil {
		return byPath, AgentActionBOMGraphRefs{}
	}
	all := AgentActionBOMGraphRefs{}
	for _, node := range graph.Nodes {
		key := strings.TrimSpace(node.PathID)
		item := byPath[key]
		item.NodeIDs = append(item.NodeIDs, strings.TrimSpace(node.NodeID))
		byPath[key] = item
		all.NodeIDs = append(all.NodeIDs, strings.TrimSpace(node.NodeID))
	}
	for _, edge := range graph.Edges {
		key := strings.TrimSpace(edge.PathID)
		item := byPath[key]
		item.EdgeIDs = append(item.EdgeIDs, strings.TrimSpace(edge.EdgeID))
		byPath[key] = item
		all.EdgeIDs = append(all.EdgeIDs, strings.TrimSpace(edge.EdgeID))
	}
	for key, refs := range byPath {
		refs.NodeIDs = uniqueSortedStrings(refs.NodeIDs)
		refs.EdgeIDs = uniqueSortedStrings(refs.EdgeIDs)
		byPath[key] = refs
	}
	all.NodeIDs = uniqueSortedStrings(all.NodeIDs)
	all.EdgeIDs = uniqueSortedStrings(all.EdgeIDs)
	return byPath, all
}

func runtimeEvidenceByPath(summary *ingest.Summary) map[string]ingest.Correlation {
	out := map[string]ingest.Correlation{}
	if summary == nil {
		return out
	}
	for _, item := range summary.Correlations {
		if strings.TrimSpace(item.PathID) == "" {
			continue
		}
		out[strings.TrimSpace(item.PathID)] = item
	}
	return out
}

func proofRefs(proof ProofReference) []string {
	refs := []string{}
	if strings.TrimSpace(proof.HeadHash) != "" {
		refs = append(refs, "proof_head:"+strings.TrimSpace(proof.HeadHash))
	}
	if strings.TrimSpace(proof.ChainPath) != "" {
		refs = append(refs, "proof_chain:"+strings.TrimSpace(proof.ChainPath))
	}
	for _, key := range proof.CanonicalFindingKeys {
		refs = append(refs, "finding:"+strings.TrimSpace(key))
	}
	return uniqueSortedStrings(refs)
}

func fallbackProofCoverage(proof ProofReference) string {
	if strings.TrimSpace(proof.HeadHash) == "" {
		return proofCoverageMissing
	}
	return proofCoverageChainAttached
}

func proofCoverageByPath(paths []risk.ActionPath, statuses []ControlProofStatus) map[string]pathProofCoverage {
	if len(statuses) == 0 {
		return nil
	}

	statusesByPath := map[string][]ControlProofStatus{}
	statusesByLocation := map[string][]ControlProofStatus{}
	for _, status := range statuses {
		pathID := strings.TrimSpace(status.LinkedActionPathID)
		if pathID != "" {
			statusesByPath[pathID] = append(statusesByPath[pathID], status)
		}
		locationKey := proofCoverageLocationKey(status.Repo, status.Path)
		if locationKey != "" {
			statusesByLocation[locationKey] = append(statusesByLocation[locationKey], status)
		}
	}

	out := map[string]pathProofCoverage{}
	for _, path := range paths {
		pathID := strings.TrimSpace(path.PathID)
		items := statusesByLocation[proofCoverageLocationKey(path.Repo, path.Location)]
		if len(items) == 0 {
			items = statusesByPath[pathID]
		}
		if len(items) == 0 {
			out[pathID] = pathProofCoverage{Status: proofCoverageMissing}
			continue
		}

		coverage := proofCoverageCovered
		for _, item := range items {
			if strings.TrimSpace(item.Status) == "missing" {
				coverage = proofCoverageMissing
				break
			}
		}
		out[pathID] = pathProofCoverage{Status: coverage}
	}
	return out
}

func proofCoverageLocationKey(repo string, path string) string {
	repo = strings.TrimSpace(repo)
	path = strings.TrimSpace(path)
	if repo == "" || path == "" {
		return ""
	}
	return repo + "|" + path
}

func itemEvidenceRefs(path risk.ActionPath, backlog controlbacklog.Item, runtime ingest.Correlation, graphRefs AgentActionBOMGraphRefs) []string {
	refs := []string{}
	refs = append(refs, path.ApprovalGapReasons...)
	refs = append(refs, path.PolicyEvidenceRefs...)
	if path.CredentialAuthority != nil {
		refs = append(refs, path.CredentialAuthority.ReasonCodes...)
	}
	if path.CredentialProvenance != nil {
		refs = append(refs, path.CredentialProvenance.EvidenceBasis...)
		refs = append(refs, path.CredentialProvenance.ClassificationReasons...)
	}
	if path.ActionLineage != nil {
		for _, segment := range path.ActionLineage.Segments {
			refs = append(refs, segment.EvidenceRefs...)
		}
	}
	refs = append(refs, backlog.EvidenceBasis...)
	refs = append(refs, runtime.RecordIDs...)
	refs = append(refs, runtime.Sources...)
	refs = append(refs, path.AttackPathRefs...)
	refs = append(refs, path.SourceFindingKeys...)
	refs = append(refs, graphRefs.NodeIDs...)
	refs = append(refs, graphRefs.EdgeIDs...)
	return uniqueSortedStrings(refs)
}

func isStaticCredentialItem(provenance *agginventory.CredentialProvenance) bool {
	normalized := agginventory.NormalizeCredentialProvenance(provenance)
	if normalized == nil {
		return false
	}
	switch normalized.CredentialKind {
	case agginventory.CredentialKindGitHubPAT,
		agginventory.CredentialKindGitHubAppKey,
		agginventory.CredentialKindDeployKey,
		agginventory.CredentialKindCloudAdminKey,
		agginventory.CredentialKindCloudAccessKey,
		agginventory.CredentialKindStaticSecret,
		agginventory.CredentialKindUnknownDurable:
		return true
	default:
		return normalized.Type == agginventory.CredentialProvenanceStaticSecret
	}
}

func summaryEvidenceRefs(items []AgentActionBOMItem) []string {
	refs := []string{}
	for _, item := range items {
		refs = append(refs, item.EvidenceRefs...)
	}
	return uniqueSortedStrings(refs)
}

func summarizeAgentActionBOMItems(items []AgentActionBOMItem, paths []risk.ActionPath, report *scanquality.Report) AgentActionBOMSummary {
	projection := risk.SummarizeActionPaths(paths, risk.ActionPathSummaryOptions{
		ScanCoverageReduced: scanQualityCoverageReduced(report),
	})
	counts := AgentActionBOMSummary{
		TotalItems:                   len(items),
		ConfirmedActionPathItems:     projection.ConfirmedActionPaths,
		LikelyActionPathItems:        projection.LikelyActionPaths,
		SemanticReviewCandidateItems: projection.SemanticReviewCandidatePaths,
		ContextOnlyItems:             projection.ContextOnlyPaths,
	}
	for _, item := range items {
		if strings.TrimSpace(item.ControlPriority) == risk.ControlPriorityControlFirst {
			counts.ControlFirstItems++
		}
		if item.StandingPrivilege {
			counts.StandingPrivilegeItems++
		}
		if isStaticCredentialItem(item.CredentialProvenance) {
			counts.StaticCredentialItems++
		}
		if item.ProductionWrite || len(item.MatchedProductionTargets) > 0 {
			counts.ProductionTargetItems++
		}
		if item.ApprovalEvidenceState == risk.EvidenceStateUnknown {
			counts.ApprovalEvidenceUnknownItems++
			counts.MissingApprovalItems++
		}
		if item.ControlResolutionState == risk.ControlResolutionStateNoVisibleControl {
			counts.ControlEvidenceUnknownItems++
			counts.MissingPolicyItems++
		}
		if item.OwnerEvidenceState == risk.EvidenceStateUnknown || item.OwnerEvidenceState == risk.EvidenceStateContradictory {
			counts.OwnerEvidenceUnknownItems++
			counts.UnresolvedOwnerItems++
		}
		if item.ProofEvidenceState == risk.EvidenceStateUnknown {
			counts.ProofEvidenceUnknownItems++
			counts.MissingProofItems++
		}
		if item.PolicyStatus == risk.PolicyCoverageStatusRuntimeProven || item.RuntimeEvidenceStatus == ingest.CorrelationStatusMatched {
			counts.RuntimeProvenItems++
		}
	}
	counts.EmptyStateStatus, counts.EmptyStateReasons = evaluateBOMEmptyState(projection, counts, scanQualityCoverageReduced(report))
	return counts
}

func evaluateBOMEmptyState(projection risk.ActionPathSummary, counts AgentActionBOMSummary, scanCoverageReduced bool) (string, []string) {
	reasons := []string{}
	if projection.TotalPaths == 0 {
		reasons = append(reasons, "action_paths:none")
	} else if projection.ContextOnlyPaths == projection.TotalPaths {
		reasons = append(reasons, "action_paths:context_only_only")
	}

	hasBlocker := false
	for _, blocker := range []struct {
		count  int
		reason string
	}{
		{counts.ControlFirstItems, "control_first_paths_present"},
		{projection.WriteCapablePaths, "write_capable_paths_present"},
		{projection.CredentialAccessPaths, "credential_access_paths_present"},
		{counts.StandingPrivilegeItems, "standing_privilege_paths_present"},
		{counts.ProductionTargetItems, "production_target_backed_paths_present"},
		{counts.ApprovalEvidenceUnknownItems, "approval_evidence_unknown_paths_present"},
		{counts.ControlEvidenceUnknownItems, "control_evidence_unknown_paths_present"},
		{counts.ProofEvidenceUnknownItems, "proof_evidence_unknown_paths_present"},
		{counts.OwnerEvidenceUnknownItems, "owner_evidence_unknown_paths_present"},
		{projection.HighReviewBurdenPaths, "high_review_burden_paths_present"},
		{counts.ConfirmedActionPathItems, "confirmed_action_paths_present"},
		{counts.LikelyActionPathItems, "likely_action_paths_present"},
		{counts.SemanticReviewCandidateItems, "semantic_review_candidates_present"},
	} {
		if blocker.count > 0 {
			hasBlocker = true
			reasons = append(reasons, blocker.reason)
		}
	}
	if scanCoverageReduced {
		reasons = append(reasons, "scan_quality:reduced")
	}

	switch {
	case hasBlocker:
		return risk.EmptyStateNotEligible, uniqueSortedStrings(reasons)
	case scanCoverageReduced:
		return risk.EmptyStateCoverageReduced, uniqueSortedStrings(reasons)
	default:
		return risk.EmptyStateEligible, uniqueSortedStrings(reasons)
	}
}

func cloneShareProfileMetadata(in *ShareProfileMetadata) *ShareProfileMetadata {
	if in == nil {
		return nil
	}
	out := *in
	out.PolicySummary = append([]string(nil), in.PolicySummary...)
	return &out
}

func cloneScanScope(in *ScanScopeSummary) *ScanScopeSummary {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneAxisSummary(in *scorecore.AxisSummary) *scorecore.AxisSummary {
	if in == nil {
		return nil
	}
	out := *in
	out.Rationale = append([]string(nil), in.Rationale...)
	return &out
}

func decorateLineageForBOM(in *risk.ActionLineage, item AgentActionBOMItem) *risk.ActionLineage {
	if in == nil {
		return nil
	}
	out := risk.CloneActionLineage(in)
	for idx := range out.Segments {
		switch strings.TrimSpace(out.Segments[idx].Kind) {
		case "approval":
			if item.ApprovalGap {
				out.Segments[idx].Status = "missing"
				out.Segments[idx].Label = risk.BuyerEvidenceStateLabel("approval", item.ApprovalEvidenceState)
			} else {
				out.Segments[idx].Status = "present"
				out.Segments[idx].Label = firstNonEmptyValue(strings.TrimSpace(out.Segments[idx].Label), risk.BuyerEvidenceStateLabel("approval", item.ApprovalEvidenceState))
			}
		case "proof":
			switch strings.TrimSpace(item.ProofCoverage) {
			case proofCoverageCovered, proofCoverageChainAttached:
				out.Segments[idx].Status = "present"
			default:
				out.Segments[idx].Status = "missing"
			}
			out.Segments[idx].Label = firstNonEmptyValue(strings.TrimSpace(out.Segments[idx].Label), risk.BuyerEvidenceStateLabel("proof", item.ProofEvidenceState))
		}
	}
	return out
}

func coverageConfidenceLabel(report *scanquality.Report) string {
	if report == nil {
		return "unknown"
	}
	if scanQualityCoverageReduced(report) {
		return "reduced"
	}
	return "complete"
}

func queueForControlPriority(priority string) string {
	switch strings.TrimSpace(priority) {
	case risk.ControlPriorityControlFirst:
		return controlbacklog.QueueControlFirst
	case risk.ControlPriorityInventoryHygiene:
		return controlbacklog.QueueInventoryHygiene
	default:
		return controlbacklog.QueueReviewQueue
	}
}

func visibilityForQueue(queue string) string {
	switch strings.TrimSpace(queue) {
	case controlbacklog.QueueControlFirst, controlbacklog.QueueReviewQueue:
		return controlbacklog.FindingVisibilityPrimary
	case controlbacklog.QueueInventoryHygiene:
		return controlbacklog.FindingVisibilityAppendix
	default:
		return controlbacklog.FindingVisibilityDebug
	}
}

func proofRefsForPath(path risk.ActionPath, statuses []ControlProofStatus) []string {
	refs := []string{}
	pathID := strings.TrimSpace(path.PathID)
	if pathID != "" {
		refs = append(refs, "path:"+pathID)
	}
	for _, key := range path.SourceFindingKeys {
		refs = append(refs, "finding:"+strings.TrimSpace(key))
	}
	for _, status := range controlProofStatusesForPath(path, statuses) {
		for _, recordID := range status.RecordIDs {
			refs = append(refs, "proof_record:"+strings.TrimSpace(recordID))
		}
	}
	return uniqueSortedStrings(refs)
}

func controlProofStatusesForPath(path risk.ActionPath, statuses []ControlProofStatus) []ControlProofStatus {
	if len(statuses) == 0 {
		return nil
	}
	pathID := strings.TrimSpace(path.PathID)
	locationKey := proofCoverageLocationKey(path.Repo, path.Location)
	out := []ControlProofStatus{}
	for _, status := range statuses {
		if strings.TrimSpace(status.LinkedActionPathID) == pathID {
			out = append(out, status)
			continue
		}
		if locationKey != "" && proofCoverageLocationKey(status.Repo, status.Path) == locationKey {
			out = append(out, status)
		}
	}
	return out
}

func excludedTopAttackPathItems(summary Summary) []AgentActionBOMItem {
	if len(summary.topAttackPaths) == 0 {
		return nil
	}
	matched := map[string]struct{}{}
	for _, path := range summary.ActionPaths {
		for _, ref := range path.AttackPathRefs {
			if strings.TrimSpace(ref) != "" {
				matched[strings.TrimSpace(ref)] = struct{}{}
			}
		}
	}
	items := []AgentActionBOMItem{}
	for _, attackPath := range summary.topAttackPaths {
		if _, ok := matched[strings.TrimSpace(attackPath.PathID)]; ok {
			continue
		}
		location, toolType := firstAttackPathLocationAndTool(attackPath.SourceFindings)
		riskTier := attackPathRiskTier(attackPath.PathScore)
		item := AgentActionBOMItem{
			PathID:                strings.TrimSpace(attackPath.PathID),
			Org:                   strings.TrimSpace(attackPath.Org),
			Repo:                  strings.TrimSpace(attackPath.Repo),
			ToolType:              firstNonEmptyValue(toolType, "attack_path_exclusion"),
			Location:              location,
			ApprovalGap:           false,
			PolicyStatus:          risk.PolicyCoverageStatusNone,
			ProofCoverage:         proofCoverageMissing,
			ProofRefs:             attackPathProofRefs(attackPath),
			InventoryRisk:         risk.InventoryRiskVisibilityOnly,
			ControlPriority:       risk.ControlPriorityReviewQueue,
			RiskTier:              riskTier,
			RecommendedNextAction: "proof",
			Queue:                 controlbacklog.QueueReviewQueue,
			FindingVisibility:     controlbacklog.FindingVisibilityPrimary,
			Remediation:           "Investigate why this top attack path has no matching govern-first action path, add the missing path or record an explicit exclusion reason, and rerun the report.",
			AttackPathRefs:        []string{strings.TrimSpace(attackPath.PathID)},
			SourceFindingKeys:     append([]string(nil), attackPath.SourceFindings...),
			ExclusionReason:       "top_attack_path_missing_matching_action_path",
			EvidenceRefs:          attackPathEvidenceRefs(attackPath),
		}
		if profile, ok := ParseShareProfile(summary.ShareProfile); ok && shareProfileRequiresRedaction(profile) {
			item.PathID = redactValue("attack", item.PathID, 8)
			item.Org = redactValue("org", item.Org, 6)
			item.Repo = redactValue("repo", item.Repo, 6)
			item.Location = redactValue("loc", item.Location, 8)
			item.AttackPathRefs = redactStringSlice(item.AttackPathRefs, "attack")
			item.SourceFindingKeys = redactStringSlice(item.SourceFindingKeys, "finding")
			item.EvidenceRefs = redactStringSlice(item.EvidenceRefs, "evidence")
			item.ProofRefs = redactStringSlice(item.ProofRefs, "proof")
		}
		items = append(items, item)
	}
	return items
}

func attackPathRiskTier(score float64) string {
	switch {
	case score >= 9.0:
		return risk.RiskTierCritical
	case score >= 7.0:
		return risk.RiskTierHigh
	case score >= 5.0:
		return risk.RiskTierMedium
	default:
		return risk.RiskTierLow
	}
}

func attackPathProofRefs(path riskattack.ScoredPath) []string {
	refs := []string{"attack_path:" + strings.TrimSpace(path.PathID)}
	for _, key := range path.SourceFindings {
		refs = append(refs, "finding:"+strings.TrimSpace(key))
	}
	return uniqueSortedStrings(refs)
}

func attackPathEvidenceRefs(path riskattack.ScoredPath) []string {
	refs := []string{"attack_path:" + strings.TrimSpace(path.PathID)}
	refs = append(refs, path.SourceFindings...)
	return uniqueSortedStrings(refs)
}

func firstAttackPathLocationAndTool(keys []string) (string, string) {
	for _, key := range keys {
		location, toolType := parseAttackPathFindingKey(key)
		if location != "" || toolType != "" {
			return location, toolType
		}
	}
	return "", ""
}

func parseAttackPathFindingKey(key string) (string, string) {
	parts := strings.Split(strings.TrimSpace(key), "|")
	if len(parts) < 6 {
		return "", ""
	}
	return strings.TrimSpace(parts[3]), strings.TrimSpace(parts[2])
}

func reachabilityByPathID(paths []risk.ActionPath, findings []model.Finding) map[string][]AgentActionBOMReachability {
	if len(paths) == 0 || len(findings) == 0 {
		return map[string][]AgentActionBOMReachability{}
	}
	findingsByRepoLocation := map[string][]model.Finding{}
	mcpByRepoName := map[string]model.Finding{}
	for _, finding := range findings {
		key := strings.Join([]string{strings.TrimSpace(finding.Org), strings.TrimSpace(finding.Repo), strings.TrimSpace(finding.Location)}, "|")
		findingsByRepoLocation[key] = append(findingsByRepoLocation[key], finding)
		if strings.TrimSpace(finding.FindingType) == "mcp_server" {
			name := firstEvidenceValue(finding, "server")
			if strings.TrimSpace(name) != "" {
				mcpByRepoName[strings.Join([]string{strings.TrimSpace(finding.Org), strings.TrimSpace(finding.Repo), strings.TrimSpace(name)}, "|")] = finding
			}
		}
	}

	out := map[string][]AgentActionBOMReachability{}
	for _, path := range paths {
		key := strings.Join([]string{strings.TrimSpace(path.Org), strings.TrimSpace(path.Repo), strings.TrimSpace(path.Location)}, "|")
		items := []AgentActionBOMReachability{}
		for _, semantic := range agginventory.NormalizeMutableEndpointSemantics(path.MutableEndpointSemantics) {
			items = append(items, AgentActionBOMReachability{
				Surface:      "reachable_endpoint",
				Name:         firstNonEmptyValue(strings.TrimSpace(semantic.Operation), strings.TrimSpace(semantic.Semantic)),
				Capabilities: []string{strings.TrimSpace(semantic.Semantic)},
				EvidenceRefs: append([]string(nil), semantic.EvidenceRefs...),
			})
		}
		for _, finding := range findingsByRepoLocation[key] {
			switch strings.TrimSpace(finding.FindingType) {
			case "mcp_server":
				items = append(items, AgentActionBOMReachability{
					Surface:      "mcp_server",
					Name:         firstEvidenceValue(finding, "server"),
					Capabilities: append([]string(nil), finding.Permissions...),
					TrustDepth:   agginventory.TrustDepthFromFinding(finding),
					EvidenceRefs: findingEvidenceRefs(finding),
				})
			case "a2a_agent_card":
				items = append(items, AgentActionBOMReachability{
					Surface:      "a2a_agent",
					Name:         firstEvidenceValue(finding, "agent_name"),
					Capabilities: splitEvidenceList(firstEvidenceValue(finding, "capabilities")),
					TrustDepth:   agginventory.TrustDepthFromFinding(finding),
					EvidenceRefs: findingEvidenceRefs(finding),
				})
			case "agent_framework":
				for _, toolName := range splitEvidenceList(firstEvidenceValue(finding, "tool_bindings")) {
					items = append(items, AgentActionBOMReachability{
						Surface:      "reachable_tool",
						Name:         toolName,
						EvidenceRefs: findingEvidenceRefs(finding),
					})
					if boundServer, ok := mcpByRepoName[strings.Join([]string{strings.TrimSpace(path.Org), strings.TrimSpace(path.Repo), toolName}, "|")]; ok {
						items = append(items, AgentActionBOMReachability{
							Surface:      "mcp_server",
							Name:         toolName,
							Capabilities: append([]string(nil), boundServer.Permissions...),
							TrustDepth:   agginventory.TrustDepthFromFinding(boundServer),
							EvidenceRefs: findingEvidenceRefs(boundServer),
						})
					}
				}
				for _, endpoint := range splitEvidenceList(firstEvidenceValue(finding, "reachable_endpoints")) {
					items = append(items, AgentActionBOMReachability{
						Surface:      "reachable_endpoint",
						Name:         endpoint,
						EvidenceRefs: findingEvidenceRefs(finding),
					})
				}
				for _, target := range splitEvidenceList(firstEvidenceValue(finding, "reachable_targets")) {
					items = append(items, AgentActionBOMReachability{
						Surface:      "reachable_target",
						Name:         target,
						EvidenceRefs: findingEvidenceRefs(finding),
					})
				}
			}
		}
		if len(items) > 0 {
			sort.Slice(items, func(i, j int) bool {
				if items[i].Surface != items[j].Surface {
					return items[i].Surface < items[j].Surface
				}
				return items[i].Name < items[j].Name
			})
			out[strings.TrimSpace(path.PathID)] = items
		}
	}
	return out
}

func namedReachability(items []AgentActionBOMReachability) (
	[]AgentActionBOMReachability,
	[]AgentActionBOMReachability,
	[]AgentActionBOMReachability,
	[]AgentActionBOMReachability,
	[]AgentActionBOMReachability,
	[]AgentActionBOMReachability,
) {
	servers := []AgentActionBOMReachability{}
	tools := []AgentActionBOMReachability{}
	endpoints := []AgentActionBOMReachability{}
	targets := []AgentActionBOMReachability{}
	apis := []AgentActionBOMReachability{}
	agents := []AgentActionBOMReachability{}

	for _, item := range items {
		switch strings.TrimSpace(item.Surface) {
		case "mcp_server":
			servers = append(servers, item)
			tools = append(tools, reachabilityCapabilities("mcp_tool", item)...)
		case "a2a_agent":
			agents = append(agents, item)
			apis = append(apis, reachabilityCapabilities("a2a_capability", item)...)
		case "reachable_endpoint":
			endpoints = append(endpoints, item)
		case "reachable_target":
			targets = append(targets, item)
		case "reachable_tool":
			tools = append(tools, item)
		default:
			if strings.Contains(strings.TrimSpace(item.Surface), "api") {
				apis = append(apis, item)
			}
		}
	}

	return sortReachability(servers), sortReachability(tools), sortReachability(endpoints), sortReachability(targets), sortReachability(apis), sortReachability(agents)
}

type pathSignal struct {
	Confidence       string
	EvidenceStrength string
}

func pathSignalsByPathID(paths []risk.ActionPath, findings []model.Finding) map[string]pathSignal {
	out := map[string]pathSignal{}
	if len(paths) == 0 || len(findings) == 0 {
		return out
	}
	findingsByRepoLocation := map[string][]model.Finding{}
	for _, finding := range findings {
		key := strings.Join([]string{strings.TrimSpace(finding.Org), strings.TrimSpace(finding.Repo), strings.TrimSpace(finding.Location)}, "|")
		findingsByRepoLocation[key] = append(findingsByRepoLocation[key], finding)
	}
	for _, path := range paths {
		key := strings.Join([]string{strings.TrimSpace(path.Org), strings.TrimSpace(path.Repo), strings.TrimSpace(path.Location)}, "|")
		signal := pathSignal{}
		for _, finding := range findingsByRepoLocation[key] {
			confidence := firstEvidenceValue(finding, "confidence")
			evidenceStrength := firstEvidenceValue(finding, "evidence_strength")
			if confidenceRank(confidence) > confidenceRank(signal.Confidence) {
				signal.Confidence = strings.TrimSpace(confidence)
			}
			if evidenceStrengthPriority(evidenceStrength) < evidenceStrengthPriority(signal.EvidenceStrength) || strings.TrimSpace(signal.EvidenceStrength) == "" {
				signal.EvidenceStrength = strings.TrimSpace(evidenceStrength)
			}
		}
		if signal.Confidence != "" || signal.EvidenceStrength != "" {
			out[strings.TrimSpace(path.PathID)] = signal
		}
	}
	return out
}

func confidenceRank(value string) int {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func evidenceStrengthPriority(value string) int {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "credential":
		return 0
	case "tool_binding":
		return 1
	case "retriever":
		return 2
	case "workflow":
		return 3
	case "provider":
		return 4
	case "constructor":
		return 5
	default:
		return 99
	}
}

func reachabilityCapabilities(surface string, item AgentActionBOMReachability) []AgentActionBOMReachability {
	capabilities := uniqueSortedStrings(item.Capabilities)
	if len(capabilities) == 0 {
		return nil
	}
	out := make([]AgentActionBOMReachability, 0, len(capabilities))
	for _, capability := range capabilities {
		out = append(out, AgentActionBOMReachability{
			Surface:      surface,
			Name:         capability,
			TrustDepth:   agginventory.CloneTrustDepth(item.TrustDepth),
			EvidenceRefs: append([]string(nil), item.EvidenceRefs...),
		})
	}
	return out
}

func sortReachability(items []AgentActionBOMReachability) []AgentActionBOMReachability {
	if len(items) == 0 {
		return nil
	}
	sort.SliceStable(items, func(i, j int) bool {
		if strings.TrimSpace(items[i].Surface) != strings.TrimSpace(items[j].Surface) {
			return strings.TrimSpace(items[i].Surface) < strings.TrimSpace(items[j].Surface)
		}
		if strings.TrimSpace(items[i].Name) != strings.TrimSpace(items[j].Name) {
			return strings.TrimSpace(items[i].Name) < strings.TrimSpace(items[j].Name)
		}
		return strings.Join(items[i].EvidenceRefs, ",") < strings.Join(items[j].EvidenceRefs, ",")
	})
	return items
}

func firstEvidenceValue(finding model.Finding, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) == key {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func splitEvidenceList(value string) []string {
	parts := strings.Split(strings.TrimSpace(value), ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return uniqueSortedStrings(out)
}

func findingEvidenceRefs(finding model.Finding) []string {
	out := []string{}
	for _, item := range finding.Evidence {
		if strings.TrimSpace(item.Key) == "" || strings.TrimSpace(item.Value) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(item.Key)+":"+strings.TrimSpace(item.Value))
	}
	return uniqueSortedStrings(out)
}

func firstNonEmptyValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
