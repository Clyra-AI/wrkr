package controlbacklog

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/governancequeue"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const BacklogVersion = "1"

const (
	SignalClassUniqueWrkrSignal      = "unique_wrkr_signal"
	SignalClassSupportingSecurity    = "supporting_security_signal"
	QueueControlFirst                = "control_first"
	QueueReviewQueue                 = "review_queue"
	QueueAcceptedRisk                = "accepted_risk_queue"
	QueueInventoryHygiene            = "inventory_hygiene"
	QueueDebugOnly                   = "debug_only"
	FindingVisibilityPrimary         = "primary"
	FindingVisibilityAppendix        = "appendix"
	FindingVisibilityDebug           = "debug"
	ControlSurfaceAIAgent            = "ai_agent"
	ControlSurfaceCodingAssistant    = "coding_assistant_config"
	ControlSurfaceMCPServerTool      = "mcp_server_tool"
	ControlSurfaceCIAutomation       = "ci_automation"
	ControlSurfaceReleaseAutomation  = "release_automation"
	ControlSurfaceDependencyAgent    = "dependency_agent_surface"
	ControlSurfaceSecretWorkflow     = "secret_bearing_workflow"
	ControlSurfaceNonHumanIdentity   = "non_human_identity"
	ControlPathAgentConfig           = "agent_config"
	ControlPathMCPTool               = "mcp_tool"
	ControlPathCIAutomation          = "ci_automation"
	ControlPathReleaseWorkflow       = "release_workflow"
	ControlPathDependencyAgent       = "dependency_agent_surface"
	ControlPathSecretWorkflow        = "secret_bearing_workflow"
	ActionAttachEvidence             = "attach_evidence"
	ActionApprove                    = "approve"
	ActionRemediate                  = "remediate"
	ActionDowngrade                  = "downgrade"
	ActionDeprecate                  = "deprecate"
	ActionExclude                    = "exclude"
	ActionMonitor                    = "monitor"
	ActionInventoryReview            = "inventory_review"
	ActionSuppress                   = "suppress"
	ActionDebugOnly                  = "debug_only"
	ConfidenceHigh                   = "high"
	ConfidenceMedium                 = "medium"
	ConfidenceLow                    = "low"
	GovernanceKindAcceptedRisk       = "accepted_risk"
	GovernanceKindSuppression        = "suppression"
	GovernanceStatusActive           = "active"
	GovernanceStatusExpired          = "expired"
	GovernanceStatusInvalid          = "invalid"
	SecretReferenceDetected          = "secret_reference_detected"
	SecretValueDetected              = "secret_value_detected"
	SecretScopeUnknown               = "secret_scope_unknown" // #nosec G101 -- governance enum label, not credential material.
	SecretRotationEvidenceMissing    = "secret_rotation_evidence_missing"
	SecretOwnerMissing               = "secret_owner_missing"
	SecretUsedByWriteCapableWorkflow = "secret_used_by_write_capable_workflow"
)

type Backlog struct {
	ControlBacklogVersion string  `json:"control_backlog_version"`
	Summary               Summary `json:"summary"`
	Items                 []Item  `json:"items"`
}

type Summary struct {
	TotalItems                int `json:"total_items"`
	UniqueWrkrSignalItems     int `json:"unique_wrkr_signal_items"`
	SupportingSecurityItems   int `json:"supporting_security_signal_items"`
	AttachEvidenceActionItems int `json:"attach_evidence_action_items"`
	ApproveActionItems        int `json:"approve_action_items"`
	RemediateActionItems      int `json:"remediate_action_items"`
	ControlFirstQueueItems    int `json:"control_first_queue_items,omitempty"`
	ReviewQueueItems          int `json:"review_queue_items,omitempty"`
	AcceptedRiskQueueItems    int `json:"accepted_risk_queue_items,omitempty"`
	InventoryHygieneItems     int `json:"inventory_hygiene_items,omitempty"`
	DebugOnlyQueueItems       int `json:"debug_only_queue_items,omitempty"`
	LifecycleQueueItems       int `json:"lifecycle_queue_items,omitempty"`
}

type GovernanceDisposition struct {
	Kind               string   `json:"kind"`
	Status             string   `json:"status"`
	Reason             string   `json:"reason"`
	Scope              string   `json:"scope"`
	Issuer             string   `json:"issuer,omitempty"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
	EvidenceState      string   `json:"evidence_state,omitempty"`
	VisibilityBehavior string   `json:"visibility_behavior,omitempty"`
	RescanBehavior     string   `json:"rescan_behavior,omitempty"`
	EvidenceRefs       []string `json:"evidence_refs,omitempty"`
}

type Item struct {
	ID                         string                                  `json:"id"`
	AgentID                    string                                  `json:"agent_id,omitempty"`
	Repo                       string                                  `json:"repo"`
	Path                       string                                  `json:"path"`
	ControlSurfaceType         string                                  `json:"control_surface_type"`
	ControlPathType            string                                  `json:"control_path_type"`
	Capability                 string                                  `json:"capability"`
	Capabilities               []string                                `json:"capabilities,omitempty"`
	WritePathClasses           []string                                `json:"write_path_classes,omitempty"`
	ActionClasses              []string                                `json:"action_classes,omitempty"`
	ActionReasons              []string                                `json:"action_reasons,omitempty"`
	GovernanceControls         []agginventory.GovernanceControlMapping `json:"governance_controls,omitempty"`
	Owner                      string                                  `json:"owner,omitempty"`
	OwnerSource                string                                  `json:"owner_source,omitempty"`
	OwnershipStatus            string                                  `json:"ownership_status,omitempty"`
	OwnershipState             string                                  `json:"ownership_state,omitempty"`
	OwnershipConfidence        float64                                 `json:"ownership_confidence,omitempty"`
	OwnershipEvidence          []string                                `json:"ownership_evidence_basis,omitempty"`
	OwnershipConflicts         []string                                `json:"ownership_conflicts,omitempty"`
	EvidenceDecisions          []evidencepolicy.Decision               `json:"evidence_decisions,omitempty"`
	Contradictions             []evidencepolicy.Contradiction          `json:"contradictions,omitempty"`
	ControlResolutionState     string                                  `json:"control_resolution_state,omitempty"`
	ControlResolutionReasons   []string                                `json:"control_resolution_reasons,omitempty"`
	ControlEvidenceRefs        []string                                `json:"control_evidence_refs,omitempty"`
	ConstraintEvidenceClasses  []string                                `json:"constraint_evidence_classes,omitempty"`
	ConstraintEvidenceRefs     []string                                `json:"constraint_evidence_refs,omitempty"`
	ApprovalEvidenceState      string                                  `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState         string                                  `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState         string                                  `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState       string                                  `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState        string                                  `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState    string                                  `json:"credential_evidence_state,omitempty"`
	TargetClass                string                                  `json:"target_class,omitempty"`
	TargetClassReasons         []string                                `json:"target_class_reasons,omitempty"`
	TargetClassEvidenceRefs    []string                                `json:"target_class_evidence_refs,omitempty"`
	ActionPathType             string                                  `json:"action_path_type,omitempty"`
	ActionPathTypeReasons      []string                                `json:"action_path_type_reasons,omitempty"`
	ActionPathTypeEvidenceRefs []string                                `json:"action_path_type_evidence_refs,omitempty"`
	EvidenceSource             string                                  `json:"evidence_source"`
	EvidenceBasis              []string                                `json:"evidence_basis"`
	ApprovalStatus             string                                  `json:"approval_status"`
	SecurityVisibility         string                                  `json:"security_visibility"`
	Queue                      string                                  `json:"queue,omitempty"`
	FindingVisibility          string                                  `json:"finding_visibility,omitempty"`
	SignalClass                string                                  `json:"signal_class"`
	RecommendedAction          string                                  `json:"recommended_action"`
	Remediation                string                                  `json:"remediation,omitempty"`
	Confidence                 string                                  `json:"confidence"`
	EvidenceGaps               []string                                `json:"evidence_gaps,omitempty"`
	ConfidenceRaise            []string                                `json:"confidence_raise,omitempty"`
	SLA                        string                                  `json:"sla"`
	ClosureCriteria            string                                  `json:"closure_criteria"`
	ClosureRequirements        []risk.ClosureRequirement               `json:"closure_requirements,omitempty"`
	EvidenceCompleteness       *risk.EvidenceCompleteness              `json:"evidence_completeness,omitempty"`
	GovernanceDisposition      *GovernanceDisposition                  `json:"governance_disposition,omitempty"`
	LifecycleQueue             *governancequeue.Item                   `json:"lifecycle_queue,omitempty"`
	SecretSignalTypes          []string                                `json:"secret_signal_types,omitempty"`
	LinkedFindingIDs           []string                                `json:"linked_finding_ids,omitempty"`
	LinkedActionPathID         string                                  `json:"linked_action_path_id,omitempty"`
	LinkedControlPathNodeIDs   []string                                `json:"linked_control_path_node_ids,omitempty"`
	LinkedControlPathEdgeIDs   []string                                `json:"linked_control_path_edge_ids,omitempty"`
	CredentialProvenance       *agginventory.CredentialProvenance      `json:"credential_provenance,omitempty"`
	CredentialAuthority        *agginventory.CredentialAuthority       `json:"credential_authority,omitempty"`
	StandingPrivilege          bool                                    `json:"standing_privilege,omitempty"`
	StandingPrivilegeReasons   []string                                `json:"standing_privilege_reasons,omitempty"`
	ControlState               string                                  `json:"control_state,omitempty"`
	ControlStateReasons        []string                                `json:"control_state_reasons,omitempty"`
	RiskZone                   string                                  `json:"risk_zone,omitempty"`
	RiskZoneReasons            []string                                `json:"risk_zone_reasons,omitempty"`
	ReviewBurden               string                                  `json:"review_burden,omitempty"`
	ReviewBurdenReasons        []string                                `json:"review_burden_reasons,omitempty"`
	ConfidenceLane             string                                  `json:"confidence_lane,omitempty"`
	ConfidenceLaneReasons      []string                                `json:"confidence_lane_reasons,omitempty"`
	PolicyCoverageStatus       string                                  `json:"policy_coverage_status,omitempty"`
	PolicyRefs                 []string                                `json:"policy_refs,omitempty"`
	PolicyMissingReasons       []string                                `json:"policy_missing_reasons,omitempty"`
	PolicyEvidenceRefs         []string                                `json:"policy_evidence_refs,omitempty"`
	PolicyConfidence           string                                  `json:"policy_confidence,omitempty"`
	TrustDepth                 *agginventory.TrustDepth                `json:"trust_depth,omitempty"`
	SecurityTestRecipes        []SecurityTestRecipe                    `json:"security_test_recipes,omitempty"`
}

type SecurityTestRecipe struct {
	ID                  string   `json:"id"`
	Class               string   `json:"class"`
	Title               string   `json:"title"`
	Preconditions       []string `json:"preconditions,omitempty"`
	ExpectedObservation string   `json:"expected_observation"`
	RequiredApprovals   []string `json:"required_approvals,omitempty"`
	DryRunFlag          string   `json:"dry_run_flag,omitempty"`
	EvidenceRefs        []string `json:"evidence_refs,omitempty"`
}

type Input struct {
	Mode             string
	GeneratedAt      time.Time
	Findings         []model.Finding
	Inventory        *agginventory.Inventory
	Identities       []manifest.IdentityRecord
	LifecycleGaps    []lifecycle.Gap
	ActionPaths      []risk.ActionPath
	ControlPathGraph *aggattack.ControlPathGraph
}

func Build(input Input) Backlog {
	builder := newBuilder(input)
	for _, path := range input.ActionPaths {
		builder.addActionPath(path)
	}
	for _, gap := range input.LifecycleGaps {
		builder.addLifecycleGap(gap)
	}
	for _, finding := range input.Findings {
		builder.addFinding(finding, input.Mode)
	}
	items := builder.items()
	return Backlog{
		ControlBacklogVersion: BacklogVersion,
		Summary:               summarize(items),
		Items:                 items,
	}
}

func ValidSignalClass(value string) bool {
	switch strings.TrimSpace(value) {
	case SignalClassUniqueWrkrSignal, SignalClassSupportingSecurity:
		return true
	default:
		return false
	}
}

func ValidRecommendedAction(value string) bool {
	switch strings.TrimSpace(value) {
	case ActionAttachEvidence, ActionApprove, ActionRemediate, ActionDowngrade, ActionDeprecate, ActionExclude, ActionMonitor, ActionInventoryReview, ActionSuppress, ActionDebugOnly:
		return true
	default:
		return false
	}
}

func ValidConfidence(value string) bool {
	switch strings.TrimSpace(value) {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	default:
		return false
	}
}

type builder struct {
	findingsByLocation map[string][]model.Finding
	toolByLocation     map[string]agginventory.Tool
	locationByKey      map[string]agginventory.ToolLocation
	actionPathByKey    map[string]risk.ActionPath
	actionPathByAgent  map[string]risk.ActionPath
	writeByLocation    map[string]bool
	identityByAgent    map[string]manifest.IdentityRecord
	identityByRepoPath map[string]manifest.IdentityRecord
	itemsByKey         map[string]Item
	graphRefsByPath    map[string]controlPathRefs
	generatedAt        time.Time
}

type controlPathRefs struct {
	nodeIDs []string
	edgeIDs []string
}

func newBuilder(input Input) *builder {
	b := &builder{
		findingsByLocation: map[string][]model.Finding{},
		toolByLocation:     map[string]agginventory.Tool{},
		locationByKey:      map[string]agginventory.ToolLocation{},
		actionPathByKey:    map[string]risk.ActionPath{},
		actionPathByAgent:  map[string]risk.ActionPath{},
		writeByLocation:    map[string]bool{},
		identityByAgent:    map[string]manifest.IdentityRecord{},
		identityByRepoPath: map[string]manifest.IdentityRecord{},
		itemsByKey:         map[string]Item{},
		graphRefsByPath:    buildControlPathRefs(input.ControlPathGraph),
		generatedAt:        input.GeneratedAt.UTC(),
	}
	if b.generatedAt.IsZero() {
		b.generatedAt = time.Now().UTC().Truncate(time.Second)
	}
	for _, finding := range input.Findings {
		key := locationKey(finding.Org, finding.Repo, finding.Location)
		b.findingsByLocation[key] = append(b.findingsByLocation[key], finding)
		if findingWriteCapable(finding) {
			b.writeByLocation[key] = true
		}
	}
	if input.Inventory != nil {
		for _, tool := range input.Inventory.Tools {
			for _, loc := range tool.Locations {
				key := locationKey(tool.Org, loc.Repo, loc.Location)
				b.toolByLocation[key] = tool
				b.locationByKey[key] = loc
			}
		}
	}
	for _, path := range input.ActionPaths {
		projected := risk.ProjectActionPath(path)
		key := locationKey(projected.Org, projected.Repo, projected.Location)
		b.actionPathByKey[key] = projected
		if agentID := strings.TrimSpace(projected.AgentID); agentID != "" {
			b.actionPathByAgent[agentID] = projected
		}
	}
	for _, record := range input.Identities {
		if agentID := strings.TrimSpace(record.AgentID); agentID != "" {
			b.identityByAgent[agentID] = record
		}
		if repoPathKey := strings.TrimSpace(record.Repo) + "|" + strings.TrimSpace(record.Location); repoPathKey != "|" {
			b.identityByRepoPath[repoPathKey] = record
		}
	}
	return b
}

func buildControlPathRefs(graph *aggattack.ControlPathGraph) map[string]controlPathRefs {
	if graph == nil {
		return map[string]controlPathRefs{}
	}
	refs := map[string]controlPathRefs{}
	for _, node := range graph.Nodes {
		pathID := strings.TrimSpace(node.PathID)
		if pathID == "" {
			continue
		}
		item := refs[pathID]
		item.nodeIDs = mergeStrings(item.nodeIDs, []string{node.NodeID})
		refs[pathID] = item
	}
	for _, edge := range graph.Edges {
		pathID := strings.TrimSpace(edge.PathID)
		if pathID == "" {
			continue
		}
		item := refs[pathID]
		item.edgeIDs = mergeStrings(item.edgeIDs, []string{edge.EdgeID})
		refs[pathID] = item
	}
	return refs
}

func (b *builder) addActionPath(path risk.ActionPath) {
	path = risk.ProjectActionPath(path)
	graphRefs := b.graphRefsByPath[strings.TrimSpace(path.PathID)]
	item := Item{
		ID:                         backlogID("action_path", path.Org, path.Repo, path.Location, path.PathID),
		AgentID:                    strings.TrimSpace(path.AgentID),
		Repo:                       strings.TrimSpace(path.Repo),
		Path:                       strings.TrimSpace(path.Location),
		ControlSurfaceType:         controlSurfaceType(path.ToolType, path.Location, path.CredentialAccess, false),
		ControlPathType:            controlPathType(path.ToolType, path.Location, path.CredentialAccess, false),
		Capabilities:               capabilitiesFromActionPath(path),
		WritePathClasses:           writePathClassesFromActionPath(path),
		ActionClasses:              append([]string(nil), path.ActionClasses...),
		ActionReasons:              append([]string(nil), path.ActionReasons...),
		GovernanceControls:         append([]agginventory.GovernanceControlMapping(nil), path.GovernanceControls...),
		Owner:                      strings.TrimSpace(path.OperationalOwner),
		OwnerSource:                strings.TrimSpace(path.OwnerSource),
		OwnershipStatus:            strings.TrimSpace(path.OwnershipStatus),
		OwnershipState:             strings.TrimSpace(path.OwnershipState),
		OwnershipConfidence:        path.OwnershipConfidence,
		OwnershipEvidence:          append([]string(nil), path.OwnershipEvidence...),
		OwnershipConflicts:         append([]string(nil), path.OwnershipConflicts...),
		EvidenceDecisions:          append([]evidencepolicy.Decision(nil), path.EvidenceDecisions...),
		Contradictions:             append([]evidencepolicy.Contradiction(nil), path.Contradictions...),
		ControlResolutionState:     strings.TrimSpace(path.ControlResolutionState),
		ControlResolutionReasons:   append([]string(nil), path.ControlResolutionReasons...),
		ControlEvidenceRefs:        append([]string(nil), path.ControlEvidenceRefs...),
		ConstraintEvidenceClasses:  append([]string(nil), path.ConstraintEvidenceClasses...),
		ConstraintEvidenceRefs:     append([]string(nil), path.ConstraintEvidenceRefs...),
		ApprovalEvidenceState:      strings.TrimSpace(path.ApprovalEvidenceState),
		OwnerEvidenceState:         strings.TrimSpace(path.OwnerEvidenceState),
		ProofEvidenceState:         strings.TrimSpace(path.ProofEvidenceState),
		RuntimeEvidenceState:       strings.TrimSpace(path.RuntimeEvidenceState),
		TargetEvidenceState:        strings.TrimSpace(path.TargetEvidenceState),
		CredentialEvidenceState:    strings.TrimSpace(path.CredentialEvidenceState),
		TargetClass:                strings.TrimSpace(path.TargetClass),
		TargetClassReasons:         append([]string(nil), path.TargetClassReasons...),
		TargetClassEvidenceRefs:    append([]string(nil), path.TargetClassEvidenceRefs...),
		ActionPathType:             strings.TrimSpace(path.ActionPathType),
		ActionPathTypeReasons:      append([]string(nil), path.ActionPathTypeReasons...),
		ActionPathTypeEvidenceRefs: append([]string(nil), path.ActionPathTypeEvidenceRefs...),
		EvidenceSource:             "risk_action_path",
		EvidenceBasis:              evidenceBasisFromActionPath(path),
		ApprovalStatus:             approvalStatus(path.ApprovalGap, path.SecurityVisibilityStatus),
		SecurityVisibility:         agginventory.GovernanceSecurityVisibilityStatus(path.SecurityVisibilityStatus, "", ""),
		Queue:                      queueFromActionPath(path),
		FindingVisibility:          visibilityFromActionPath(path),
		SignalClass:                SignalClassUniqueWrkrSignal,
		RecommendedAction:          actionFromActionPath(path.RecommendedAction, path),
		Remediation:                risk.RemediationForActionPath(path),
		LinkedActionPathID:         path.PathID,
		LinkedControlPathNodeIDs:   append([]string(nil), graphRefs.nodeIDs...),
		LinkedControlPathEdgeIDs:   append([]string(nil), graphRefs.edgeIDs...),
		CredentialProvenance:       agginventory.CloneCredentialProvenance(path.CredentialProvenance),
		CredentialAuthority:        agginventory.CloneCredentialAuthority(path.CredentialAuthority),
		StandingPrivilege:          path.StandingPrivilege,
		StandingPrivilegeReasons:   append([]string(nil), path.StandingPrivilegeReasons...),
		ControlState:               strings.TrimSpace(path.ControlState),
		ControlStateReasons:        append([]string(nil), path.ControlStateReasons...),
		RiskZone:                   strings.TrimSpace(path.RiskZone),
		RiskZoneReasons:            append([]string(nil), path.RiskZoneReasons...),
		ReviewBurden:               strings.TrimSpace(path.ReviewBurden),
		ReviewBurdenReasons:        append([]string(nil), path.ReviewBurdenReasons...),
		ConfidenceLane:             strings.TrimSpace(path.ConfidenceLane),
		ConfidenceLaneReasons:      append([]string(nil), path.ConfidenceLaneReasons...),
		PolicyCoverageStatus:       strings.TrimSpace(path.PolicyCoverageStatus),
		PolicyRefs:                 append([]string(nil), path.PolicyRefs...),
		PolicyMissingReasons:       append([]string(nil), path.PolicyMissingReasons...),
		PolicyEvidenceRefs:         append([]string(nil), path.PolicyEvidenceRefs...),
		PolicyConfidence:           strings.TrimSpace(path.PolicyConfidence),
		TrustDepth:                 agginventory.CloneTrustDepth(path.TrustDepth),
		ClosureRequirements:        risk.CloneClosureRequirements(path.ClosureRequirements),
		EvidenceCompleteness:       risk.CloneEvidenceCompleteness(path.EvidenceCompleteness),
	}
	item.LinkedFindingIDs = b.linkedFindingIDs(path.Org, path.Repo, path.Location)
	item.SecretSignalTypes = secretSignalTypesForActionPath(path)
	if len(item.GovernanceControls) == 0 {
		item.GovernanceControls = agginventory.BuildGovernanceControls(agginventory.GovernanceControlInput{
			Owner:                    item.Owner,
			OwnershipStatus:          item.OwnershipStatus,
			ApprovalClassification:   item.ApprovalStatus,
			SecurityVisibilityStatus: item.SecurityVisibility,
			ProductionTargetStatus:   path.ProductionTargetStatus,
			WritePathClasses:         item.WritePathClasses,
			CredentialAccess:         path.CredentialAccess,
			ProductionWrite:          path.ProductionWrite,
			EvidenceBasis:            item.EvidenceBasis,
		})
	}
	item.Capability = capabilitySummary(item.Capabilities)
	item.Confidence, item.EvidenceGaps, item.ConfidenceRaise = qualityForItem(item)
	item.SLA = slaForAction(item.RecommendedAction)
	item.ClosureCriteria = risk.ClosureCriteriaText(item.ClosureRequirements, closureCriteriaForAction(item.RecommendedAction))
	item.SecurityTestRecipes = buildSecurityTestRecipes(item)
	b.merge(item)
}

func (b *builder) addFinding(finding model.Finding, mode string) {
	if !includeFinding(finding, mode) {
		return
	}
	key := locationKey(finding.Org, finding.Repo, finding.Location)
	tool := b.toolByLocation[key]
	loc := b.locationByKey[key]
	writeCapable := b.writeByLocation[key]
	isSecret := isSecretFinding(finding)
	item := Item{
		ID:                  backlogID("finding", finding.Org, finding.Repo, finding.Location, finding.FindingType, finding.RuleID, finding.Detector),
		AgentID:             strings.TrimSpace(tool.AgentID),
		Repo:                strings.TrimSpace(finding.Repo),
		Path:                strings.TrimSpace(finding.Location),
		ControlSurfaceType:  controlSurfaceType(finding.ToolType, finding.Location, writeCapable, isSecret),
		ControlPathType:     controlPathType(finding.ToolType, finding.Location, writeCapable, isSecret),
		Capabilities:        capabilitiesFromFinding(finding, writeCapable),
		WritePathClasses:    writePathClassesFromFinding(finding, tool, writeCapable),
		Owner:               strings.TrimSpace(loc.Owner),
		OwnerSource:         strings.TrimSpace(loc.OwnerSource),
		OwnershipStatus:     strings.TrimSpace(loc.OwnershipStatus),
		OwnershipState:      strings.TrimSpace(loc.OwnershipState),
		OwnershipConfidence: loc.OwnershipConfidence,
		OwnershipEvidence:   append([]string(nil), loc.OwnershipEvidence...),
		OwnershipConflicts:  append([]string(nil), loc.OwnershipConflicts...),
		EvidenceSource:      evidenceSourceForFinding(finding),
		EvidenceBasis:       evidenceBasisForFinding(finding),
		ApprovalStatus:      fallback(tool.ApprovalClass, "unknown"),
		SecurityVisibility:  agginventory.GovernanceSecurityVisibilityStatus(tool.SecurityVisibilityStatus, tool.ApprovalStatus, tool.LifecycleState),
		Queue:               queueFromFinding(finding, writeCapable),
		FindingVisibility:   visibilityFromFinding(finding, writeCapable),
		SignalClass:         signalClassForFinding(finding, writeCapable),
		RecommendedAction:   actionForFinding(finding, writeCapable),
		Remediation:         remediationForFinding(finding, writeCapable),
		LinkedFindingIDs:    []string{findingID(finding)},
		SecretSignalTypes:   secretSignalTypesForFinding(finding, writeCapable),
		TrustDepth:          agginventory.TrustDepthFromFinding(finding),
	}
	item.Capability = capabilitySummary(item.Capabilities)
	item.GovernanceControls = agginventory.BuildGovernanceControls(agginventory.GovernanceControlInput{
		Owner:                    item.Owner,
		OwnershipStatus:          item.OwnershipStatus,
		ApprovalStatus:           tool.ApprovalStatus,
		ApprovalClassification:   tool.ApprovalClass,
		LifecycleState:           tool.LifecycleState,
		SecurityVisibilityStatus: item.SecurityVisibility,
		WritePathClasses:         item.WritePathClasses,
		CredentialAccess:         contains(item.Capabilities, "secret_access"),
		EvidenceBasis:            item.EvidenceBasis,
	})
	item.Confidence, item.EvidenceGaps, item.ConfidenceRaise = qualityForItem(item)
	item.SLA = slaForAction(item.RecommendedAction)
	item.ClosureCriteria = closureCriteriaForAction(item.RecommendedAction)
	item.SecurityTestRecipes = buildSecurityTestRecipes(item)
	b.merge(item)
}

func (b *builder) merge(item Item) {
	if strings.TrimSpace(item.Path) == "" && strings.TrimSpace(item.Repo) == "" {
		return
	}
	key := mergeKey(item)
	current, exists := b.itemsByKey[key]
	if !exists {
		b.itemsByKey[key] = normalizeItem(item)
		return
	}
	current.Capabilities = mergeStrings(current.Capabilities, item.Capabilities)
	current.Capability = capabilitySummary(current.Capabilities)
	current.WritePathClasses = mergeStrings(current.WritePathClasses, item.WritePathClasses)
	current.EvidenceBasis = mergeStrings(current.EvidenceBasis, item.EvidenceBasis)
	current.EvidenceGaps = mergeStrings(current.EvidenceGaps, item.EvidenceGaps)
	current.ConfidenceRaise = mergeStrings(current.ConfidenceRaise, item.ConfidenceRaise)
	current.SecretSignalTypes = mergeStrings(current.SecretSignalTypes, item.SecretSignalTypes)
	current.LinkedFindingIDs = mergeStrings(current.LinkedFindingIDs, item.LinkedFindingIDs)
	current.LinkedControlPathNodeIDs = mergeStrings(current.LinkedControlPathNodeIDs, item.LinkedControlPathNodeIDs)
	current.LinkedControlPathEdgeIDs = mergeStrings(current.LinkedControlPathEdgeIDs, item.LinkedControlPathEdgeIDs)
	current.CredentialProvenance = mergeCredentialProvenance(current.CredentialProvenance, item.CredentialProvenance)
	current.CredentialAuthority = mergeCredentialAuthority(current.CredentialAuthority, item.CredentialAuthority)
	current.ConfidenceLane = firstNonEmptyConfidenceLane(current.ConfidenceLane, item.ConfidenceLane)
	current.ConfidenceLaneReasons = mergeStrings(current.ConfidenceLaneReasons, item.ConfidenceLaneReasons)
	current.TrustDepth = agginventory.MergeTrustDepth(current.TrustDepth, item.TrustDepth)
	current.SecurityTestRecipes = mergeSecurityTestRecipes(current.SecurityTestRecipes, item.SecurityTestRecipes)
	current.ApprovalStatus = mergeBacklogApprovalStatus(current.ApprovalStatus, item.ApprovalStatus)
	current.SecurityVisibility = mergeBacklogSecurityVisibility(current.SecurityVisibility, item.SecurityVisibility)
	if actionPriority(item.RecommendedAction) < actionPriority(current.RecommendedAction) {
		current.RecommendedAction = item.RecommendedAction
		current.SLA = slaForAction(item.RecommendedAction)
		current.ClosureCriteria = closureCriteriaForAction(item.RecommendedAction)
	}
	if queuePriority(item.Queue) < queuePriority(current.Queue) {
		current.Queue = item.Queue
		current.Remediation = item.Remediation
	}
	if visibilityPriority(item.FindingVisibility) < visibilityPriority(current.FindingVisibility) {
		current.FindingVisibility = item.FindingVisibility
	}
	if signalPriority(item.SignalClass) < signalPriority(current.SignalClass) {
		current.SignalClass = item.SignalClass
	}
	if confidencePriority(item.Confidence) < confidencePriority(current.Confidence) {
		current.Confidence = item.Confidence
	}
	if current.AgentID == "" {
		current.AgentID = item.AgentID
	}
	if current.Owner == "" {
		current.Owner = item.Owner
		current.OwnerSource = item.OwnerSource
		current.OwnershipStatus = item.OwnershipStatus
		current.OwnershipState = item.OwnershipState
		current.OwnershipConfidence = item.OwnershipConfidence
	}
	current.OwnershipEvidence = mergeStrings(current.OwnershipEvidence, item.OwnershipEvidence)
	current.OwnershipConflicts = mergeStrings(current.OwnershipConflicts, item.OwnershipConflicts)
	current.EvidenceDecisions = mergeEvidenceDecisions(current.EvidenceDecisions, item.EvidenceDecisions)
	current.Contradictions = mergeContradictions(current.Contradictions, item.Contradictions)
	current.ControlResolutionState = firstNonEmptyString(current.ControlResolutionState, item.ControlResolutionState)
	current.ControlResolutionReasons = mergeStrings(current.ControlResolutionReasons, item.ControlResolutionReasons)
	current.ControlEvidenceRefs = mergeStrings(current.ControlEvidenceRefs, item.ControlEvidenceRefs)
	current.ConstraintEvidenceClasses = mergeStrings(current.ConstraintEvidenceClasses, item.ConstraintEvidenceClasses)
	current.ConstraintEvidenceRefs = mergeStrings(current.ConstraintEvidenceRefs, item.ConstraintEvidenceRefs)
	current.ApprovalEvidenceState = firstNonEmptyString(current.ApprovalEvidenceState, item.ApprovalEvidenceState)
	current.OwnerEvidenceState = firstNonEmptyString(current.OwnerEvidenceState, item.OwnerEvidenceState)
	current.ProofEvidenceState = firstNonEmptyString(current.ProofEvidenceState, item.ProofEvidenceState)
	current.RuntimeEvidenceState = firstNonEmptyString(current.RuntimeEvidenceState, item.RuntimeEvidenceState)
	current.TargetEvidenceState = firstNonEmptyString(current.TargetEvidenceState, item.TargetEvidenceState)
	current.CredentialEvidenceState = firstNonEmptyString(current.CredentialEvidenceState, item.CredentialEvidenceState)
	current.TargetClass = firstNonEmptyString(current.TargetClass, item.TargetClass)
	current.TargetClassReasons = mergeStrings(current.TargetClassReasons, item.TargetClassReasons)
	current.TargetClassEvidenceRefs = mergeStrings(current.TargetClassEvidenceRefs, item.TargetClassEvidenceRefs)
	current.ActionPathType = firstNonEmptyString(current.ActionPathType, item.ActionPathType)
	current.ActionPathTypeReasons = mergeStrings(current.ActionPathTypeReasons, item.ActionPathTypeReasons)
	current.ActionPathTypeEvidenceRefs = mergeStrings(current.ActionPathTypeEvidenceRefs, item.ActionPathTypeEvidenceRefs)
	if current.LinkedActionPathID == "" {
		current.LinkedActionPathID = item.LinkedActionPathID
	}
	if current.LifecycleQueue == nil {
		current.LifecycleQueue = item.LifecycleQueue
	}
	if strings.TrimSpace(current.Remediation) == "" {
		current.Remediation = item.Remediation
	}
	if len(current.ClosureRequirements) == 0 {
		current.ClosureRequirements = risk.CloneClosureRequirements(item.ClosureRequirements)
	}
	if current.EvidenceCompleteness == nil {
		current.EvidenceCompleteness = risk.CloneEvidenceCompleteness(item.EvidenceCompleteness)
	}
	current.GovernanceControls = mergeGovernanceControls(current.GovernanceControls, item.GovernanceControls)
	current.ClosureCriteria = risk.ClosureCriteriaText(current.ClosureRequirements, current.ClosureCriteria)
	b.itemsByKey[key] = normalizeItem(current)
}

func (b *builder) addLifecycleGap(gap lifecycle.Gap) {
	linkedPath := b.actionPathByAgent[strings.TrimSpace(gap.AgentID)]
	if strings.TrimSpace(linkedPath.PathID) == "" {
		linkedPath = b.actionPathByKey[locationKey(gap.Org, gap.Repo, gap.Location)]
	}
	graphRefs := b.graphRefsByPath[strings.TrimSpace(linkedPath.PathID)]
	item := Item{
		ID:                       backlogID("lifecycle_gap", gap.AgentID, gap.ReasonCode, gap.Repo, gap.Location),
		AgentID:                  strings.TrimSpace(gap.AgentID),
		Repo:                     strings.TrimSpace(gap.Repo),
		Path:                     strings.TrimSpace(gap.Location),
		ControlSurfaceType:       controlSurfaceType(gap.ToolType, gap.Location, gap.WriteCapable, gap.CredentialAccess),
		ControlPathType:          controlPathType(gap.ToolType, gap.Location, gap.WriteCapable, gap.CredentialAccess),
		Capabilities:             lifecycleGapCapabilities(gap),
		WritePathClasses:         lifecycleGapWritePathClasses(gap),
		Owner:                    strings.TrimSpace(gap.Owner),
		OwnershipStatus:          strings.TrimSpace(gap.OwnershipStatus),
		EvidenceSource:           "lifecycle_gap",
		EvidenceBasis:            append([]string{gap.ReasonCode}, gap.EvidenceBasis...),
		ApprovalStatus:           "unapproved",
		SecurityVisibility:       agginventory.SecurityVisibilityNeedsReview,
		Queue:                    QueueReviewQueue,
		FindingVisibility:        FindingVisibilityPrimary,
		SignalClass:              SignalClassUniqueWrkrSignal,
		RecommendedAction:        lifecycleGapRecommendedAction(gap),
		Remediation:              remediationForLifecycleGap(gap),
		LinkedFindingIDs:         []string{gap.GapID},
		LinkedActionPathID:       strings.TrimSpace(linkedPath.PathID),
		LinkedControlPathNodeIDs: append([]string(nil), graphRefs.nodeIDs...),
		LinkedControlPathEdgeIDs: append([]string(nil), graphRefs.edgeIDs...),
		SecretSignalTypes:        lifecycleGapSecretSignalTypes(gap),
		LifecycleQueue:           lifecycleQueueForGap(gap),
	}
	item.Capability = capabilitySummary(item.Capabilities)
	item.GovernanceControls = agginventory.BuildGovernanceControls(agginventory.GovernanceControlInput{
		Owner:                    item.Owner,
		OwnershipStatus:          item.OwnershipStatus,
		ApprovalStatus:           gap.ApprovalStatus,
		LifecycleState:           gap.LifecycleState,
		SecurityVisibilityStatus: item.SecurityVisibility,
		WritePathClasses:         item.WritePathClasses,
		CredentialAccess:         gap.CredentialAccess,
		EvidenceBasis:            item.EvidenceBasis,
	})
	item.Confidence, item.EvidenceGaps, item.ConfidenceRaise = qualityForItem(item)
	item.SLA = slaForAction(item.RecommendedAction)
	item.ClosureCriteria = closureCriteriaForAction(item.RecommendedAction)
	item.SecurityTestRecipes = buildSecurityTestRecipes(item)
	b.merge(item)
}

func (b *builder) items() []Item {
	items := make([]Item, 0, len(b.itemsByKey))
	for _, item := range b.itemsByKey {
		items = append(items, b.decorateGovernance(normalizeItem(item)))
	}
	sort.Slice(items, func(i, j int) bool {
		if queuePriority(items[i].Queue) != queuePriority(items[j].Queue) {
			return queuePriority(items[i].Queue) < queuePriority(items[j].Queue)
		}
		if signalPriority(items[i].SignalClass) != signalPriority(items[j].SignalClass) {
			return signalPriority(items[i].SignalClass) < signalPriority(items[j].SignalClass)
		}
		if actionPriority(items[i].RecommendedAction) != actionPriority(items[j].RecommendedAction) {
			return actionPriority(items[i].RecommendedAction) < actionPriority(items[j].RecommendedAction)
		}
		if confidencePriority(items[i].Confidence) != confidencePriority(items[j].Confidence) {
			return confidencePriority(items[i].Confidence) < confidencePriority(items[j].Confidence)
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		if items[i].ControlPathType != items[j].ControlPathType {
			return items[i].ControlPathType < items[j].ControlPathType
		}
		return items[i].ID < items[j].ID
	})
	return items
}

func summarize(items []Item) Summary {
	summary := Summary{TotalItems: len(items)}
	for _, item := range items {
		switch item.Queue {
		case QueueControlFirst:
			summary.ControlFirstQueueItems++
		case QueueReviewQueue:
			summary.ReviewQueueItems++
		case QueueAcceptedRisk:
			summary.AcceptedRiskQueueItems++
		case QueueInventoryHygiene:
			summary.InventoryHygieneItems++
		case QueueDebugOnly:
			summary.DebugOnlyQueueItems++
		}
		if item.LifecycleQueue != nil {
			summary.LifecycleQueueItems++
		}
		switch item.SignalClass {
		case SignalClassUniqueWrkrSignal:
			summary.UniqueWrkrSignalItems++
		case SignalClassSupportingSecurity:
			summary.SupportingSecurityItems++
		}
		switch item.RecommendedAction {
		case ActionAttachEvidence:
			summary.AttachEvidenceActionItems++
		case ActionApprove:
			summary.ApproveActionItems++
		case ActionRemediate:
			summary.RemediateActionItems++
		}
	}
	return summary
}

func SummarizeItems(items []Item) Summary {
	return summarize(items)
}

func lifecycleQueueForGap(gap lifecycle.Gap) *governancequeue.Item {
	item := lifecycle.QueueItemFromGap(gap)
	return &item
}

func (b *builder) decorateGovernance(item Item) Item {
	record, ok := b.matchIdentityRecord(item)
	if !ok {
		return item
	}
	disposition := governanceDispositionForRecord(item, record, b.generatedAt)
	if disposition == nil {
		return item
	}
	item.GovernanceDisposition = disposition
	switch disposition.Status {
	case GovernanceStatusExpired:
		item.EvidenceGaps = mergeStrings(item.EvidenceGaps, []string{"governance_record_expired"})
	case GovernanceStatusInvalid:
		item.EvidenceGaps = mergeStrings(item.EvidenceGaps, []string{"governance_record_invalid"})
	case GovernanceStatusActive:
		switch disposition.Kind {
		case GovernanceKindAcceptedRisk:
			item.SecurityVisibility = agginventory.SecurityVisibilityAcceptedRisk
			item.Queue = QueueAcceptedRisk
			item.FindingVisibility = FindingVisibilityAppendix
		case GovernanceKindSuppression:
			item.Queue = QueueInventoryHygiene
			item.FindingVisibility = FindingVisibilityAppendix
		}
	}
	return normalizeItem(item)
}

func (b *builder) matchIdentityRecord(item Item) (manifest.IdentityRecord, bool) {
	if agentID := strings.TrimSpace(item.AgentID); agentID != "" {
		if record, ok := b.identityByAgent[agentID]; ok {
			return record, true
		}
	}
	if key := strings.TrimSpace(item.Repo) + "|" + strings.TrimSpace(item.Path); key != "|" {
		if record, ok := b.identityByRepoPath[key]; ok {
			return record, true
		}
	}
	return manifest.IdentityRecord{}, false
}

func governanceDispositionForRecord(item Item, record manifest.IdentityRecord, generatedAt time.Time) *GovernanceDisposition {
	approval := record.Approval
	reason := strings.TrimSpace(approval.DecisionReason)
	if reason == "" {
		reason = strings.TrimSpace(approval.ExclusionReason)
	}
	scope := strings.TrimSpace(approval.Scope)
	if scope == "" {
		scope = "control_path"
	}
	issuer := strings.TrimSpace(approval.Approver)
	if issuer == "" {
		issuer = strings.TrimSpace(approval.Owner)
	}
	evidenceState := governanceEvidenceState(item)
	expiresAt := strings.TrimSpace(approval.Expires)
	evidenceRefs := governanceEvidenceRefs(record)
	kind := ""
	visibilityBehavior := ""
	rescanBehavior := ""
	switch {
	case approval.AcceptedRisk || strings.TrimSpace(record.ApprovalState) == "accepted_risk" || strings.TrimSpace(record.ApprovalState) == "risk_accepted":
		kind = GovernanceKindAcceptedRisk
		visibilityBehavior = QueueAcceptedRisk
		rescanBehavior = "repromote_on_expiry"
	case strings.TrimSpace(approval.ExclusionReason) != "" || strings.TrimSpace(record.ApprovalState) == "excluded":
		kind = GovernanceKindSuppression
		visibilityBehavior = FindingVisibilityAppendix
		rescanBehavior = "retain_appendix_until_expiry"
	default:
		return nil
	}

	status := GovernanceStatusActive
	if strings.TrimSpace(reason) == "" || strings.TrimSpace(approval.Owner) == "" || expiresAt == "" {
		status = GovernanceStatusInvalid
	} else if expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			status = GovernanceStatusInvalid
		} else if !generatedAt.IsZero() && generatedAt.After(parsed.UTC()) {
			status = GovernanceStatusExpired
		}
	}

	return &GovernanceDisposition{
		Kind:               kind,
		Status:             status,
		Reason:             reason,
		Scope:              scope,
		Issuer:             issuer,
		ExpiresAt:          expiresAt,
		EvidenceState:      evidenceState,
		VisibilityBehavior: visibilityBehavior,
		RescanBehavior:     rescanBehavior,
		EvidenceRefs:       evidenceRefs,
	}
}

func governanceEvidenceState(item Item) string {
	values := []string{
		strings.TrimSpace(item.ApprovalEvidenceState),
		strings.TrimSpace(item.OwnerEvidenceState),
		strings.TrimSpace(item.ProofEvidenceState),
		strings.TrimSpace(item.RuntimeEvidenceState),
		strings.TrimSpace(item.TargetEvidenceState),
		strings.TrimSpace(item.CredentialEvidenceState),
	}
	if containsState(values, risk.EvidenceStateContradictory) {
		return risk.EvidenceStateContradictory
	}
	if containsState(values, risk.EvidenceStateUnknown) {
		return risk.EvidenceStateUnknown
	}
	if containsState(values, risk.EvidenceStateInferred) {
		return risk.EvidenceStateInferred
	}
	if containsState(values, risk.EvidenceStateDeclared) {
		return risk.EvidenceStateDeclared
	}
	if containsState(values, risk.EvidenceStateVerified) {
		return risk.EvidenceStateVerified
	}
	return risk.EvidenceStateUnknown
}

func containsState(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func governanceEvidenceRefs(record manifest.IdentityRecord) []string {
	values := []string{
		"manifest://identity/" + strings.TrimSpace(record.AgentID),
		strings.TrimSpace(record.Approval.ControlID),
		strings.TrimSpace(record.Approval.EvidenceURL),
	}
	return mergeStrings(values, nil)
}

func includeFinding(finding model.Finding, mode string) bool {
	if strings.TrimSpace(mode) != "deep" && findingGeneratedPath(finding) {
		return false
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "", "policy_check", "source_discovery":
		return false
	default:
		return true
	}
}

func parseErrorPath(finding model.Finding) string {
	if finding.ParseError == nil {
		return ""
	}
	return finding.ParseError.Path
}

func findingGeneratedPath(finding model.Finding) bool {
	return detect.IsGeneratedPath(finding.Location) || detect.IsGeneratedPath(parseErrorPath(finding))
}

func controlSurfaceType(toolType, location string, writeCapable bool, secret bool) string {
	tool := strings.ToLower(strings.TrimSpace(toolType))
	loc := strings.ToLower(strings.TrimSpace(location))
	switch {
	case secret && (writeCapable || strings.Contains(loc, ".github/workflows") || strings.Contains(loc, "jenkinsfile")):
		return ControlSurfaceSecretWorkflow
	case strings.Contains(loc, ".github/workflows") || strings.Contains(loc, "jenkinsfile") || tool == "ci_agent":
		if strings.Contains(loc, "release") || strings.Contains(loc, "deploy") {
			return ControlSurfaceReleaseAutomation
		}
		return ControlSurfaceCIAutomation
	case tool == "mcp" || strings.Contains(tool, "mcp"):
		return ControlSurfaceMCPServerTool
	case tool == "dependency" || strings.Contains(tool, "dependency"):
		return ControlSurfaceDependencyAgent
	case tool == "non_human_identity":
		return ControlSurfaceNonHumanIdentity
	case tool == "claude" || tool == "cursor" || tool == "codex" || tool == "copilot" || strings.Contains(loc, ".claude") || strings.Contains(loc, ".cursor") || strings.Contains(loc, ".codex") || strings.Contains(loc, "agents.md"):
		return ControlSurfaceCodingAssistant
	default:
		return ControlSurfaceAIAgent
	}
}

func controlPathType(toolType, location string, writeCapable bool, secret bool) string {
	surface := controlSurfaceType(toolType, location, writeCapable, secret)
	switch surface {
	case ControlSurfaceSecretWorkflow:
		return ControlPathSecretWorkflow
	case ControlSurfaceMCPServerTool:
		return ControlPathMCPTool
	case ControlSurfaceCIAutomation:
		return ControlPathCIAutomation
	case ControlSurfaceReleaseAutomation:
		return ControlPathReleaseWorkflow
	case ControlSurfaceDependencyAgent:
		return ControlPathDependencyAgent
	default:
		return ControlPathAgentConfig
	}
}

func capabilitiesFromActionPath(path risk.ActionPath) []string {
	values := make([]string, 0)
	if path.PullRequestWrite {
		values = append(values, "pr_write")
	}
	if path.MergeExecute {
		values = append(values, "repo_write")
	}
	if path.DeployWrite {
		values = append(values, "deploy")
	}
	if path.ProductionWrite {
		values = append(values, "production_write")
	}
	if path.WriteCapable {
		values = append(values, "write")
	}
	if path.CredentialAccess {
		values = append(values, "secret_access")
	}
	if path.TrustDepth != nil {
		if path.TrustDepth.Exposure == agginventory.TrustExposurePublic {
			values = append(values, "public_exposure")
		}
		if path.TrustDepth.DelegationModel == agginventory.TrustDelegationAgent {
			values = append(values, "delegation")
		}
	}
	return mergeStrings(values, nil)
}

func capabilitiesFromFinding(finding model.Finding, writeCapable bool) []string {
	values := make([]string, 0)
	if writeCapable {
		values = append(values, "write")
	}
	for _, permission := range finding.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		switch {
		case normalized == "pull_request.write":
			values = append(values, "pr_write")
		case normalized == "repo.write" || normalized == "filesystem.write":
			values = append(values, "repo_write")
		case normalized == "deploy.write":
			values = append(values, "deploy")
		case normalized == "iac.write":
			values = append(values, "infra_write")
		case normalized == "secret.read" || strings.Contains(normalized, "secret"):
			values = append(values, "secret_access")
		case normalized == "proc.exec" || normalized == "headless.execute":
			values = append(values, "execution")
		case strings.Contains(normalized, ".read"):
			values = append(values, "read")
		}
	}
	if isSecretFinding(finding) {
		values = append(values, "secret_access")
	}
	if trust := agginventory.TrustDepthFromFinding(finding); trust != nil {
		if trust.Exposure == agginventory.TrustExposurePublic {
			values = append(values, "public_exposure")
		}
		if trust.DelegationModel == agginventory.TrustDelegationAgent {
			values = append(values, "delegation")
		}
	}
	if len(values) == 0 {
		values = append(values, "read")
	}
	return mergeStrings(values, nil)
}

func lifecycleGapCapabilities(gap lifecycle.Gap) []string {
	values := make([]string, 0, 4)
	if gap.WriteCapable {
		values = append(values, "write")
	}
	if gap.CredentialAccess {
		values = append(values, "secret_access")
	}
	switch strings.TrimSpace(gap.ReasonCode) {
	case lifecycle.GapOwnerlessExposure:
		values = append(values, "ownerless_exposure")
	case lifecycle.GapRevokedStillPresent:
		values = append(values, "revoked_present")
	case lifecycle.GapApprovalExpired:
		values = append(values, "approval_expired")
	case lifecycle.GapPresenceDrift:
		values = append(values, "presence_drift")
	}
	if len(values) == 0 {
		values = append(values, "review")
	}
	return mergeStrings(values, nil)
}

func lifecycleGapWritePathClasses(gap lifecycle.Gap) []string {
	return agginventory.DeriveWritePathClasses(
		nil,
		gap.WriteCapable,
		false,
		false,
		false,
		gap.CredentialAccess,
		false,
		gap.Location,
		gap.ToolType,
	)
}

func writePathClassesFromActionPath(path risk.ActionPath) []string {
	if len(path.WritePathClasses) > 0 {
		return mergeStrings(path.WritePathClasses, nil)
	}
	return agginventory.DeriveWritePathClasses(
		nil,
		path.WriteCapable,
		path.PullRequestWrite,
		path.MergeExecute,
		path.DeployWrite,
		path.CredentialAccess,
		path.ProductionWrite,
		path.Location,
		path.ToolType,
	)
}

func writePathClassesFromFinding(finding model.Finding, tool agginventory.Tool, writeCapable bool) []string {
	if len(tool.WritePathClasses) > 0 {
		return mergeStrings(tool.WritePathClasses, nil)
	}
	permissions := append([]string(nil), finding.Permissions...)
	return agginventory.DeriveWritePathClasses(
		permissions,
		writeCapable,
		hasPermission(permissions, "pull_request.write"),
		hasPermission(permissions, "merge.execute"),
		hasPermission(permissions, "deploy.write"),
		isSecretFinding(finding),
		false,
		finding.Location,
		finding.ToolType,
	)
}

func hasPermission(permissions []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, permission := range permissions {
		if strings.ToLower(strings.TrimSpace(permission)) == want {
			return true
		}
	}
	return false
}

func evidenceBasisFromActionPath(path risk.ActionPath) []string {
	basis := []string{"risk_action_path"}
	if path.PullRequestWrite || path.WriteCapable {
		basis = append(basis, "workflow_permission")
	}
	if path.CredentialAccess {
		basis = append(basis, "secret_reference")
	}
	if path.OwnerSource != "" {
		basis = append(basis, path.OwnerSource)
	}
	if path.CredentialProvenance != nil {
		basis = append(basis, path.CredentialProvenance.EvidenceBasis...)
	}
	return mergeStrings(basis, nil)
}

func evidenceBasisForFinding(finding model.Finding) []string {
	basis := make([]string, 0)
	switch {
	case finding.ParseError != nil:
		basis = append(basis, "parse_error")
	case strings.Contains(strings.ToLower(finding.Location), ".github/workflows"):
		basis = append(basis, "workflow_permission")
	case isSecretFinding(finding):
		basis = append(basis, "secret_reference")
	case strings.TrimSpace(finding.Detector) != "":
		basis = append(basis, "direct_config")
	default:
		basis = append(basis, "static_finding")
	}
	for _, evidence := range finding.Evidence {
		key := strings.TrimSpace(evidence.Key)
		if key != "" {
			basis = append(basis, key)
		}
	}
	return mergeStrings(basis, nil)
}

func evidenceSourceForFinding(finding model.Finding) string {
	switch {
	case finding.ParseError != nil:
		return "parse_error"
	case isSecretFinding(finding):
		return "secret_reference"
	case strings.TrimSpace(finding.Detector) != "":
		return strings.TrimSpace(finding.Detector)
	default:
		return "static_analysis"
	}
}

func signalClassForFinding(finding model.Finding, writeCapable bool) string {
	if finding.ParseError != nil || detect.IsGeneratedPath(finding.Location) {
		return SignalClassSupportingSecurity
	}
	if isSecretFinding(finding) {
		if writeCapable {
			return SignalClassUniqueWrkrSignal
		}
		return SignalClassSupportingSecurity
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "secret_presence", "dependency_manifest", "dependency_signal", "parse_error":
		return SignalClassSupportingSecurity
	default:
		return SignalClassUniqueWrkrSignal
	}
}

func actionForFinding(finding model.Finding, writeCapable bool) string {
	if finding.ParseError != nil {
		if detect.IsGeneratedPath(finding.Location) {
			return ActionSuppress
		}
		return ActionDebugOnly
	}
	if isSecretFinding(finding) {
		if hasSecretValueEvidence(finding) {
			return ActionRemediate
		}
		return ActionAttachEvidence
	}
	if detect.IsGeneratedPath(finding.Location) {
		return ActionInventoryReview
	}
	if trust := agginventory.TrustDepthFromFinding(finding); trust != nil && trustExposureNeedsRemediation(trust) {
		return ActionRemediate
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "policy_violation", "skill_policy_conflict":
		return ActionRemediate
	case "dependency_manifest", "dependency_signal":
		return ActionInventoryReview
	}
	if writeCapable {
		return ActionApprove
	}
	return ActionAttachEvidence
}

func actionFromActionPath(action string, path risk.ActionPath) string {
	switch strings.TrimSpace(action) {
	case "control":
		if path.CredentialAccess && !path.ProductionWrite {
			return ActionAttachEvidence
		}
		return ActionRemediate
	case "approval":
		return ActionApprove
	case "proof":
		return ActionAttachEvidence
	case "inventory":
		return ActionInventoryReview
	default:
		if path.ApprovalGap {
			return ActionApprove
		}
		return ActionAttachEvidence
	}
}

func lifecycleGapRecommendedAction(gap lifecycle.Gap) string {
	switch strings.TrimSpace(gap.ReasonCode) {
	case lifecycle.GapRevokedStillPresent, lifecycle.GapOverApproved:
		return ActionRemediate
	case lifecycle.GapOwnerlessExposure, lifecycle.GapApprovalExpired, lifecycle.GapInactiveCredentialed:
		return ActionApprove
	default:
		return ActionAttachEvidence
	}
}

func secretSignalTypesForActionPath(path risk.ActionPath) []string {
	if !path.CredentialAccess {
		return nil
	}
	values := []string{SecretReferenceDetected, SecretRotationEvidenceMissing}
	if path.CredentialProvenance == nil || strings.TrimSpace(path.CredentialProvenance.Scope) == "" || strings.TrimSpace(path.CredentialProvenance.Scope) == agginventory.CredentialScopeUnknown {
		values = append(values, SecretScopeUnknown)
	}
	if path.WriteCapable || path.PullRequestWrite || path.DeployWrite || path.MergeExecute {
		values = append(values, SecretUsedByWriteCapableWorkflow)
	}
	if strings.TrimSpace(path.OperationalOwner) == "" || strings.TrimSpace(path.OwnershipStatus) == "unresolved" {
		values = append(values, SecretOwnerMissing)
	}
	return mergeStrings(values, nil)
}

func secretSignalTypesForFinding(finding model.Finding, writeCapable bool) []string {
	if !isSecretFinding(finding) {
		return nil
	}
	values := []string{SecretReferenceDetected, SecretScopeUnknown, SecretRotationEvidenceMissing}
	if hasSecretValueEvidence(finding) {
		values = append(values, SecretValueDetected)
	}
	if writeCapable {
		values = append(values, SecretUsedByWriteCapableWorkflow)
	}
	return mergeStrings(values, nil)
}

func lifecycleGapSecretSignalTypes(gap lifecycle.Gap) []string {
	if !gap.CredentialAccess {
		return nil
	}
	values := []string{SecretReferenceDetected}
	if gap.WriteCapable {
		values = append(values, SecretUsedByWriteCapableWorkflow)
	}
	if strings.TrimSpace(gap.Owner) == "" {
		values = append(values, SecretOwnerMissing)
	}
	return mergeStrings(values, nil)
}

func qualityForItem(item Item) (string, []string, []string) {
	gaps := make([]string, 0)
	raise := make([]string, 0)
	confidence := ConfidenceHigh
	switch {
	case strings.TrimSpace(item.OwnershipState) == "conflicting_owner" || strings.TrimSpace(item.OwnerSource) == "multi_repo_conflict":
		gaps = append(gaps, "owner_conflict")
		raise = append(raise, "resolve conflicting CODEOWNERS, service catalog, or owner mapping records")
		confidence = ConfidenceLow
	case strings.TrimSpace(item.Owner) == "":
		gaps = append(gaps, "owner_missing")
		raise = append(raise, "add CODEOWNERS or service ownership record")
		confidence = ConfidenceLow
	case strings.TrimSpace(item.OwnershipState) == "missing_owner" || strings.TrimSpace(item.OwnershipStatus) == "unresolved":
		gaps = append(gaps, "owner_missing")
		raise = append(raise, "add CODEOWNERS or service ownership record")
		confidence = ConfidenceLow
	case strings.TrimSpace(item.OwnershipState) == "inferred_owner" || strings.TrimSpace(item.OwnershipStatus) == "inferred" || strings.TrimSpace(item.OwnerSource) == "repo_fallback":
		gaps = append(gaps, "explicit_owner_evidence_missing")
		raise = append(raise, "replace fallback owner with CODEOWNERS or service catalog evidence")
		confidence = ConfidenceMedium
	}
	if item.OwnershipConfidence > 0 && item.OwnershipConfidence < 0.5 {
		gaps = append(gaps, "owner_confidence_low")
		if confidence == ConfidenceHigh || confidence == ConfidenceMedium {
			confidence = ConfidenceLow
		}
	}
	if strings.TrimSpace(item.ApprovalStatus) == "" || strings.TrimSpace(item.ApprovalStatus) == "unknown" || strings.TrimSpace(item.ApprovalStatus) == "unapproved" {
		gaps = append(gaps, "approval_evidence_missing")
		raise = append(raise, "attach an approval record with owner and expiry")
		if confidence == ConfidenceHigh {
			confidence = ConfidenceMedium
		}
	}
	if len(item.SecretSignalTypes) > 0 && credentialNeedsRotationEvidence(item.CredentialAuthority, item.CredentialProvenance) {
		gaps = append(gaps, "secret_rotation_evidence_missing")
		raise = append(raise, "attach secret rotation evidence")
	}
	if containsSecretSignal(item.SecretSignalTypes, SecretScopeUnknown) {
		gaps = append(gaps, "secret_scope_evidence_missing")
		raise = append(raise, "attach secret scope evidence")
	}
	if (item.CredentialAuthority != nil && strings.TrimSpace(item.CredentialAuthority.CredentialKind) == agginventory.CredentialKindUnknown) ||
		(item.CredentialProvenance != nil && strings.TrimSpace(item.CredentialProvenance.Type) == agginventory.CredentialProvenanceUnknown) {
		gaps = append(gaps, "credential_provenance_unknown")
		raise = append(raise, "classify whether the path uses static secrets, workload identity, OAuth delegation, JIT, or inherited human credentials")
		if confidence == ConfidenceHigh {
			confidence = ConfidenceMedium
		}
	}
	if item.TrustDepth != nil {
		for _, gap := range item.TrustDepth.TrustGaps {
			switch strings.TrimSpace(gap) {
			case "public_exposure", "gateway_unprotected", "delegation_without_policy", "policy_ref_missing", "sanitization_unspecified":
				gaps = append(gaps, "trust_depth_gap:"+strings.TrimSpace(gap))
			}
		}
		if len(item.TrustDepth.TrustGaps) > 0 {
			raise = append(raise, "review MCP/A2A trust-depth posture for gateway coverage, policy binding, and sanitization claims")
			if confidence == ConfidenceHigh {
				confidence = ConfidenceMedium
			}
		}
	}
	if item.RecommendedAction == ActionDebugOnly || item.RecommendedAction == ActionSuppress {
		confidence = ConfidenceLow
	}
	return confidence, mergeStrings(gaps, nil), mergeStrings(raise, nil)
}

func credentialNeedsRotationEvidence(authority *agginventory.CredentialAuthority, provenance *agginventory.CredentialProvenance) bool {
	normalizedAuthority := agginventory.NormalizeCredentialAuthority(authority)
	if normalizedAuthority != nil {
		switch strings.TrimSpace(normalizedAuthority.RotationEvidenceStatus) {
		case agginventory.CredentialRotationEvidencePresent, agginventory.CredentialRotationEvidenceNotApplicable:
			return false
		case agginventory.CredentialRotationEvidenceMissing, agginventory.CredentialRotationEvidenceStale, agginventory.CredentialRotationEvidenceUnknown:
			return true
		}
	}
	return agginventory.NormalizeCredentialProvenance(provenance) != nil
}

func mergeCredentialProvenance(current, incoming *agginventory.CredentialProvenance) *agginventory.CredentialProvenance {
	current = agginventory.NormalizeCredentialProvenance(current)
	incoming = agginventory.NormalizeCredentialProvenance(incoming)
	switch {
	case current == nil:
		return agginventory.CloneCredentialProvenance(incoming)
	case incoming == nil:
		return agginventory.CloneCredentialProvenance(current)
	case current.Type == incoming.Type && current.Subject == incoming.Subject && current.Scope == incoming.Scope:
		merged := agginventory.CloneCredentialProvenance(current)
		merged.EvidenceBasis = mergeStrings(merged.EvidenceBasis, incoming.EvidenceBasis)
		if confidencePriority(incoming.Confidence) < confidencePriority(merged.Confidence) {
			merged.Confidence = incoming.Confidence
		}
		if incoming.RiskMultiplier > merged.RiskMultiplier {
			merged.RiskMultiplier = incoming.RiskMultiplier
		}
		return agginventory.NormalizeCredentialProvenance(merged)
	default:
		return agginventory.NormalizeCredentialProvenance(&agginventory.CredentialProvenance{
			Type:           agginventory.CredentialProvenanceUnknown,
			Scope:          agginventory.CredentialScopeUnknown,
			Confidence:     ConfidenceLow,
			EvidenceBasis:  mergeStrings(append([]string{"credential_provenance_conflict"}, current.EvidenceBasis...), incoming.EvidenceBasis),
			RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceUnknown),
		})
	}
}

func mergeCredentialAuthority(current, incoming *agginventory.CredentialAuthority) *agginventory.CredentialAuthority {
	current = agginventory.NormalizeCredentialAuthority(current)
	incoming = agginventory.NormalizeCredentialAuthority(incoming)
	switch {
	case current == nil:
		return agginventory.CloneCredentialAuthority(incoming)
	case incoming == nil:
		return agginventory.CloneCredentialAuthority(current)
	default:
		merged := agginventory.CloneCredentialAuthority(current)
		merged.CredentialPresent = current.CredentialPresent || incoming.CredentialPresent
		merged.CredentialReferencedByWorkflow = current.CredentialReferencedByWorkflow || incoming.CredentialReferencedByWorkflow
		merged.CredentialUsableByPath = current.CredentialUsableByPath || incoming.CredentialUsableByPath
		merged.CredentialKind = firstNonEmptyString(merged.CredentialKind, incoming.CredentialKind)
		merged.AccessType = firstNonEmptyString(merged.AccessType, incoming.AccessType)
		merged.StandingAccess = current.StandingAccess || incoming.StandingAccess
		merged.LikelyJIT = current.LikelyJIT || incoming.LikelyJIT
		merged.RotationEvidenceStatus = firstNonEmptyString(merged.RotationEvidenceStatus, incoming.RotationEvidenceStatus)
		merged.CredentialSource = firstNonEmptyString(merged.CredentialSource, incoming.CredentialSource)
		if confidencePriority(incoming.Confidence) < confidencePriority(merged.Confidence) {
			merged.Confidence = incoming.Confidence
		}
		merged.ReasonCodes = mergeStrings(merged.ReasonCodes, incoming.ReasonCodes)
		return agginventory.NormalizeCredentialAuthority(merged)
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func approvalStatus(approvalGap bool, visibility string) string {
	if approvalGap {
		return "unapproved"
	}
	if strings.TrimSpace(visibility) == agginventory.SecurityVisibilityApproved || strings.TrimSpace(visibility) == agginventory.SecurityVisibilityKnownApproved {
		return "approved"
	}
	return "unknown"
}

func trustExposureNeedsRemediation(depth *agginventory.TrustDepth) bool {
	normalized := agginventory.NormalizeTrustDepth(depth)
	if normalized == nil {
		return false
	}
	if normalized.Exposure == agginventory.TrustExposurePublic && normalized.GatewayCoverage == agginventory.TrustCoverageUnprotected {
		return true
	}
	for _, gap := range normalized.TrustGaps {
		switch strings.TrimSpace(gap) {
		case "gateway_unprotected", "delegation_without_policy":
			return true
		}
	}
	return false
}

func findingWriteCapable(finding model.Finding) bool {
	for _, permission := range finding.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if strings.Contains(normalized, ".write") ||
			strings.Contains(normalized, "write") ||
			strings.Contains(normalized, "deploy") ||
			strings.Contains(normalized, "exec") {
			return true
		}
	}
	return false
}

func isSecretFinding(finding model.Finding) bool {
	if strings.TrimSpace(finding.FindingType) == "secret_presence" {
		return true
	}
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if strings.Contains(key, "secret") || strings.Contains(key, "credential") {
			return true
		}
	}
	return false
}

func hasSecretValueEvidence(finding model.Finding) bool {
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		value := strings.ToLower(strings.TrimSpace(evidence.Value))
		if key == "secret_value_detected" && value == "true" {
			return true
		}
		if key == "value_redacted" && value != "true" {
			return true
		}
	}
	return false
}

func (b *builder) linkedFindingIDs(org, repo, location string) []string {
	findings := b.findingsByLocation[locationKey(org, repo, location)]
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, findingID(finding))
	}
	return mergeStrings(ids, nil)
}

func locationKey(org, repo, location string) string {
	return strings.Join([]string{strings.TrimSpace(org), strings.TrimSpace(repo), strings.TrimSpace(location)}, "|")
}

func mergeKey(item Item) string {
	return strings.Join([]string{item.Repo, item.Path, item.ControlPathType, item.SignalClass}, "|")
}

func backlogID(parts ...string) string {
	joined := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(joined))
	return "cb-" + hex.EncodeToString(sum[:6])
}

func findingID(finding model.Finding) string {
	parts := []string{
		finding.Org,
		finding.Repo,
		finding.Location,
		finding.FindingType,
		finding.RuleID,
		finding.ToolType,
		finding.Detector,
	}
	return backlogID(parts...)
}

func normalizeItem(item Item) Item {
	item.AgentID = strings.TrimSpace(item.AgentID)
	item.Repo = strings.TrimSpace(item.Repo)
	item.Path = strings.TrimSpace(item.Path)
	item.ControlSurfaceType = fallback(item.ControlSurfaceType, ControlSurfaceAIAgent)
	item.ControlPathType = fallback(item.ControlPathType, ControlPathAgentConfig)
	item.Capabilities = mergeStrings(item.Capabilities, nil)
	item.Capability = capabilitySummary(item.Capabilities)
	item.WritePathClasses = mergeStrings(item.WritePathClasses, nil)
	item.EvidenceBasis = mergeStrings(item.EvidenceBasis, nil)
	item.OwnershipEvidence = mergeStrings(item.OwnershipEvidence, nil)
	item.OwnershipConflicts = mergeStrings(item.OwnershipConflicts, nil)
	item.ApprovalStatus = fallback(item.ApprovalStatus, "unknown")
	item.SecurityVisibility = agginventory.GovernanceSecurityVisibilityStatus(item.SecurityVisibility, item.ApprovalStatus, "")
	item.Queue = fallback(item.Queue, queueFromAction(item.RecommendedAction))
	item.FindingVisibility = fallback(item.FindingVisibility, visibilityForQueue(item.Queue))
	if !ValidSignalClass(item.SignalClass) {
		item.SignalClass = SignalClassSupportingSecurity
	}
	if !ValidRecommendedAction(item.RecommendedAction) {
		item.RecommendedAction = ActionAttachEvidence
	}
	if !ValidConfidence(item.Confidence) {
		item.Confidence = ConfidenceMedium
	}
	item.Remediation = fallback(item.Remediation, remediationForBacklogAction(item.RecommendedAction))
	item.SLA = fallback(item.SLA, slaForAction(item.RecommendedAction))
	item.ClosureRequirements = risk.CloneClosureRequirements(item.ClosureRequirements)
	item.EvidenceCompleteness = risk.CloneEvidenceCompleteness(item.EvidenceCompleteness)
	item.ClosureCriteria = risk.ClosureCriteriaText(item.ClosureRequirements, fallback(item.ClosureCriteria, closureCriteriaForAction(item.RecommendedAction)))
	item.EvidenceGaps = mergeStrings(item.EvidenceGaps, nil)
	item.ConfidenceRaise = mergeStrings(item.ConfidenceRaise, nil)
	item.ConfidenceLane = firstNonEmptyConfidenceLane(item.ConfidenceLane, "")
	item.ConfidenceLaneReasons = mergeStrings(item.ConfidenceLaneReasons, nil)
	item.SecretSignalTypes = mergeStrings(item.SecretSignalTypes, nil)
	item.LinkedFindingIDs = mergeStrings(item.LinkedFindingIDs, nil)
	if item.GovernanceDisposition != nil {
		item.GovernanceDisposition.Kind = strings.TrimSpace(item.GovernanceDisposition.Kind)
		item.GovernanceDisposition.Status = strings.TrimSpace(item.GovernanceDisposition.Status)
		item.GovernanceDisposition.Reason = strings.TrimSpace(item.GovernanceDisposition.Reason)
		item.GovernanceDisposition.Scope = strings.TrimSpace(item.GovernanceDisposition.Scope)
		item.GovernanceDisposition.Issuer = strings.TrimSpace(item.GovernanceDisposition.Issuer)
		item.GovernanceDisposition.ExpiresAt = strings.TrimSpace(item.GovernanceDisposition.ExpiresAt)
		item.GovernanceDisposition.EvidenceState = strings.TrimSpace(item.GovernanceDisposition.EvidenceState)
		item.GovernanceDisposition.VisibilityBehavior = strings.TrimSpace(item.GovernanceDisposition.VisibilityBehavior)
		item.GovernanceDisposition.RescanBehavior = strings.TrimSpace(item.GovernanceDisposition.RescanBehavior)
		item.GovernanceDisposition.EvidenceRefs = mergeStrings(item.GovernanceDisposition.EvidenceRefs, nil)
	}
	item.SecurityTestRecipes = mergeSecurityTestRecipes(item.SecurityTestRecipes, nil)
	item.GovernanceControls = mergeGovernanceControls(nil, item.GovernanceControls)
	return item
}

func mergeBacklogApprovalStatus(current, incoming string) string {
	if approvalStatusPriority(incoming) < approvalStatusPriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func approvalStatusPriority(value string) int {
	switch strings.TrimSpace(value) {
	case "unapproved":
		return 0
	case "unknown":
		return 1
	default:
		return 2
	}
}

func mergeBacklogSecurityVisibility(current, incoming string) string {
	if securityVisibilityPriority(incoming) < securityVisibilityPriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func securityVisibilityPriority(value string) int {
	switch strings.TrimSpace(value) {
	case agginventory.SecurityVisibilityApproved, agginventory.SecurityVisibilityKnownApproved:
		return 0
	case agginventory.SecurityVisibilityAcceptedRisk:
		return 1
	case agginventory.SecurityVisibilityKnownUnapproved:
		return 2
	case agginventory.SecurityVisibilityNeedsReview:
		return 3
	case agginventory.SecurityVisibilityUnknownToSecurity:
		return 4
	default:
		return 5
	}
}

func buildSecurityTestRecipes(item Item) []SecurityTestRecipe {
	recipes := make([]SecurityTestRecipe, 0, 6)
	evidenceRefs := mergeStrings(append([]string(nil), item.LinkedFindingIDs...), item.LinkedControlPathNodeIDs)
	requiredApprovals := []string{"security_review"}
	if item.RecommendedAction == ActionApprove || item.RecommendedAction == ActionRemediate {
		requiredApprovals = append(requiredApprovals, "owner_approval")
	}
	addRecipe := func(class, title, expected string, preconditions []string) {
		recipes = append(recipes, SecurityTestRecipe{
			ID:                  backlogID("security_test", item.ID, class),
			Class:               class,
			Title:               title,
			Preconditions:       mergeStrings(preconditions, nil),
			ExpectedObservation: expected,
			RequiredApprovals:   mergeStrings(requiredApprovals, nil),
			DryRunFlag:          "--dry-run",
			EvidenceRefs:        evidenceRefs,
		})
	}
	if item.TrustDepth != nil && item.TrustDepth.Exposure == agginventory.TrustExposurePublic && item.TrustDepth.GatewayCoverage != agginventory.TrustCoverageProtected {
		addRecipe("mcp_endpoint_swap", "Validate gateway binding against endpoint swap", "Control path rejects or logs the swapped MCP/A2A endpoint without granting unreviewed capability.", []string{"use a staging or disposable endpoint", "confirm deny-by-default gateway policy is present"})
	}
	if contains(item.Capabilities, "delegation") {
		addRecipe("prompt_injection", "Validate delegation prompt boundary", "Delegation request is denied, sanitized, or routed through approved policy enforcement.", []string{"use a non-production prompt fixture", "log policy decision and target agent identity"})
	}
	if contains(item.Capabilities, "write") || contains(item.Capabilities, "deploy") || contains(item.Capabilities, "repo_write") || contains(item.Capabilities, "pr_write") {
		addRecipe("destructive_action_dry_run", "Validate destructive action dry-run path", "Action path stays in dry-run or approval-gated mode and produces auditable evidence instead of mutating systems.", []string{"target a sandbox or preview environment", "verify rollback path and operator ownership"})
	}
	if item.CredentialProvenance != nil || contains(item.Capabilities, "secret_access") {
		addRecipe("secret_scope_validation", "Validate secret scope and provenance", "Path only receives the minimum expected secret scope and surfaces provenance or denial evidence.", []string{"use non-production credentials or a simulator", "capture secret scope evidence without revealing values"})
	}
	if item.ControlPathType == ControlPathCIAutomation || item.ControlPathType == ControlPathReleaseWorkflow {
		addRecipe("untrusted_repo_content", "Validate untrusted repository content handling", "Workflow does not promote untrusted repository content into privileged execution without policy gates.", []string{"run against a fixture branch with controlled untrusted content", "confirm approvals and content-origin checks are enabled"})
	}
	if item.TrustDepth != nil && item.TrustDepth.Exposure == agginventory.TrustExposurePublic {
		addRecipe("egress_attempt", "Validate outbound egress controls", "Publicly reachable path cannot exfiltrate or reach blocked destinations beyond declared policy.", []string{"use a sink or denied test endpoint", "confirm audit logging for blocked egress"})
	}
	return mergeSecurityTestRecipes(recipes, nil)
}

func mergeSecurityTestRecipes(current, incoming []SecurityTestRecipe) []SecurityTestRecipe {
	recipes := append(append([]SecurityTestRecipe(nil), current...), incoming...)
	if len(recipes) == 0 {
		return nil
	}
	byID := map[string]SecurityTestRecipe{}
	for _, recipe := range recipes {
		if strings.TrimSpace(recipe.ID) == "" {
			continue
		}
		currentItem, ok := byID[recipe.ID]
		if !ok {
			currentItem = recipe
		}
		currentItem.Preconditions = mergeStrings(currentItem.Preconditions, recipe.Preconditions)
		currentItem.RequiredApprovals = mergeStrings(currentItem.RequiredApprovals, recipe.RequiredApprovals)
		currentItem.EvidenceRefs = mergeStrings(currentItem.EvidenceRefs, recipe.EvidenceRefs)
		if currentItem.Title == "" {
			currentItem.Title = recipe.Title
		}
		if currentItem.ExpectedObservation == "" {
			currentItem.ExpectedObservation = recipe.ExpectedObservation
		}
		if currentItem.Class == "" {
			currentItem.Class = recipe.Class
		}
		if currentItem.DryRunFlag == "" {
			currentItem.DryRunFlag = recipe.DryRunFlag
		}
		byID[currentItem.ID] = currentItem
	}
	out := make([]SecurityTestRecipe, 0, len(byID))
	for _, recipe := range byID {
		out = append(out, recipe)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].ID < out[j].ID
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func mergeGovernanceControls(a, b []agginventory.GovernanceControlMapping) []agginventory.GovernanceControlMapping {
	byControl := map[string]agginventory.GovernanceControlMapping{}
	for _, item := range append(append([]agginventory.GovernanceControlMapping(nil), a...), b...) {
		control := strings.TrimSpace(item.Control)
		if control == "" {
			continue
		}
		item.Control = control
		item.Evidence = mergeStrings(item.Evidence, nil)
		item.Gaps = mergeStrings(item.Gaps, nil)
		current, exists := byControl[control]
		if !exists || controlStatusPriority(item.Status) < controlStatusPriority(current.Status) {
			byControl[control] = item
			continue
		}
		if controlStatusPriority(item.Status) == controlStatusPriority(current.Status) {
			current.Evidence = mergeStrings(current.Evidence, item.Evidence)
			current.Gaps = mergeStrings(current.Gaps, item.Gaps)
			byControl[control] = current
		}
	}
	out := make([]agginventory.GovernanceControlMapping, 0, len(byControl))
	for _, item := range byControl {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Control < out[j].Control
	})
	return out
}

func controlStatusPriority(status string) int {
	switch strings.TrimSpace(status) {
	case agginventory.ControlStatusGap:
		return 0
	case agginventory.ControlStatusSatisfied:
		return 1
	case agginventory.ControlStatusNotApplicable:
		return 2
	default:
		return 3
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func capabilitySummary(values []string) string {
	values = mergeStrings(values, nil)
	if len(values) == 0 {
		return "read"
	}
	return strings.Join(values, " + ")
}

func slaForAction(action string) string {
	switch action {
	case ActionRemediate:
		return "7d"
	case ActionAttachEvidence, ActionApprove:
		return "14d"
	case ActionInventoryReview, ActionDowngrade, ActionDeprecate, ActionMonitor:
		return "30d"
	default:
		return "none"
	}
}

func closureCriteriaForAction(action string) string {
	switch action {
	case ActionAttachEvidence:
		return "Attach owner, scope, approval, and proof evidence for this control path."
	case ActionApprove:
		return "Record owner-approved, time-bounded approval evidence and rescan."
	case ActionRemediate:
		return "Remove or reduce the unsafe control path and rescan until the backlog item closes."
	case ActionInventoryReview:
		return "Confirm owner, scope, production relevance, and whether to approve, deprecate, or exclude."
	case ActionSuppress:
		return "Confirm generated or out-of-scope evidence and keep it in scan quality, not active backlog."
	case ActionDebugOnly:
		return "Review parser/debug context and fix only if it affects control-path visibility."
	case ActionDowngrade:
		return "Document non-production or low-criticality context and rescan."
	case ActionDeprecate:
		return "Record deprecation reason and confirm the path no longer executes."
	case ActionExclude:
		return "Record false-positive or out-of-scope rationale with review owner."
	default:
		return "Monitor for drift and rescan on owner, approval, or capability change."
	}
}

func signalPriority(value string) int {
	if value == SignalClassUniqueWrkrSignal {
		return 0
	}
	return 1
}

func queuePriority(value string) int {
	switch strings.TrimSpace(value) {
	case QueueControlFirst:
		return 0
	case QueueReviewQueue:
		return 1
	case QueueAcceptedRisk:
		return 2
	case QueueInventoryHygiene:
		return 3
	case QueueDebugOnly:
		return 4
	default:
		return 99
	}
}

func visibilityPriority(value string) int {
	switch strings.TrimSpace(value) {
	case FindingVisibilityPrimary:
		return 0
	case FindingVisibilityAppendix:
		return 1
	case FindingVisibilityDebug:
		return 2
	default:
		return 99
	}
}

func actionPriority(value string) int {
	switch value {
	case ActionRemediate:
		return 0
	case ActionAttachEvidence:
		return 1
	case ActionApprove:
		return 2
	case ActionInventoryReview:
		return 3
	case ActionMonitor:
		return 4
	case ActionDowngrade, ActionDeprecate:
		return 5
	case ActionExclude, ActionSuppress:
		return 6
	case ActionDebugOnly:
		return 7
	default:
		return 99
	}
}

func confidencePriority(value string) int {
	switch value {
	case ConfidenceHigh:
		return 0
	case ConfidenceMedium:
		return 1
	default:
		return 2
	}
}

func mergeStrings(a, b []string) []string {
	set := map[string]struct{}{}
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mergeEvidenceDecisions(current, incoming []evidencepolicy.Decision) []evidencepolicy.Decision {
	if len(current) == 0 && len(incoming) == 0 {
		return nil
	}
	byField := map[string]evidencepolicy.Decision{}
	for _, item := range append(append([]evidencepolicy.Decision(nil), current...), incoming...) {
		field := strings.TrimSpace(item.Field)
		if field == "" {
			continue
		}
		byField[field] = item
	}
	out := make([]evidencepolicy.Decision, 0, len(byField))
	for _, item := range byField {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field < out[j].Field })
	return out
}

func mergeContradictions(current, incoming []evidencepolicy.Contradiction) []evidencepolicy.Contradiction {
	if len(current) == 0 && len(incoming) == 0 {
		return nil
	}
	seen := map[string]evidencepolicy.Contradiction{}
	for _, item := range append(append([]evidencepolicy.Contradiction(nil), current...), incoming...) {
		key := strings.Join([]string{
			strings.TrimSpace(item.Class),
			strings.TrimSpace(item.ImpactedTarget),
			strings.Join(item.ReasonCodes, "|"),
		}, "|")
		seen[key] = item
	}
	out := make([]evidencepolicy.Contradiction, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Class != out[j].Class {
			return out[i].Class < out[j].Class
		}
		return out[i].ImpactedTarget < out[j].ImpactedTarget
	})
	return out
}

func containsSecretSignal(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fallbackValue)
}

func firstNonEmptyConfidenceLane(current, incoming string) string {
	if strings.TrimSpace(current) != "" {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(incoming)
}

func queueFromActionPath(path risk.ActionPath) string {
	if strings.TrimSpace(path.ReviewBurden) == risk.ReviewBurdenCritical ||
		strings.TrimSpace(path.ControlPriority) == risk.ControlPriorityControlFirst {
		return QueueControlFirst
	}
	switch strings.TrimSpace(path.ControlState) {
	case risk.ControlStateBlockRecommend:
		return QueueControlFirst
	case risk.ControlStateApprovalNeeded, risk.ControlStateEvidenceNeeded:
		return QueueReviewQueue
	case risk.ControlStateInventoryOnly:
		return QueueInventoryHygiene
	}
	switch strings.TrimSpace(path.ControlPriority) {
	case risk.ControlPriorityControlFirst:
		return QueueControlFirst
	case risk.ControlPriorityInventoryHygiene:
		return QueueInventoryHygiene
	default:
		return QueueReviewQueue
	}
}

func visibilityFromActionPath(path risk.ActionPath) string {
	return visibilityForQueue(queueFromActionPath(path))
}

func queueFromFinding(finding model.Finding, writeCapable bool) string {
	switch actionForFinding(finding, writeCapable) {
	case ActionDebugOnly, ActionSuppress:
		return QueueDebugOnly
	case ActionInventoryReview:
		return QueueInventoryHygiene
	default:
		return QueueReviewQueue
	}
}

func visibilityFromFinding(finding model.Finding, writeCapable bool) string {
	return visibilityForQueue(queueFromFinding(finding, writeCapable))
}

func visibilityForQueue(queue string) string {
	switch strings.TrimSpace(queue) {
	case QueueControlFirst, QueueReviewQueue:
		return FindingVisibilityPrimary
	case QueueAcceptedRisk, QueueInventoryHygiene:
		return FindingVisibilityAppendix
	default:
		return FindingVisibilityDebug
	}
}

func queueFromAction(action string) string {
	switch strings.TrimSpace(action) {
	case ActionDebugOnly, ActionSuppress:
		return QueueDebugOnly
	case ActionInventoryReview:
		return QueueInventoryHygiene
	default:
		return QueueReviewQueue
	}
}

func remediationForFinding(finding model.Finding, writeCapable bool) string {
	if finding.ParseError != nil {
		if detect.IsGeneratedPath(finding.Location) {
			return "Keep this generated or bundled parser noise in debug coverage unless it blocks control-path visibility."
		}
		return "Review this parser diagnostic only if it affects MCP, framework, or control-path coverage; otherwise keep it out of the primary remediation queue."
	}
	if detect.IsGeneratedPath(finding.Location) {
		return "Treat this generated artifact as appendix or accepted inventory unless higher-confidence source evidence proves it is an active control path."
	}
	if isSecretFinding(finding) {
		if hasSecretValueEvidence(finding) {
			return "Rotate or revoke the exposed credential, replace it with brokered or JIT access where possible, and rescan."
		}
		if writeCapable {
			return "Attach owner, scope, and rotation evidence for this credential-bearing write path and confirm whether standing access can be reduced."
		}
		return "Attach owner, scope, and rotation evidence for this credential reference before treating it as approved inventory."
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "dependency_manifest", "dependency_signal":
		return "Confirm whether this dependency signal reflects active agent behavior; suppress it as accepted inventory unless source-level binding evidence exists."
	case "policy_violation", "skill_policy_conflict":
		return "Fix the failing policy condition, attach the policy reference or approval evidence, and rescan."
	default:
		return remediationForBacklogAction(actionForFinding(finding, writeCapable))
	}
}

func remediationForLifecycleGap(gap lifecycle.Gap) string {
	switch strings.TrimSpace(gap.ReasonCode) {
	case lifecycle.GapRevokedStillPresent, lifecycle.GapOverApproved:
		return "Remove or reduce this stale high-authority path, record the lifecycle decision, and rescan."
	case lifecycle.GapOwnerlessExposure:
		return "Assign an explicit owner and attach review evidence before this path keeps running with unclear accountability."
	default:
		return "Record the missing lifecycle review evidence for this path and rescan."
	}
}

func remediationForBacklogAction(action string) string {
	switch strings.TrimSpace(action) {
	case ActionRemediate:
		return "Reduce or remove the risky capability on this path, attach proof of the change, and rescan."
	case ActionApprove:
		return "Record a time-bounded owner approval with scope and expiry, then rescan."
	case ActionAttachEvidence:
		return "Attach owner, policy, proof, or credential-scope evidence for this exact path and rescan."
	case ActionInventoryReview:
		return "Confirm whether this item is active, accepted inventory, or suppression-worthy before it stays in the buyer-facing backlog."
	case ActionSuppress:
		return "Keep this item in coverage or appendix output only after recording the suppression rationale."
	default:
		return "Review this item, attach the missing evidence, and rescan."
	}
}
