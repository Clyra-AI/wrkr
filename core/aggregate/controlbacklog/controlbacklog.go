package controlbacklog

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const BacklogVersion = "1"

const (
	SignalClassUniqueWrkrSignal      = "unique_wrkr_signal"
	SignalClassSupportingSecurity    = "supporting_security_signal"
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
}

type Item struct {
	ID                       string                                  `json:"id"`
	Repo                     string                                  `json:"repo"`
	Path                     string                                  `json:"path"`
	ControlSurfaceType       string                                  `json:"control_surface_type"`
	ControlPathType          string                                  `json:"control_path_type"`
	Capability               string                                  `json:"capability"`
	Capabilities             []string                                `json:"capabilities,omitempty"`
	WritePathClasses         []string                                `json:"write_path_classes,omitempty"`
	GovernanceControls       []agginventory.GovernanceControlMapping `json:"governance_controls,omitempty"`
	Owner                    string                                  `json:"owner,omitempty"`
	OwnerSource              string                                  `json:"owner_source,omitempty"`
	OwnershipStatus          string                                  `json:"ownership_status,omitempty"`
	OwnershipState           string                                  `json:"ownership_state,omitempty"`
	OwnershipConfidence      float64                                 `json:"ownership_confidence,omitempty"`
	OwnershipEvidence        []string                                `json:"ownership_evidence_basis,omitempty"`
	OwnershipConflicts       []string                                `json:"ownership_conflicts,omitempty"`
	EvidenceSource           string                                  `json:"evidence_source"`
	EvidenceBasis            []string                                `json:"evidence_basis"`
	ApprovalStatus           string                                  `json:"approval_status"`
	SecurityVisibility       string                                  `json:"security_visibility"`
	SignalClass              string                                  `json:"signal_class"`
	RecommendedAction        string                                  `json:"recommended_action"`
	Confidence               string                                  `json:"confidence"`
	EvidenceGaps             []string                                `json:"evidence_gaps,omitempty"`
	ConfidenceRaise          []string                                `json:"confidence_raise,omitempty"`
	SLA                      string                                  `json:"sla"`
	ClosureCriteria          string                                  `json:"closure_criteria"`
	SecretSignalTypes        []string                                `json:"secret_signal_types,omitempty"`
	LinkedFindingIDs         []string                                `json:"linked_finding_ids,omitempty"`
	LinkedActionPathID       string                                  `json:"linked_action_path_id,omitempty"`
	LinkedControlPathNodeIDs []string                                `json:"linked_control_path_node_ids,omitempty"`
	LinkedControlPathEdgeIDs []string                                `json:"linked_control_path_edge_ids,omitempty"`
	CredentialProvenance     *agginventory.CredentialProvenance      `json:"credential_provenance,omitempty"`
}

type Input struct {
	Mode             string
	Findings         []model.Finding
	Inventory        *agginventory.Inventory
	ActionPaths      []risk.ActionPath
	ControlPathGraph *aggattack.ControlPathGraph
}

func Build(input Input) Backlog {
	builder := newBuilder(input)
	for _, path := range input.ActionPaths {
		builder.addActionPath(path)
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
	writeByLocation    map[string]bool
	itemsByKey         map[string]Item
	graphRefsByPath    map[string]controlPathRefs
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
		writeByLocation:    map[string]bool{},
		itemsByKey:         map[string]Item{},
		graphRefsByPath:    buildControlPathRefs(input.ControlPathGraph),
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
	graphRefs := b.graphRefsByPath[strings.TrimSpace(path.PathID)]
	item := Item{
		ID:                       backlogID("action_path", path.Org, path.Repo, path.Location, path.PathID),
		Repo:                     strings.TrimSpace(path.Repo),
		Path:                     strings.TrimSpace(path.Location),
		ControlSurfaceType:       controlSurfaceType(path.ToolType, path.Location, path.CredentialAccess, false),
		ControlPathType:          controlPathType(path.ToolType, path.Location, path.CredentialAccess, false),
		Capabilities:             capabilitiesFromActionPath(path),
		WritePathClasses:         writePathClassesFromActionPath(path),
		GovernanceControls:       append([]agginventory.GovernanceControlMapping(nil), path.GovernanceControls...),
		Owner:                    strings.TrimSpace(path.OperationalOwner),
		OwnerSource:              strings.TrimSpace(path.OwnerSource),
		OwnershipStatus:          strings.TrimSpace(path.OwnershipStatus),
		OwnershipState:           strings.TrimSpace(path.OwnershipState),
		OwnershipConfidence:      path.OwnershipConfidence,
		OwnershipEvidence:        append([]string(nil), path.OwnershipEvidence...),
		OwnershipConflicts:       append([]string(nil), path.OwnershipConflicts...),
		EvidenceSource:           "risk_action_path",
		EvidenceBasis:            evidenceBasisFromActionPath(path),
		ApprovalStatus:           approvalStatus(path.ApprovalGap, path.SecurityVisibilityStatus),
		SecurityVisibility:       agginventory.GovernanceSecurityVisibilityStatus(path.SecurityVisibilityStatus, "", ""),
		SignalClass:              SignalClassUniqueWrkrSignal,
		RecommendedAction:        actionFromActionPath(path.RecommendedAction, path),
		LinkedActionPathID:       path.PathID,
		LinkedControlPathNodeIDs: append([]string(nil), graphRefs.nodeIDs...),
		LinkedControlPathEdgeIDs: append([]string(nil), graphRefs.edgeIDs...),
		CredentialProvenance:     agginventory.CloneCredentialProvenance(path.CredentialProvenance),
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
	item.ClosureCriteria = closureCriteriaForAction(item.RecommendedAction)
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
		SignalClass:         signalClassForFinding(finding, writeCapable),
		RecommendedAction:   actionForFinding(finding, writeCapable),
		LinkedFindingIDs:    []string{findingID(finding)},
		SecretSignalTypes:   secretSignalTypesForFinding(finding, writeCapable),
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
	if actionPriority(item.RecommendedAction) < actionPriority(current.RecommendedAction) {
		current.RecommendedAction = item.RecommendedAction
		current.SLA = slaForAction(item.RecommendedAction)
		current.ClosureCriteria = closureCriteriaForAction(item.RecommendedAction)
	}
	if signalPriority(item.SignalClass) < signalPriority(current.SignalClass) {
		current.SignalClass = item.SignalClass
	}
	if confidencePriority(item.Confidence) < confidencePriority(current.Confidence) {
		current.Confidence = item.Confidence
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
	if current.LinkedActionPathID == "" {
		current.LinkedActionPathID = item.LinkedActionPathID
	}
	current.GovernanceControls = mergeGovernanceControls(current.GovernanceControls, item.GovernanceControls)
	b.itemsByKey[key] = normalizeItem(current)
}

func (b *builder) items() []Item {
	items := make([]Item, 0, len(b.itemsByKey))
	for _, item := range b.itemsByKey {
		items = append(items, normalizeItem(item))
	}
	sort.Slice(items, func(i, j int) bool {
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
	if len(values) == 0 {
		values = append(values, "read")
	}
	return mergeStrings(values, nil)
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
	if len(item.SecretSignalTypes) > 0 {
		gaps = append(gaps, "secret_scope_evidence_missing", "secret_rotation_evidence_missing")
		raise = append(raise, "attach secret scope and rotation evidence")
	}
	if item.CredentialProvenance != nil && strings.TrimSpace(item.CredentialProvenance.Type) == agginventory.CredentialProvenanceUnknown {
		gaps = append(gaps, "credential_provenance_unknown")
		raise = append(raise, "classify whether the path uses static secrets, workload identity, OAuth delegation, JIT, or inherited human credentials")
		if confidence == ConfidenceHigh {
			confidence = ConfidenceMedium
		}
	}
	if item.RecommendedAction == ActionDebugOnly || item.RecommendedAction == ActionSuppress {
		confidence = ConfidenceLow
	}
	return confidence, mergeStrings(gaps, nil), mergeStrings(raise, nil)
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
	if !ValidSignalClass(item.SignalClass) {
		item.SignalClass = SignalClassSupportingSecurity
	}
	if !ValidRecommendedAction(item.RecommendedAction) {
		item.RecommendedAction = ActionAttachEvidence
	}
	if !ValidConfidence(item.Confidence) {
		item.Confidence = ConfidenceMedium
	}
	item.SLA = fallback(item.SLA, slaForAction(item.RecommendedAction))
	item.ClosureCriteria = fallback(item.ClosureCriteria, closureCriteriaForAction(item.RecommendedAction))
	item.EvidenceGaps = mergeStrings(item.EvidenceGaps, nil)
	item.ConfidenceRaise = mergeStrings(item.ConfidenceRaise, nil)
	item.SecretSignalTypes = mergeStrings(item.SecretSignalTypes, nil)
	item.LinkedFindingIDs = mergeStrings(item.LinkedFindingIDs, nil)
	item.GovernanceControls = mergeGovernanceControls(nil, item.GovernanceControls)
	return item
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

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fallbackValue)
}
