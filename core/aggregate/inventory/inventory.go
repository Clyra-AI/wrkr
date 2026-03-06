package inventory

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/exposure"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/owners"
	"github.com/Clyra-AI/wrkr/core/source"
)

type ToolLocation struct {
	Repo     string `json:"repo" yaml:"repo"`
	Location string `json:"location" yaml:"location"`
	Owner    string `json:"owner" yaml:"owner"`
}

type Agent struct {
	AgentID                string               `json:"agent_id" yaml:"agent_id"`
	AgentInstanceID        string               `json:"agent_instance_id" yaml:"agent_instance_id"`
	Framework              string               `json:"framework" yaml:"framework"`
	Org                    string               `json:"org" yaml:"org"`
	Repo                   string               `json:"repo" yaml:"repo"`
	Location               string               `json:"location" yaml:"location"`
	LocationRange          *model.LocationRange `json:"location_range,omitempty" yaml:"location_range,omitempty"`
	BoundTools             []string             `json:"bound_tools,omitempty" yaml:"bound_tools,omitempty"`
	BoundDataSources       []string             `json:"bound_data_sources,omitempty" yaml:"bound_data_sources,omitempty"`
	BoundAuthSurfaces      []string             `json:"bound_auth_surfaces,omitempty" yaml:"bound_auth_surfaces,omitempty"`
	BindingEvidenceKeys    []string             `json:"binding_evidence_keys,omitempty" yaml:"binding_evidence_keys,omitempty"`
	MissingBindings        []string             `json:"missing_bindings,omitempty" yaml:"missing_bindings,omitempty"`
	DeploymentStatus       string               `json:"deployment_status,omitempty" yaml:"deployment_status,omitempty"`
	DeploymentArtifacts    []string             `json:"deployment_artifacts,omitempty" yaml:"deployment_artifacts,omitempty"`
	DeploymentEvidenceKeys []string             `json:"deployment_evidence_keys,omitempty" yaml:"deployment_evidence_keys,omitempty"`
}

type AgentBindingContext struct {
	BoundTools          []string
	BoundDataSources    []string
	BoundAuthSurfaces   []string
	BindingEvidenceKeys []string
	MissingBindings     []string
}

type AgentDeploymentContext struct {
	DeploymentStatus       string
	DeploymentArtifacts    []string
	DeploymentEvidenceKeys []string
}

type Tool struct {
	ToolID            string             `json:"tool_id" yaml:"tool_id"`
	AgentID           string             `json:"agent_id" yaml:"agent_id"`
	DiscoveryMethod   string             `json:"discovery_method" yaml:"discovery_method"`
	ToolType          string             `json:"tool_type" yaml:"tool_type"`
	ToolCategory      string             `json:"tool_category" yaml:"tool_category"`
	ConfidenceScore   float64            `json:"confidence_score" yaml:"confidence_score"`
	Org               string             `json:"org" yaml:"org"`
	Repos             []string           `json:"repos" yaml:"repos"`
	Locations         []ToolLocation     `json:"locations" yaml:"locations"`
	Permissions       []string           `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	PermissionSurface PermissionSurface  `json:"permission_surface" yaml:"permission_surface"`
	PermissionTier    string             `json:"permission_tier" yaml:"permission_tier"`
	RiskTier          string             `json:"risk_tier" yaml:"risk_tier"`
	AdoptionPattern   string             `json:"adoption_pattern" yaml:"adoption_pattern"`
	RegulatoryMapping []RegulatoryStatus `json:"regulatory_mapping" yaml:"regulatory_mapping"`
	EndpointClass     string             `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass         string             `json:"data_class" yaml:"data_class"`
	AutonomyLevel     string             `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore         float64            `json:"risk_score" yaml:"risk_score"`
	ApprovalStatus    string             `json:"approval_status" yaml:"approval_status"`
	ApprovalClass     string             `json:"approval_classification" yaml:"approval_classification"`
	LifecycleState    string             `json:"lifecycle_state" yaml:"lifecycle_state"`
}

type PermissionSurface struct {
	Read  bool `json:"read" yaml:"read"`
	Write bool `json:"write" yaml:"write"`
	Admin bool `json:"admin" yaml:"admin"`
}

type RegulatoryStatus struct {
	Regulation string `json:"regulation" yaml:"regulation"`
	ControlID  string `json:"control_id" yaml:"control_id"`
	Status     string `json:"status" yaml:"status"`
	Rationale  string `json:"rationale" yaml:"rationale"`
}

type Summary struct {
	TotalTools int `json:"total_tools" yaml:"total_tools"`
	HighRisk   int `json:"high_risk" yaml:"high_risk"`
	MediumRisk int `json:"medium_risk" yaml:"medium_risk"`
	LowRisk    int `json:"low_risk" yaml:"low_risk"`
}

type Inventory struct {
	InventoryVersion      string                         `json:"inventory_version" yaml:"inventory_version"`
	GeneratedAt           string                         `json:"generated_at" yaml:"generated_at"`
	Org                   string                         `json:"org" yaml:"org"`
	Agents                []Agent                        `json:"agents" yaml:"agents"`
	Tools                 []Tool                         `json:"tools" yaml:"tools"`
	Methodology           MethodologySummary             `json:"methodology" yaml:"methodology"`
	ApprovalSummary       ApprovalSummary                `json:"approval_summary" yaml:"approval_summary"`
	AdoptionSummary       AdoptionSummary                `json:"adoption_summary" yaml:"adoption_summary"`
	RegulatorySummary     RegulatorySummary              `json:"regulatory_summary" yaml:"regulatory_summary"`
	RepoExposureSummaries []exposure.RepoExposureSummary `json:"repo_exposure_summaries" yaml:"repo_exposure_summaries"`
	PrivilegeBudget       PrivilegeBudget                `json:"privilege_budget" yaml:"privilege_budget"`
	AgentPrivilegeMap     []AgentPrivilegeMapEntry       `json:"agent_privilege_map" yaml:"agent_privilege_map"`
	Summary               Summary                        `json:"summary" yaml:"summary"`
}

type MethodologySummary struct {
	WrkrVersion         string                `json:"wrkr_version" yaml:"wrkr_version"`
	ScanStartedAt       string                `json:"scan_started_at" yaml:"scan_started_at"`
	ScanCompletedAt     string                `json:"scan_completed_at" yaml:"scan_completed_at"`
	ScanDurationSeconds float64               `json:"scan_duration_seconds" yaml:"scan_duration_seconds"`
	RepoCount           int                   `json:"repo_count" yaml:"repo_count"`
	FileCountProcessed  int                   `json:"file_count_processed" yaml:"file_count_processed"`
	Detectors           []MethodologyDetector `json:"detectors" yaml:"detectors"`
}

type MethodologyDetector struct {
	ID           string `json:"id" yaml:"id"`
	Version      string `json:"version" yaml:"version"`
	FindingCount int    `json:"finding_count" yaml:"finding_count"`
}

type ApprovalSummary struct {
	ApprovedTools        int      `json:"approved_tools" yaml:"approved_tools"`
	UnapprovedTools      int      `json:"unapproved_tools" yaml:"unapproved_tools"`
	UnknownTools         int      `json:"unknown_tools" yaml:"unknown_tools"`
	ApprovedPercent      float64  `json:"approved_percent" yaml:"approved_percent"`
	UnapprovedPercent    float64  `json:"unapproved_percent" yaml:"unapproved_percent"`
	UnknownPercent       float64  `json:"unknown_percent" yaml:"unknown_percent"`
	UnapprovedPerApprove *float64 `json:"unapproved_per_approved" yaml:"unapproved_per_approved"`
}

type AdoptionSummary struct {
	OrgWide    int `json:"org_wide" yaml:"org_wide"`
	TeamLevel  int `json:"team_level" yaml:"team_level"`
	Individual int `json:"individual" yaml:"individual"`
	OneOff     int `json:"one_off" yaml:"one_off"`
}

type RegulatorySummary struct {
	ByRegulation []RegulationRollup `json:"by_regulation" yaml:"by_regulation"`
	ByControl    []ControlRollup    `json:"by_control" yaml:"by_control"`
}

type RegulationRollup struct {
	Regulation string `json:"regulation" yaml:"regulation"`
	Total      int    `json:"total" yaml:"total"`
	Pass       int    `json:"pass" yaml:"pass"`
	Gap        int    `json:"gap" yaml:"gap"`
	Unknown    int    `json:"unknown" yaml:"unknown"`
}

type ControlRollup struct {
	Regulation string `json:"regulation" yaml:"regulation"`
	ControlID  string `json:"control_id" yaml:"control_id"`
	Total      int    `json:"total" yaml:"total"`
	Pass       int    `json:"pass" yaml:"pass"`
	Gap        int    `json:"gap" yaml:"gap"`
	Unknown    int    `json:"unknown" yaml:"unknown"`
}

type ToolContext struct {
	EndpointClass  string
	DataClass      string
	AutonomyLevel  string
	RiskScore      float64
	ApprovalStatus string
	LifecycleState string
}

type BuildInput struct {
	Manifest              source.Manifest
	Findings              []model.Finding
	Contexts              map[string]ToolContext
	AgentBindings         map[string]AgentBindingContext
	AgentDeployments      map[string]AgentDeploymentContext
	Methodology           MethodologySummary
	RepoExposureSummaries []exposure.RepoExposureSummary
	GeneratedAt           time.Time
}

func Build(input BuildInput) Inventory {
	generatedAt := input.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC().Truncate(time.Second)
	}
	org := deriveOrg(input.Manifest)

	type accumulator struct {
		tool          Tool
		repoSet       map[string]struct{}
		locSet        map[string]struct{}
		permissionSet map[string]struct{}
	}
	toolMap := map[string]*accumulator{}
	agentMap := map[string]Agent{}
	for _, finding := range input.Findings {
		if !includeFinding(finding) {
			continue
		}
		findingOrg := strings.TrimSpace(finding.Org)
		if findingOrg == "" {
			findingOrg = org
		}
		toolID := identity.ToolID(finding.ToolType, finding.Location)
		key := findingOrg + "::" + toolID
		item, exists := toolMap[key]
		if !exists {
			agentID := identity.AgentID(toolID, findingOrg)
			context := input.Contexts[KeyForFinding(finding)]
			tool := Tool{
				ToolID:          toolID,
				AgentID:         agentID,
				DiscoveryMethod: normalizeDiscoveryMethod(finding.DiscoveryMethod),
				ToolType:        strings.TrimSpace(finding.ToolType),
				ToolCategory:    classifyToolCategory(finding.ToolType),
				ConfidenceScore: findingConfidence(finding),
				Org:             findingOrg,
				EndpointClass:   fallback(context.EndpointClass, "workspace"),
				DataClass:       fallback(context.DataClass, "code"),
				AutonomyLevel:   fallback(context.AutonomyLevel, "interactive"),
				RiskScore:       context.RiskScore,
				ApprovalStatus:  fallback(context.ApprovalStatus, "missing"),
				LifecycleState:  fallback(context.LifecycleState, identity.StateDiscovered),
			}
			item = &accumulator{tool: tool, repoSet: map[string]struct{}{}, locSet: map[string]struct{}{}, permissionSet: map[string]struct{}{}}
			toolMap[key] = item
		}

		framework := strings.TrimSpace(finding.ToolType)
		symbol := findingAgentSymbol(finding)
		startLine, endLine := findingRangeLines(finding)
		instanceID := identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
		agentKey := strings.Join([]string{
			findingOrg,
			framework,
			instanceID,
			strings.TrimSpace(finding.Location),
			strings.TrimSpace(finding.Repo),
			strings.TrimSpace(symbol),
			strings.TrimSpace(fmt.Sprintf("%d:%d", startLine, endLine)),
		}, "::")
		agentMap[agentKey] = Agent{
			AgentID:                identity.AgentID(instanceID, findingOrg),
			AgentInstanceID:        instanceID,
			Framework:              framework,
			Org:                    findingOrg,
			Repo:                   strings.TrimSpace(finding.Repo),
			Location:               strings.TrimSpace(finding.Location),
			LocationRange:          cloneLocationRange(finding.LocationRange),
			BoundTools:             cloneStringSlice(input.AgentBindings[instanceID].BoundTools),
			BoundDataSources:       cloneStringSlice(input.AgentBindings[instanceID].BoundDataSources),
			BoundAuthSurfaces:      cloneStringSlice(input.AgentBindings[instanceID].BoundAuthSurfaces),
			BindingEvidenceKeys:    cloneStringSlice(input.AgentBindings[instanceID].BindingEvidenceKeys),
			MissingBindings:        cloneStringSlice(input.AgentBindings[instanceID].MissingBindings),
			DeploymentStatus:       strings.TrimSpace(input.AgentDeployments[instanceID].DeploymentStatus),
			DeploymentArtifacts:    cloneStringSlice(input.AgentDeployments[instanceID].DeploymentArtifacts),
			DeploymentEvidenceKeys: cloneStringSlice(input.AgentDeployments[instanceID].DeploymentEvidenceKeys),
		}

		if finding.Repo != "" {
			item.repoSet[finding.Repo] = struct{}{}
		}
		owner := owners.ResolveOwner(repoRoot(input.Manifest, finding.Repo), finding.Repo, findingOrg, finding.Location)
		locKey := finding.Repo + "::" + finding.Location
		if _, exists := item.locSet[locKey]; !exists {
			item.locSet[locKey] = struct{}{}
			item.tool.Locations = append(item.tool.Locations, ToolLocation{Repo: finding.Repo, Location: finding.Location, Owner: owner})
		}
		for _, permission := range finding.Permissions {
			trimmed := strings.TrimSpace(permission)
			if trimmed == "" {
				continue
			}
			item.permissionSet[trimmed] = struct{}{}
		}

		context := input.Contexts[KeyForFinding(finding)]
		if context.RiskScore > item.tool.RiskScore {
			item.tool.RiskScore = context.RiskScore
			item.tool.EndpointClass = fallback(context.EndpointClass, item.tool.EndpointClass)
			item.tool.DataClass = fallback(context.DataClass, item.tool.DataClass)
			item.tool.AutonomyLevel = fallback(context.AutonomyLevel, item.tool.AutonomyLevel)
		}
		item.tool.DiscoveryMethod = normalizeDiscoveryMethod(finding.DiscoveryMethod)
		if confidence := findingConfidence(finding); confidence > item.tool.ConfidenceScore {
			item.tool.ConfidenceScore = confidence
		}
		item.tool.ApprovalStatus = fallback(context.ApprovalStatus, item.tool.ApprovalStatus)
		item.tool.LifecycleState = fallback(context.LifecycleState, item.tool.LifecycleState)
	}

	tools := make([]Tool, 0, len(toolMap))
	summary := Summary{}
	approvalSummary := ApprovalSummary{}
	adoptionSummary := AdoptionSummary{}
	for _, item := range toolMap {
		item.tool.Repos = sortedSet(item.repoSet)
		item.tool.Permissions = sortedSet(item.permissionSet)
		item.tool.ApprovalClass = classifyApproval(item.tool.ApprovalStatus, item.tool.LifecycleState)
		item.tool.PermissionSurface = derivePermissionSurface(item.tool.Permissions)
		item.tool.PermissionTier = classifyPermissionTier(item.tool.PermissionSurface)
		item.tool.RiskTier = projectRiskTier(item.tool.PermissionTier, item.tool.RiskScore, item.tool.AutonomyLevel, item.tool.ApprovalClass)
		item.tool.AdoptionPattern = classifyAdoptionPattern(item.tool.Repos, item.tool.Locations)
		item.tool.RegulatoryMapping = regulatoryMappings(item.tool)
		sort.Slice(item.tool.Locations, func(i, j int) bool {
			if item.tool.Locations[i].Repo != item.tool.Locations[j].Repo {
				return item.tool.Locations[i].Repo < item.tool.Locations[j].Repo
			}
			if item.tool.Locations[i].Location != item.tool.Locations[j].Location {
				return item.tool.Locations[i].Location < item.tool.Locations[j].Location
			}
			return item.tool.Locations[i].Owner < item.tool.Locations[j].Owner
		})
		tools = append(tools, item.tool)
		summary.TotalTools++
		switch item.tool.ApprovalClass {
		case "approved":
			approvalSummary.ApprovedTools++
		case "unapproved":
			approvalSummary.UnapprovedTools++
		default:
			approvalSummary.UnknownTools++
		}
		switch item.tool.AdoptionPattern {
		case "org_wide":
			adoptionSummary.OrgWide++
		case "team_level":
			adoptionSummary.TeamLevel++
		case "individual":
			adoptionSummary.Individual++
		default:
			adoptionSummary.OneOff++
		}
		switch {
		case item.tool.RiskScore >= 8:
			summary.HighRisk++
		case item.tool.RiskScore >= 5:
			summary.MediumRisk++
		default:
			summary.LowRisk++
		}
	}

	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Org != tools[j].Org {
			return tools[i].Org < tools[j].Org
		}
		if tools[i].ToolType != tools[j].ToolType {
			return tools[i].ToolType < tools[j].ToolType
		}
		return tools[i].ToolID < tools[j].ToolID
	})
	agents := make([]Agent, 0, len(agentMap))
	for _, agent := range agentMap {
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool {
		if agents[i].Org != agents[j].Org {
			return agents[i].Org < agents[j].Org
		}
		if agents[i].Framework != agents[j].Framework {
			return agents[i].Framework < agents[j].Framework
		}
		if agents[i].AgentInstanceID != agents[j].AgentInstanceID {
			return agents[i].AgentInstanceID < agents[j].AgentInstanceID
		}
		if agents[i].Location != agents[j].Location {
			return agents[i].Location < agents[j].Location
		}
		if agents[i].Repo != agents[j].Repo {
			return agents[i].Repo < agents[j].Repo
		}
		return agents[i].AgentID < agents[j].AgentID
	})
	approvalSummary = finalizeApprovalSummary(approvalSummary)
	regulatorySummary := buildRegulatorySummary(tools)

	return Inventory{
		InventoryVersion:      "1",
		GeneratedAt:           generatedAt.Format(time.RFC3339),
		Org:                   org,
		Agents:                agents,
		Tools:                 tools,
		Methodology:           normalizeMethodology(input.Methodology),
		ApprovalSummary:       approvalSummary,
		AdoptionSummary:       adoptionSummary,
		RegulatorySummary:     regulatorySummary,
		RepoExposureSummaries: append([]exposure.RepoExposureSummary(nil), input.RepoExposureSummaries...),
		PrivilegeBudget: PrivilegeBudget{
			TotalTools: summary.TotalTools,
			ProductionWrite: ProductionWriteBudget{
				Configured: false,
				Status:     ProductionTargetsStatusNotConfigured,
				Count:      nil,
			},
		},
		AgentPrivilegeMap: []AgentPrivilegeMapEntry{},
		Summary:           summary,
	}
}

func classifyApproval(approvalStatus, lifecycleState string) string {
	status := strings.ToLower(strings.TrimSpace(approvalStatus))
	lifecycle := strings.ToLower(strings.TrimSpace(lifecycleState))

	switch lifecycle {
	case "approved", "active":
		return "approved"
	case "discovered", "under_review", "deprecated", "revoked":
		return "unapproved"
	}

	switch status {
	case "valid", "approved":
		return "approved"
	case "missing", "revoked", "invalid", "expired":
		return "unapproved"
	default:
		return "unknown"
	}
}

func finalizeApprovalSummary(in ApprovalSummary) ApprovalSummary {
	total := in.ApprovedTools + in.UnapprovedTools + in.UnknownTools
	if total <= 0 {
		in.ApprovedPercent = 0
		in.UnapprovedPercent = 0
		in.UnknownPercent = 0
		in.UnapprovedPerApprove = nil
		return in
	}

	in.ApprovedPercent = roundPercent(float64(in.ApprovedTools) / float64(total) * 100)
	in.UnapprovedPercent = roundPercent(float64(in.UnapprovedTools) / float64(total) * 100)
	in.UnknownPercent = roundPercent(float64(in.UnknownTools) / float64(total) * 100)

	if in.ApprovedTools > 0 {
		ratio := roundPercent(float64(in.UnapprovedTools) / float64(in.ApprovedTools))
		in.UnapprovedPerApprove = &ratio
	}

	return in
}

func roundPercent(value float64) float64 {
	return math.Round(value*100) / 100
}

func derivePermissionSurface(permissions []string) PermissionSurface {
	surface := PermissionSurface{}
	for _, permission := range permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		switch {
		case strings.Contains(normalized, "admin"):
			surface.Admin = true
			surface.Write = true
			surface.Read = true
		case strings.Contains(normalized, ".write"), strings.HasSuffix(normalized, "write"), strings.Contains(normalized, "deploy"), strings.Contains(normalized, "exec"):
			surface.Write = true
			surface.Read = true
		case strings.Contains(normalized, ".read"), strings.HasSuffix(normalized, "read"), strings.Contains(normalized, "contents"):
			surface.Read = true
		}
	}
	return surface
}

func classifyPermissionTier(surface PermissionSurface) string {
	switch {
	case surface.Admin:
		return "admin"
	case surface.Write:
		return "write"
	case surface.Read:
		return "read"
	default:
		return "none"
	}
}

func projectRiskTier(permissionTier string, riskScore float64, autonomyLevel string, approvalClass string) string {
	tier := "low"
	switch strings.ToLower(strings.TrimSpace(permissionTier)) {
	case "admin":
		tier = "critical"
	case "write":
		tier = "high"
	case "read":
		tier = "medium"
	}
	if strings.EqualFold(strings.TrimSpace(autonomyLevel), "headless_auto") && tier != "critical" {
		tier = "high"
	}
	if strings.EqualFold(strings.TrimSpace(approvalClass), "unknown") && tier == "low" {
		tier = "medium"
	}
	if riskScore >= 9 {
		return "critical"
	}
	if riskScore >= 8 {
		if tier == "critical" {
			return tier
		}
		return "high"
	}
	if riskScore >= 5 && tier == "low" {
		return "medium"
	}
	return tier
}

func classifyAdoptionPattern(repos []string, locations []ToolLocation) string {
	repoCount := len(repos)
	if repoCount >= 3 {
		return "org_wide"
	}
	if repoCount == 2 {
		return "team_level"
	}
	if repoCount == 1 {
		for _, item := range locations {
			path := strings.ToLower(strings.TrimSpace(item.Location))
			if strings.Contains(path, ".github/") || strings.Contains(path, ".gitlab/") || strings.HasSuffix(path, "jenkinsfile") {
				return "team_level"
			}
		}
		if len(locations) > 1 {
			return "individual"
		}
		return "one_off"
	}
	if len(locations) > 1 {
		return "individual"
	}
	return "one_off"
}

func regulatoryMappings(tool Tool) []RegulatoryStatus {
	out := []RegulatoryStatus{
		{
			Regulation: "eu_ai_act",
			ControlID:  "article_9_risk_management",
			Status:     ternaryStatus(tool.RiskTier == "critical" || tool.RiskTier == "high"),
			Rationale:  "high or critical risk tiers require documented risk assessment evidence",
		},
		{
			Regulation: "eu_ai_act",
			ControlID:  "article_12_record_keeping",
			Status:     ternaryStatus(len(tool.Locations) == 0),
			Rationale:  "detected locations provide record-keeping anchors for inventory traceability",
		},
		{
			Regulation: "eu_ai_act",
			ControlID:  "article_14_human_oversight",
			Status:     ternaryStatus(strings.EqualFold(tool.AutonomyLevel, "headless_auto")),
			Rationale:  "headless automation requires explicit human oversight controls",
		},
		{
			Regulation: "eu_ai_act",
			ControlID:  "article_15_transparency",
			Status:     ternaryStatus(tool.ApprovalClass == "unknown"),
			Rationale:  "unknown approval classification indicates incomplete governance transparency",
		},
		{
			Regulation: "soc2",
			ControlID:  "cc6_least_privilege",
			Status:     ternaryStatus(tool.PermissionTier == "write" || tool.PermissionTier == "admin"),
			Rationale:  "write/admin capability requires documented least-privilege justification",
		},
		{
			Regulation: "nist_ai_rmf",
			ControlID:  "govern_1",
			Status:     ternaryStatus(tool.ApprovalClass != "approved"),
			Rationale:  "governance controls require explicit ownership and approval evidence",
		},
		{
			Regulation: "colorado_ai_act",
			ControlID:  "risk_management_program",
			Status:     ternaryStatus(tool.RiskTier == "critical"),
			Rationale:  "critical tier tools need demonstrable risk-management controls",
		},
		{
			Regulation: "texas_traiga",
			ControlID:  "transparency_disclosure",
			Status:     ternaryStatus(tool.ApprovalClass == "unknown"),
			Rationale:  "unknown approval posture weakens required disclosure readiness",
		},
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Regulation != out[j].Regulation {
			return out[i].Regulation < out[j].Regulation
		}
		return out[i].ControlID < out[j].ControlID
	})
	return out
}

func ternaryStatus(hasGap bool) string {
	if hasGap {
		return "gap"
	}
	return "pass"
}

// ReclassifyApprovalWithMatcher applies explicit approved-list policy matching
// and recomputes approval summary plus dependent derived fields.
func ReclassifyApprovalWithMatcher(inv *Inventory, matcher func(Tool) bool) {
	if inv == nil || matcher == nil {
		return
	}
	for idx := range inv.Tools {
		if matcher(inv.Tools[idx]) {
			inv.Tools[idx].ApprovalClass = "approved"
			inv.Tools[idx].ApprovalStatus = "approved_list"
		} else {
			inv.Tools[idx].ApprovalClass = "unapproved"
		}
		inv.Tools[idx].RiskTier = projectRiskTier(inv.Tools[idx].PermissionTier, inv.Tools[idx].RiskScore, inv.Tools[idx].AutonomyLevel, inv.Tools[idx].ApprovalClass)
		inv.Tools[idx].RegulatoryMapping = regulatoryMappings(inv.Tools[idx])
	}
	inv.ApprovalSummary = buildApprovalSummary(inv.Tools)
	inv.RegulatorySummary = buildRegulatorySummary(inv.Tools)
}

func buildApprovalSummary(tools []Tool) ApprovalSummary {
	summary := ApprovalSummary{}
	for _, tool := range tools {
		switch strings.TrimSpace(tool.ApprovalClass) {
		case "approved":
			summary.ApprovedTools++
		case "unapproved":
			summary.UnapprovedTools++
		default:
			summary.UnknownTools++
		}
	}
	return finalizeApprovalSummary(summary)
}

func buildRegulatorySummary(tools []Tool) RegulatorySummary {
	type counters struct {
		total   int
		pass    int
		gap     int
		unknown int
	}
	byRegulation := map[string]*counters{}
	byControl := map[string]*counters{}

	for _, tool := range tools {
		for _, mapping := range tool.RegulatoryMapping {
			regulation := strings.TrimSpace(mapping.Regulation)
			controlID := strings.TrimSpace(mapping.ControlID)
			if regulation == "" || controlID == "" {
				continue
			}
			regCounters := byRegulation[regulation]
			if regCounters == nil {
				regCounters = &counters{}
				byRegulation[regulation] = regCounters
			}
			regCounters.total++

			controlKey := regulation + "::" + controlID
			controlCounters := byControl[controlKey]
			if controlCounters == nil {
				controlCounters = &counters{}
				byControl[controlKey] = controlCounters
			}
			controlCounters.total++

			switch strings.TrimSpace(mapping.Status) {
			case "pass":
				regCounters.pass++
				controlCounters.pass++
			case "gap":
				regCounters.gap++
				controlCounters.gap++
			default:
				regCounters.unknown++
				controlCounters.unknown++
			}
		}
	}

	regulationRollups := make([]RegulationRollup, 0, len(byRegulation))
	for regulation, counts := range byRegulation {
		regulationRollups = append(regulationRollups, RegulationRollup{
			Regulation: regulation,
			Total:      counts.total,
			Pass:       counts.pass,
			Gap:        counts.gap,
			Unknown:    counts.unknown,
		})
	}
	sort.Slice(regulationRollups, func(i, j int) bool {
		return regulationRollups[i].Regulation < regulationRollups[j].Regulation
	})

	controlRollups := make([]ControlRollup, 0, len(byControl))
	for key, counts := range byControl {
		parts := strings.SplitN(key, "::", 2)
		if len(parts) != 2 {
			continue
		}
		controlRollups = append(controlRollups, ControlRollup{
			Regulation: parts[0],
			ControlID:  parts[1],
			Total:      counts.total,
			Pass:       counts.pass,
			Gap:        counts.gap,
			Unknown:    counts.unknown,
		})
	}
	sort.Slice(controlRollups, func(i, j int) bool {
		if controlRollups[i].Regulation != controlRollups[j].Regulation {
			return controlRollups[i].Regulation < controlRollups[j].Regulation
		}
		return controlRollups[i].ControlID < controlRollups[j].ControlID
	})

	return RegulatorySummary{
		ByRegulation: regulationRollups,
		ByControl:    controlRollups,
	}
}

func classifyToolCategory(toolType string) string {
	normalized := strings.ToLower(strings.TrimSpace(toolType))
	switch normalized {
	case "claude", "cursor", "codex", "copilot", "cody", "windsurf":
		return "assistant"
	case "a2a", "agent", "agent_framework", "ci_agent", "compiled_action", "langchain", "crewai", "autogen", "llamaindex", "openai_agents", "mcp_client", "custom_agent":
		return "agent_framework"
	case "mcp", "mcpgateway", "webmcp":
		return "mcp_integration"
	case "plugin", "extension", "ide_plugin", "browser_extension":
		return "plugin_extension"
	case "openai", "anthropic", "google", "gemini", "model_api", "api_key":
		return "model_api_integration"
	default:
		return "custom_wrapper"
	}
}

func findingConfidence(finding model.Finding) float64 {
	score := 0.9
	if strings.TrimSpace(finding.Detector) == "" {
		score = 0.75
	}
	if strings.TrimSpace(finding.Location) == "" {
		score -= 0.15
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "source_discovery":
		score = 0.65
	case "ci_autonomy", "compiled_action":
		if score < 0.8 {
			score = 0.8
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return math.Round(score*100) / 100
}

func normalizeMethodology(in MethodologySummary) MethodologySummary {
	in.WrkrVersion = strings.TrimSpace(in.WrkrVersion)
	in.ScanStartedAt = strings.TrimSpace(in.ScanStartedAt)
	in.ScanCompletedAt = strings.TrimSpace(in.ScanCompletedAt)
	if in.ScanDurationSeconds < 0 {
		in.ScanDurationSeconds = 0
	}
	if in.RepoCount < 0 {
		in.RepoCount = 0
	}
	if in.FileCountProcessed < 0 {
		in.FileCountProcessed = 0
	}
	normalized := make([]MethodologyDetector, 0, len(in.Detectors))
	for _, item := range in.Detectors {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		version := strings.TrimSpace(item.Version)
		if version == "" {
			version = "v1"
		}
		count := item.FindingCount
		if count < 0 {
			count = 0
		}
		normalized = append(normalized, MethodologyDetector{
			ID:           id,
			Version:      version,
			FindingCount: count,
		})
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].ID != normalized[j].ID {
			return normalized[i].ID < normalized[j].ID
		}
		if normalized[i].Version != normalized[j].Version {
			return normalized[i].Version < normalized[j].Version
		}
		return normalized[i].FindingCount < normalized[j].FindingCount
	})
	in.Detectors = normalized
	return in
}

func KeyForFinding(finding model.Finding) string {
	return strings.Join([]string{
		finding.FindingType,
		finding.RuleID,
		normalizeDiscoveryMethod(finding.DiscoveryMethod),
		finding.ToolType,
		finding.Location,
		finding.Repo,
		finding.Org,
	}, "|")
}

func includeFinding(finding model.Finding) bool {
	return model.IsInventoryBearingFinding(finding)
}

func deriveOrg(manifest source.Manifest) string {
	if strings.TrimSpace(manifest.Target.Value) != "" && manifest.Target.Mode == "org" {
		return manifest.Target.Value
	}
	if len(manifest.Repos) > 0 {
		repo := strings.TrimSpace(manifest.Repos[0].Repo)
		if idx := strings.Index(repo, "/"); idx > 0 {
			return repo[:idx]
		}
	}
	return "local"
}

func repoRoot(manifest source.Manifest, repo string) string {
	for _, item := range manifest.Repos {
		if item.Repo == repo {
			return item.Location
		}
	}
	return "."
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}

func normalizeDiscoveryMethod(value string) string {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	if trimmed == "" {
		return model.DiscoveryMethodStatic
	}
	return trimmed
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	out = append(out, values...)
	return out
}

func findingAgentSymbol(finding model.Finding) string {
	index := map[string]string{}
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "" {
			continue
		}
		index[key] = strings.TrimSpace(evidence.Value)
	}
	for _, key := range []string{
		"symbol",
		"name",
		"agent_name",
		"agent.symbol",
		"agent.name",
		"function",
		"class",
	} {
		if value := strings.TrimSpace(index[key]); value != "" {
			return value
		}
	}
	return ""
}

func findingRangeLines(finding model.Finding) (int, int) {
	if finding.LocationRange == nil {
		return 0, 0
	}
	return finding.LocationRange.StartLine, finding.LocationRange.EndLine
}

func cloneLocationRange(in *model.LocationRange) *model.LocationRange {
	if in == nil {
		return nil
	}
	return &model.LocationRange{StartLine: in.StartLine, EndLine: in.EndLine}
}
