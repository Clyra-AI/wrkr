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
	Repo            string `json:"repo" yaml:"repo"`
	Location        string `json:"location" yaml:"location"`
	Owner           string `json:"owner" yaml:"owner"`
	OwnerSource     string `json:"owner_source,omitempty" yaml:"owner_source,omitempty"`
	OwnershipStatus string `json:"ownership_status,omitempty" yaml:"ownership_status,omitempty"`
}

type Agent struct {
	AgentID                  string               `json:"agent_id" yaml:"agent_id"`
	AgentInstanceID          string               `json:"agent_instance_id" yaml:"agent_instance_id"`
	Framework                string               `json:"framework" yaml:"framework"`
	Symbol                   string               `json:"symbol,omitempty" yaml:"symbol,omitempty"`
	SecurityVisibilityStatus string               `json:"security_visibility_status,omitempty" yaml:"security_visibility_status,omitempty"`
	Org                      string               `json:"org" yaml:"org"`
	Repo                     string               `json:"repo" yaml:"repo"`
	Location                 string               `json:"location" yaml:"location"`
	LocationRange            *model.LocationRange `json:"location_range,omitempty" yaml:"location_range,omitempty"`
	BoundTools               []string             `json:"bound_tools,omitempty" yaml:"bound_tools,omitempty"`
	BoundDataSources         []string             `json:"bound_data_sources,omitempty" yaml:"bound_data_sources,omitempty"`
	BoundAuthSurfaces        []string             `json:"bound_auth_surfaces,omitempty" yaml:"bound_auth_surfaces,omitempty"`
	BindingEvidenceKeys      []string             `json:"binding_evidence_keys,omitempty" yaml:"binding_evidence_keys,omitempty"`
	MissingBindings          []string             `json:"missing_bindings,omitempty" yaml:"missing_bindings,omitempty"`
	DeploymentStatus         string               `json:"deployment_status,omitempty" yaml:"deployment_status,omitempty"`
	DeploymentArtifacts      []string             `json:"deployment_artifacts,omitempty" yaml:"deployment_artifacts,omitempty"`
	DeploymentEvidenceKeys   []string             `json:"deployment_evidence_keys,omitempty" yaml:"deployment_evidence_keys,omitempty"`
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
	ToolID                   string                     `json:"tool_id" yaml:"tool_id"`
	AgentID                  string                     `json:"agent_id" yaml:"agent_id"`
	DiscoveryMethod          string                     `json:"discovery_method" yaml:"discovery_method"`
	ToolType                 string                     `json:"tool_type" yaml:"tool_type"`
	ToolCategory             string                     `json:"tool_category" yaml:"tool_category"`
	ConfidenceScore          float64                    `json:"confidence_score" yaml:"confidence_score"`
	Org                      string                     `json:"org" yaml:"org"`
	Repos                    []string                   `json:"repos" yaml:"repos"`
	Locations                []ToolLocation             `json:"locations" yaml:"locations"`
	Permissions              []string                   `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	WritePathClasses         []string                   `json:"write_path_classes,omitempty" yaml:"write_path_classes,omitempty"`
	GovernanceControls       []GovernanceControlMapping `json:"governance_controls,omitempty" yaml:"governance_controls,omitempty"`
	PermissionSurface        PermissionSurface          `json:"permission_surface" yaml:"permission_surface"`
	PermissionTier           string                     `json:"permission_tier" yaml:"permission_tier"`
	RiskTier                 string                     `json:"risk_tier" yaml:"risk_tier"`
	AdoptionPattern          string                     `json:"adoption_pattern" yaml:"adoption_pattern"`
	RegulatoryMapping        []RegulatoryStatus         `json:"regulatory_mapping" yaml:"regulatory_mapping"`
	EndpointClass            string                     `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass                string                     `json:"data_class" yaml:"data_class"`
	AutonomyLevel            string                     `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore                float64                    `json:"risk_score" yaml:"risk_score"`
	ApprovalStatus           string                     `json:"approval_status" yaml:"approval_status"`
	ApprovalClass            string                     `json:"approval_classification" yaml:"approval_classification"`
	SecurityVisibilityStatus string                     `json:"security_visibility_status,omitempty" yaml:"security_visibility_status,omitempty"`
	LifecycleState           string                     `json:"lifecycle_state" yaml:"lifecycle_state"`
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

type LocalGovernanceSummary struct {
	ReferenceBasis    string `json:"reference_basis" yaml:"reference_basis"`
	ReferencePath     string `json:"reference_path,omitempty" yaml:"reference_path,omitempty"`
	Status            string `json:"status" yaml:"status"`
	SanctionedTools   int    `json:"sanctioned_tools" yaml:"sanctioned_tools"`
	UnsanctionedTools int    `json:"unsanctioned_tools" yaml:"unsanctioned_tools"`
	UnknownTools      int    `json:"unknown_tools" yaml:"unknown_tools"`
}

type NonHumanIdentity struct {
	IdentityID   string `json:"identity_id" yaml:"identity_id"`
	IdentityType string `json:"identity_type" yaml:"identity_type"`
	Subject      string `json:"subject" yaml:"subject"`
	Source       string `json:"source" yaml:"source"`
	Org          string `json:"org" yaml:"org"`
	Repo         string `json:"repo" yaml:"repo"`
	Location     string `json:"location" yaml:"location"`
	Confidence   string `json:"confidence,omitempty" yaml:"confidence,omitempty"`
}

type Inventory struct {
	InventoryVersion      string                         `json:"inventory_version" yaml:"inventory_version"`
	GeneratedAt           string                         `json:"generated_at" yaml:"generated_at"`
	Org                   string                         `json:"org" yaml:"org"`
	Agents                []Agent                        `json:"agents" yaml:"agents"`
	Tools                 []Tool                         `json:"tools" yaml:"tools"`
	NonHumanIdentities    []NonHumanIdentity             `json:"non_human_identities,omitempty" yaml:"non_human_identities,omitempty"`
	Methodology           MethodologySummary             `json:"methodology" yaml:"methodology"`
	ApprovalSummary       ApprovalSummary                `json:"approval_summary" yaml:"approval_summary"`
	AdoptionSummary       AdoptionSummary                `json:"adoption_summary" yaml:"adoption_summary"`
	RegulatorySummary     RegulatorySummary              `json:"regulatory_summary" yaml:"regulatory_summary"`
	SecurityVisibility    SecurityVisibilitySummary      `json:"security_visibility_summary" yaml:"security_visibility_summary"`
	LocalGovernance       *LocalGovernanceSummary        `json:"local_governance,omitempty" yaml:"local_governance,omitempty"`
	RepoExposureSummaries []exposure.RepoExposureSummary `json:"repo_exposure_summaries" yaml:"repo_exposure_summaries"`
	PrivilegeBudget       PrivilegeBudget                `json:"privilege_budget" yaml:"privilege_budget"`
	AgentPrivilegeMap     []AgentPrivilegeMapEntry       `json:"agent_privilege_map" yaml:"agent_privilege_map"`
	Summary               Summary                        `json:"summary" yaml:"summary"`
}

const (
	SecurityVisibilityApproved          = "approved"
	SecurityVisibilityKnownApproved     = "known_approved"
	SecurityVisibilityKnownUnapproved   = "known_unapproved"
	SecurityVisibilityUnknownToSecurity = "unknown_to_security"
	SecurityVisibilityAcceptedRisk      = "accepted_risk"
	SecurityVisibilityDeprecated        = "deprecated"
	SecurityVisibilityRevoked           = "revoked"
	SecurityVisibilityNeedsReview       = "needs_review"
)

type SecurityVisibilitySummary struct {
	ReferenceBasis                      string `json:"reference_basis" yaml:"reference_basis"`
	ReferencePath                       string `json:"reference_path,omitempty" yaml:"reference_path,omitempty"`
	ApprovedTools                       int    `json:"approved_tools" yaml:"approved_tools"`
	AcceptedRiskTools                   int    `json:"accepted_risk_tools,omitempty" yaml:"accepted_risk_tools,omitempty"`
	DeprecatedTools                     int    `json:"deprecated_tools,omitempty" yaml:"deprecated_tools,omitempty"`
	RevokedTools                        int    `json:"revoked_tools,omitempty" yaml:"revoked_tools,omitempty"`
	NeedsReviewTools                    int    `json:"needs_review_tools,omitempty" yaml:"needs_review_tools,omitempty"`
	KnownUnapprovedTools                int    `json:"known_unapproved_tools" yaml:"known_unapproved_tools"`
	UnknownToSecurityTools              int    `json:"unknown_to_security_tools" yaml:"unknown_to_security_tools"`
	ApprovedAgents                      int    `json:"approved_agents" yaml:"approved_agents"`
	AcceptedRiskAgents                  int    `json:"accepted_risk_agents,omitempty" yaml:"accepted_risk_agents,omitempty"`
	DeprecatedAgents                    int    `json:"deprecated_agents,omitempty" yaml:"deprecated_agents,omitempty"`
	RevokedAgents                       int    `json:"revoked_agents,omitempty" yaml:"revoked_agents,omitempty"`
	NeedsReviewAgents                   int    `json:"needs_review_agents,omitempty" yaml:"needs_review_agents,omitempty"`
	KnownUnapprovedAgents               int    `json:"known_unapproved_agents" yaml:"known_unapproved_agents"`
	UnknownToSecurityAgents             int    `json:"unknown_to_security_agents" yaml:"unknown_to_security_agents"`
	UnknownToSecurityWriteCapableAgents int    `json:"unknown_to_security_write_capable_agents" yaml:"unknown_to_security_write_capable_agents"`
}

type SecurityVisibilityReference struct {
	ReferenceBasis        string
	ReferencePath         string
	KnownToolIDs          map[string]struct{}
	KnownAgentInstanceIDs map[string]struct{}
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
	nonHumanIdentities := collectNonHumanIdentities(input.Findings, org)

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
			Symbol:                 strings.TrimSpace(symbol),
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
		owner := owners.Resolve(repoRoot(input.Manifest, finding.Repo), finding.Repo, findingOrg, finding.Location)
		locKey := finding.Repo + "::" + finding.Location
		if _, exists := item.locSet[locKey]; !exists {
			item.locSet[locKey] = struct{}{}
			item.tool.Locations = append(item.tool.Locations, ToolLocation{
				Repo:            finding.Repo,
				Location:        finding.Location,
				Owner:           owner.Owner,
				OwnerSource:     owner.OwnerSource,
				OwnershipStatus: owner.OwnershipStatus,
			})
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
		item.tool.WritePathClasses = DeriveWritePathClasses(
			item.tool.Permissions,
			item.tool.PermissionSurface.Write,
			hasPermission(item.tool.Permissions, "pull_request.write"),
			hasPermission(item.tool.Permissions, "merge.execute"),
			hasPermission(item.tool.Permissions, "deploy.write"),
			hasCredentialAccessForSurface(item.tool.DataClass, item.tool.Permissions, nil),
			false,
			primaryToolLocation(item.tool),
			item.tool.ToolType,
		)
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
			if item.tool.Locations[i].OwnerSource != item.tool.Locations[j].OwnerSource {
				return item.tool.Locations[i].OwnerSource < item.tool.Locations[j].OwnerSource
			}
			if item.tool.Locations[i].OwnershipStatus != item.tool.Locations[j].OwnershipStatus {
				return item.tool.Locations[i].OwnershipStatus < item.tool.Locations[j].OwnershipStatus
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
		NonHumanIdentities:    nonHumanIdentities,
		Methodology:           normalizeMethodology(input.Methodology),
		ApprovalSummary:       approvalSummary,
		AdoptionSummary:       adoptionSummary,
		RegulatorySummary:     regulatorySummary,
		SecurityVisibility:    SecurityVisibilitySummary{ReferenceBasis: "initial_scan"},
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

func collectNonHumanIdentities(findings []model.Finding, fallbackOrgValue string) []NonHumanIdentity {
	items := make([]NonHumanIdentity, 0)
	seen := map[string]struct{}{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.FindingType) != "non_human_identity" {
			continue
		}
		evidence := map[string]string{}
		for _, item := range finding.Evidence {
			evidence[strings.TrimSpace(item.Key)] = strings.TrimSpace(item.Value)
		}
		key := strings.Join([]string{
			fallback(strings.TrimSpace(finding.Org), fallbackOrgValue),
			strings.TrimSpace(finding.Repo),
			strings.TrimSpace(finding.Location),
			strings.TrimSpace(evidence["identity_type"]),
			strings.TrimSpace(evidence["subject"]),
			strings.TrimSpace(evidence["source"]),
		}, "|")
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		items = append(items, NonHumanIdentity{
			IdentityID:   key,
			IdentityType: strings.TrimSpace(evidence["identity_type"]),
			Subject:      strings.TrimSpace(evidence["subject"]),
			Source:       strings.TrimSpace(evidence["source"]),
			Org:          fallback(strings.TrimSpace(finding.Org), fallbackOrgValue),
			Repo:         strings.TrimSpace(finding.Repo),
			Location:     strings.TrimSpace(finding.Location),
			Confidence:   strings.TrimSpace(evidence["confidence"]),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].IdentityType != items[j].IdentityType {
			return items[i].IdentityType < items[j].IdentityType
		}
		if items[i].Subject != items[j].Subject {
			return items[i].Subject < items[j].Subject
		}
		return items[i].Location < items[j].Location
	})
	return items
}

func ApplySecurityVisibility(inv *Inventory, ref SecurityVisibilityReference) {
	if inv == nil {
		return
	}
	if ref.KnownToolIDs == nil {
		ref.KnownToolIDs = map[string]struct{}{}
	}
	if ref.KnownAgentInstanceIDs == nil {
		ref.KnownAgentInstanceIDs = map[string]struct{}{}
	}
	referenceBasis := strings.TrimSpace(ref.ReferenceBasis)
	if referenceBasis == "" {
		referenceBasis = "initial_scan"
	}

	agentStatusByTool := map[string][]string{}
	for idx := range inv.Agents {
		status := securityVisibilityForAgent(inv.Agents[idx], inv.Tools, ref)
		inv.Agents[idx].SecurityVisibilityStatus = status
		toolID := identity.ToolID(inv.Agents[idx].Framework, inv.Agents[idx].Location)
		agentStatusByTool[toolID] = append(agentStatusByTool[toolID], status)
	}

	for idx := range inv.Tools {
		status := securityVisibilityForTool(inv.Tools[idx], agentStatusByTool[inv.Tools[idx].ToolID], ref)
		inv.Tools[idx].SecurityVisibilityStatus = status
	}

	summary := SecurityVisibilitySummary{
		ReferenceBasis: referenceBasis,
		ReferencePath:  strings.TrimSpace(ref.ReferencePath),
	}
	for _, agent := range inv.Agents {
		switch strings.TrimSpace(agent.SecurityVisibilityStatus) {
		case SecurityVisibilityApproved, SecurityVisibilityKnownApproved:
			summary.ApprovedAgents++
		case SecurityVisibilityAcceptedRisk:
			summary.AcceptedRiskAgents++
		case SecurityVisibilityDeprecated:
			summary.DeprecatedAgents++
		case SecurityVisibilityRevoked:
			summary.RevokedAgents++
		case SecurityVisibilityNeedsReview:
			summary.NeedsReviewAgents++
		case SecurityVisibilityKnownUnapproved:
			summary.KnownUnapprovedAgents++
		default:
			summary.UnknownToSecurityAgents++
		}
	}
	for _, tool := range inv.Tools {
		switch strings.TrimSpace(tool.SecurityVisibilityStatus) {
		case SecurityVisibilityApproved, SecurityVisibilityKnownApproved:
			summary.ApprovedTools++
		case SecurityVisibilityAcceptedRisk:
			summary.AcceptedRiskTools++
		case SecurityVisibilityDeprecated:
			summary.DeprecatedTools++
		case SecurityVisibilityRevoked:
			summary.RevokedTools++
		case SecurityVisibilityNeedsReview:
			summary.NeedsReviewTools++
		case SecurityVisibilityKnownUnapproved:
			summary.KnownUnapprovedTools++
		default:
			summary.UnknownToSecurityTools++
		}
	}
	for idx := range inv.Tools {
		owner, ownerStatus := primaryToolOwner(inv.Tools[idx])
		inv.Tools[idx].GovernanceControls = BuildGovernanceControls(GovernanceControlInput{
			Owner:                    owner,
			OwnershipStatus:          ownerStatus,
			ApprovalStatus:           inv.Tools[idx].ApprovalStatus,
			ApprovalClassification:   inv.Tools[idx].ApprovalClass,
			LifecycleState:           inv.Tools[idx].LifecycleState,
			SecurityVisibilityStatus: inv.Tools[idx].SecurityVisibilityStatus,
			WritePathClasses:         inv.Tools[idx].WritePathClasses,
			CredentialAccess:         hasCredentialAccess(inv.Tools[idx]),
			EvidenceBasis:            inv.Tools[idx].Permissions,
		})
	}
	inv.SecurityVisibility = summary
}

func ApplySecurityVisibilityToPrivilegeMap(inv *Inventory) {
	if inv == nil {
		return
	}
	statusByInstance := map[string]string{}
	for _, agent := range inv.Agents {
		statusByInstance[strings.TrimSpace(agent.AgentInstanceID)] = strings.TrimSpace(agent.SecurityVisibilityStatus)
	}
	for idx := range inv.AgentPrivilegeMap {
		status := strings.TrimSpace(statusByInstance[strings.TrimSpace(inv.AgentPrivilegeMap[idx].AgentInstanceID)])
		if status == "" {
			status = strings.TrimSpace(inv.AgentPrivilegeMap[idx].ApprovalClassification)
		}
		inv.AgentPrivilegeMap[idx].SecurityVisibilityStatus = normalizeSecurityVisibilityStatus(status)
		inv.AgentPrivilegeMap[idx].GovernanceControls = BuildGovernanceControls(GovernanceControlInput{
			Owner:                    inv.AgentPrivilegeMap[idx].OperationalOwner,
			OwnershipStatus:          inv.AgentPrivilegeMap[idx].OwnershipStatus,
			ApprovalClassification:   inv.AgentPrivilegeMap[idx].ApprovalClassification,
			SecurityVisibilityStatus: inv.AgentPrivilegeMap[idx].SecurityVisibilityStatus,
			DeploymentGate:           deploymentGateFromEvidence(inv.AgentPrivilegeMap[idx].DeploymentEvidenceKeys),
			ProofRequirement:         proofRequirementFromEvidence(inv.AgentPrivilegeMap[idx].DeploymentEvidenceKeys),
			ProductionTargetStatus:   inv.AgentPrivilegeMap[idx].ProductionTargetStatus,
			WritePathClasses:         inv.AgentPrivilegeMap[idx].WritePathClasses,
			CredentialAccess:         inv.AgentPrivilegeMap[idx].CredentialAccess,
			ProductionWrite:          inv.AgentPrivilegeMap[idx].ProductionWrite,
			EvidenceBasis:            append(append([]string(nil), inv.AgentPrivilegeMap[idx].Permissions...), inv.AgentPrivilegeMap[idx].DeploymentEvidenceKeys...),
		})
	}
	inv.SecurityVisibility.UnknownToSecurityWriteCapableAgents = 0
	for _, entry := range inv.AgentPrivilegeMap {
		if entry.WriteCapable && strings.TrimSpace(entry.SecurityVisibilityStatus) == SecurityVisibilityUnknownToSecurity {
			inv.SecurityVisibility.UnknownToSecurityWriteCapableAgents++
		}
	}
}

func securityVisibilityForAgent(agent Agent, tools []Tool, ref SecurityVisibilityReference) string {
	if agentApproved(agent, tools) {
		return SecurityVisibilityApproved
	}
	if _, ok := ref.KnownAgentInstanceIDs[strings.TrimSpace(agent.AgentInstanceID)]; ok {
		return SecurityVisibilityKnownUnapproved
	}
	toolID := identity.ToolID(agent.Framework, agent.Location)
	if _, ok := ref.KnownToolIDs[toolID]; ok {
		return SecurityVisibilityKnownUnapproved
	}
	return SecurityVisibilityUnknownToSecurity
}

func securityVisibilityForTool(tool Tool, agentStatuses []string, ref SecurityVisibilityReference) string {
	switch strings.TrimSpace(tool.LifecycleState) {
	case "revoked":
		return SecurityVisibilityRevoked
	case "deprecated":
		return SecurityVisibilityDeprecated
	}
	switch strings.TrimSpace(tool.ApprovalStatus) {
	case "expired", "invalid":
		return SecurityVisibilityNeedsReview
	case "accepted_risk", "risk_accepted":
		return SecurityVisibilityAcceptedRisk
	}
	if strings.TrimSpace(tool.ApprovalClass) == "approved" {
		return SecurityVisibilityApproved
	}
	if len(agentStatuses) > 0 {
		return rollupSecurityVisibility(agentStatuses)
	}
	if _, ok := ref.KnownToolIDs[strings.TrimSpace(tool.ToolID)]; ok {
		return SecurityVisibilityKnownUnapproved
	}
	return SecurityVisibilityUnknownToSecurity
}

func agentApproved(agent Agent, tools []Tool) bool {
	for _, tool := range tools {
		if strings.TrimSpace(tool.ApprovalClass) != "approved" {
			continue
		}
		if fallbackOrg(tool.Org) != fallbackOrg(agent.Org) {
			continue
		}
		if strings.TrimSpace(tool.ToolID) == identity.ToolID(agent.Framework, agent.Location) {
			return true
		}
	}
	return false
}

func rollupSecurityVisibility(statuses []string) string {
	best := SecurityVisibilityApproved
	for _, status := range statuses {
		switch normalizeSecurityVisibilityStatus(status) {
		case SecurityVisibilityUnknownToSecurity:
			return SecurityVisibilityUnknownToSecurity
		case SecurityVisibilityRevoked:
			return SecurityVisibilityRevoked
		case SecurityVisibilityDeprecated:
			return SecurityVisibilityDeprecated
		case SecurityVisibilityNeedsReview:
			return SecurityVisibilityNeedsReview
		case SecurityVisibilityAcceptedRisk:
			best = SecurityVisibilityAcceptedRisk
		case SecurityVisibilityKnownUnapproved:
			best = SecurityVisibilityKnownUnapproved
		}
	}
	return best
}

func normalizeSecurityVisibilityStatus(value string) string {
	switch strings.TrimSpace(value) {
	case SecurityVisibilityApproved, SecurityVisibilityKnownApproved:
		return SecurityVisibilityApproved
	case SecurityVisibilityKnownUnapproved:
		return SecurityVisibilityKnownUnapproved
	case SecurityVisibilityAcceptedRisk:
		return SecurityVisibilityAcceptedRisk
	case SecurityVisibilityDeprecated:
		return SecurityVisibilityDeprecated
	case SecurityVisibilityRevoked:
		return SecurityVisibilityRevoked
	case SecurityVisibilityNeedsReview:
		return SecurityVisibilityNeedsReview
	default:
		return SecurityVisibilityUnknownToSecurity
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

func hasPermission(permissions []string, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	for _, permission := range permissions {
		if strings.ToLower(strings.TrimSpace(permission)) == want {
			return true
		}
	}
	return false
}

func primaryToolLocation(tool Tool) string {
	if len(tool.Locations) == 0 {
		return ""
	}
	locations := append([]ToolLocation(nil), tool.Locations...)
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Repo != locations[j].Repo {
			return locations[i].Repo < locations[j].Repo
		}
		return locations[i].Location < locations[j].Location
	})
	return strings.TrimSpace(locations[0].Location)
}

func primaryToolOwner(tool Tool) (string, string) {
	if len(tool.Locations) == 0 {
		return "", ""
	}
	locations := append([]ToolLocation(nil), tool.Locations...)
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].OwnershipStatus != locations[j].OwnershipStatus {
			return locations[i].OwnershipStatus < locations[j].OwnershipStatus
		}
		if locations[i].OwnerSource != locations[j].OwnerSource {
			return locations[i].OwnerSource < locations[j].OwnerSource
		}
		return locations[i].Owner < locations[j].Owner
	})
	return strings.TrimSpace(locations[0].Owner), strings.TrimSpace(locations[0].OwnershipStatus)
}

func deploymentGateFromEvidence(values []string) string {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if strings.Contains(normalized, "deployment_gate:approved") || normalized == "deployment_gate.approved" {
			return "approved"
		}
	}
	return ""
}

func proofRequirementFromEvidence(values []string) string {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		switch {
		case strings.Contains(normalized, "proof_requirement:evidence"), strings.Contains(normalized, "wrkr evidence"):
			return "evidence"
		case strings.Contains(normalized, "proof_requirement:attestation"), strings.Contains(normalized, "attestation"):
			return "attestation"
		}
	}
	return ""
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

func fallbackOrg(value string) string {
	if strings.TrimSpace(value) == "" {
		return "local"
	}
	return strings.TrimSpace(value)
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
