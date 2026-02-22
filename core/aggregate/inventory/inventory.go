package inventory

import (
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

type Tool struct {
	ToolID          string         `json:"tool_id" yaml:"tool_id"`
	AgentID         string         `json:"agent_id" yaml:"agent_id"`
	DiscoveryMethod string         `json:"discovery_method" yaml:"discovery_method"`
	ToolType        string         `json:"tool_type" yaml:"tool_type"`
	Org             string         `json:"org" yaml:"org"`
	Repos           []string       `json:"repos" yaml:"repos"`
	Locations       []ToolLocation `json:"locations" yaml:"locations"`
	Permissions     []string       `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	EndpointClass   string         `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass       string         `json:"data_class" yaml:"data_class"`
	AutonomyLevel   string         `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore       float64        `json:"risk_score" yaml:"risk_score"`
	ApprovalStatus  string         `json:"approval_status" yaml:"approval_status"`
	LifecycleState  string         `json:"lifecycle_state" yaml:"lifecycle_state"`
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
	Tools                 []Tool                         `json:"tools" yaml:"tools"`
	RepoExposureSummaries []exposure.RepoExposureSummary `json:"repo_exposure_summaries" yaml:"repo_exposure_summaries"`
	Summary               Summary                        `json:"summary" yaml:"summary"`
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
		item.tool.ApprovalStatus = fallback(context.ApprovalStatus, item.tool.ApprovalStatus)
		item.tool.LifecycleState = fallback(context.LifecycleState, item.tool.LifecycleState)
	}

	tools := make([]Tool, 0, len(toolMap))
	summary := Summary{}
	for _, item := range toolMap {
		item.tool.Repos = sortedSet(item.repoSet)
		item.tool.Permissions = sortedSet(item.permissionSet)
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

	return Inventory{
		InventoryVersion:      "1",
		GeneratedAt:           generatedAt.Format(time.RFC3339),
		Org:                   org,
		Tools:                 tools,
		RepoExposureSummaries: append([]exposure.RepoExposureSummary(nil), input.RepoExposureSummaries...),
		Summary:               summary,
	}
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
	if strings.TrimSpace(finding.ToolType) == "" {
		return false
	}
	switch finding.FindingType {
	case "policy_check", "policy_violation", "parse_error":
		return false
	default:
		return true
	}
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
