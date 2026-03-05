package agentframework

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

type AgentSpec struct {
	Name             string   `json:"name" yaml:"name"`
	File             string   `json:"file" yaml:"file"`
	StartLine        int      `json:"start_line" yaml:"start_line"`
	EndLine          int      `json:"end_line" yaml:"end_line"`
	Tools            []string `json:"tools" yaml:"tools"`
	DataSources      []string `json:"data_sources" yaml:"data_sources"`
	AuthSurfaces     []string `json:"auth_surfaces" yaml:"auth_surfaces"`
	Deployment       []string `json:"deployment_artifacts" yaml:"deployment_artifacts"`
	DataClass        string   `json:"data_class" yaml:"data_class"`
	ApprovalStatus   string   `json:"approval_status" yaml:"approval_status"`
	DynamicDiscovery bool     `json:"dynamic_discovery" yaml:"dynamic_discovery"`
	KillSwitch       bool     `json:"kill_switch" yaml:"kill_switch"`
	AutoDeploy       bool     `json:"auto_deploy" yaml:"auto_deploy"`
	HumanGate        bool     `json:"human_gate" yaml:"human_gate"`
	DeploymentGate   string   `json:"deployment_gate" yaml:"deployment_gate"`
}

type declaration struct {
	Agents []AgentSpec `json:"agents" yaml:"agents"`
}

type DetectorConfig struct {
	DetectorID string
	Framework  string
	ConfigPath string
	Format     string
}

func Detect(_ context.Context, scope detect.Scope, cfg DetectorConfig) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	if !detect.FileExists(scope.Root, cfg.ConfigPath) {
		return nil, nil
	}

	parsed, parseErr := parse(scope, cfg)
	if parseErr != nil {
		return []model.Finding{parseErrorFinding(scope, cfg, *parseErr)}, nil
	}
	if len(parsed.Agents) == 0 {
		return []model.Finding{parseErrorFinding(scope, cfg, model.ParseError{
			Kind:     "schema_validation_error",
			Format:   cfg.Format,
			Path:     cfg.ConfigPath,
			Detector: cfg.DetectorID,
			Message:  "expected at least one agents entry",
		})}, nil
	}

	findings := make([]model.Finding, 0, len(parsed.Agents))
	for _, agent := range parsed.Agents {
		if strings.TrimSpace(agent.Name) == "" || strings.TrimSpace(agent.File) == "" {
			return []model.Finding{parseErrorFinding(scope, cfg, model.ParseError{
				Kind:     "schema_validation_error",
				Format:   cfg.Format,
				Path:     cfg.ConfigPath,
				Detector: cfg.DetectorID,
				Message:  "each agent requires non-empty name and file",
			})}, nil
		}
		findings = append(findings, frameworkFinding(scope, cfg, agent))
	}
	model.SortFindings(findings)
	return findings, nil
}

func parse(scope detect.Scope, cfg DetectorConfig) (declaration, *model.ParseError) {
	var parsed declaration
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		if parseErr := detect.ParseJSONFile(cfg.DetectorID, scope.Root, cfg.ConfigPath, &parsed); parseErr != nil {
			return declaration{}, parseErr
		}
	case "yaml":
		if parseErr := detect.ParseYAMLFile(cfg.DetectorID, scope.Root, cfg.ConfigPath, &parsed); parseErr != nil {
			return declaration{}, parseErr
		}
	default:
		return declaration{}, &model.ParseError{Kind: "parse_error", Format: cfg.Format, Path: cfg.ConfigPath, Detector: cfg.DetectorID, Message: "unsupported detector config format"}
	}
	return parsed, nil
}

func frameworkFinding(scope detect.Scope, cfg DetectorConfig, agent AgentSpec) model.Finding {
	permissions := derivePermissions(agent)
	tools := uniqueSorted(agent.Tools)
	dataSources := uniqueSorted(agent.DataSources)
	authSurfaces := uniqueSorted(agent.AuthSurfaces)
	deployment := uniqueSorted(agent.Deployment)
	deploymentStatus := "unknown"
	if len(deployment) > 0 {
		deploymentStatus = "deployed"
	}

	evidence := []model.Evidence{
		{Key: "framework", Value: strings.TrimSpace(cfg.Framework)},
		{Key: "symbol", Value: strings.TrimSpace(agent.Name)},
		{Key: "declaration_path", Value: strings.TrimSpace(cfg.ConfigPath)},
		{Key: "bound_tools", Value: strings.Join(tools, ",")},
		{Key: "data_sources", Value: strings.Join(dataSources, ",")},
		{Key: "auth_surfaces", Value: strings.Join(authSurfaces, ",")},
		{Key: "deployment_artifacts", Value: strings.Join(deployment, ",")},
		{Key: "deployment_status", Value: deploymentStatus},
		{Key: "data_class", Value: fallback(strings.TrimSpace(agent.DataClass), "unknown")},
		{Key: "approval_status", Value: fallback(strings.TrimSpace(agent.ApprovalStatus), "missing")},
		{Key: "dynamic_discovery", Value: fmt.Sprintf("%t", agent.DynamicDiscovery)},
		{Key: "kill_switch", Value: fmt.Sprintf("%t", agent.KillSwitch)},
		{Key: "auto_deploy", Value: fmt.Sprintf("%t", agent.AutoDeploy)},
		{Key: "human_gate", Value: fmt.Sprintf("%t", agent.HumanGate)},
		{Key: "deployment_gate", Value: deriveDeploymentGate(agent)},
	}

	severity := model.SeverityLow
	if agent.AutoDeploy {
		severity = model.SeverityMedium
	}
	if agent.AutoDeploy && !agent.HumanGate {
		severity = model.SeverityHigh
	}

	var locationRange *model.LocationRange
	if agent.StartLine > 0 || agent.EndLine > 0 {
		locationRange = &model.LocationRange{StartLine: agent.StartLine, EndLine: agent.EndLine}
	}

	return model.Finding{
		FindingType:   "agent_framework",
		Severity:      severity,
		ToolType:      strings.TrimSpace(cfg.Framework),
		Location:      strings.TrimSpace(agent.File),
		LocationRange: locationRange,
		Repo:          strings.TrimSpace(scope.Repo),
		Org:           fallbackOrg(scope.Org),
		Detector:      strings.TrimSpace(cfg.DetectorID),
		Permissions:   permissions,
		Evidence:      evidence,
		Remediation:   "Declare deterministic agent bindings, deployment context, and governance controls.",
	}
}

func parseErrorFinding(scope detect.Scope, cfg DetectorConfig, parseErr model.ParseError) model.Finding {
	parseErr.Detector = strings.TrimSpace(cfg.DetectorID)
	if strings.TrimSpace(parseErr.Path) == "" {
		parseErr.Path = strings.TrimSpace(cfg.ConfigPath)
	}
	if strings.TrimSpace(parseErr.Format) == "" {
		parseErr.Format = strings.TrimSpace(cfg.Format)
	}
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    strings.TrimSpace(cfg.Framework),
		Location:    strings.TrimSpace(cfg.ConfigPath),
		Repo:        strings.TrimSpace(scope.Repo),
		Org:         fallbackOrg(scope.Org),
		Detector:    strings.TrimSpace(cfg.DetectorID),
		ParseError:  &parseErr,
		Remediation: "Fix malformed framework declaration to restore deterministic parsing.",
	}
}

func derivePermissions(agent AgentSpec) []string {
	permissions := []string{}
	for _, item := range uniqueSorted(agent.AuthSurfaces) {
		lower := strings.ToLower(strings.TrimSpace(item))
		switch {
		case strings.Contains(lower, "token"), strings.Contains(lower, "secret"), strings.Contains(lower, "credential"):
			permissions = append(permissions, "secret.read")
		case strings.Contains(lower, "oauth"):
			permissions = append(permissions, "identity.read")
		}
	}
	for _, item := range uniqueSorted(agent.Tools) {
		lower := strings.ToLower(strings.TrimSpace(item))
		if strings.Contains(lower, "write") || strings.Contains(lower, "deploy") {
			permissions = append(permissions, "deploy.write")
		}
		if strings.Contains(lower, "exec") {
			permissions = append(permissions, "proc.exec")
		}
	}
	if agent.AutoDeploy {
		permissions = append(permissions, "deploy.write")
	}
	return uniqueSorted(permissions)
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

func deriveDeploymentGate(agent AgentSpec) string {
	explicit := strings.ToLower(strings.TrimSpace(agent.DeploymentGate))
	if explicit != "" {
		return explicit
	}
	if !agent.AutoDeploy {
		return ""
	}
	if agent.HumanGate {
		return "enforced"
	}
	return "missing"
}
