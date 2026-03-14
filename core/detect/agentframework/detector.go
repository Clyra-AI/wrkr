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
	Name             string   `json:"name" yaml:"name" toml:"name"`
	File             string   `json:"file" yaml:"file" toml:"file"`
	StartLine        int      `json:"start_line" yaml:"start_line" toml:"start_line"`
	EndLine          int      `json:"end_line" yaml:"end_line" toml:"end_line"`
	Tools            []string `json:"tools" yaml:"tools" toml:"tools"`
	DataSources      []string `json:"data_sources" yaml:"data_sources" toml:"data_sources"`
	AuthSurfaces     []string `json:"auth_surfaces" yaml:"auth_surfaces" toml:"auth_surfaces"`
	Deployment       []string `json:"deployment_artifacts" yaml:"deployment_artifacts" toml:"deployment_artifacts"`
	DataClass        string   `json:"data_class" yaml:"data_class" toml:"data_class"`
	ApprovalStatus   string   `json:"approval_status" yaml:"approval_status" toml:"approval_status"`
	DynamicDiscovery bool     `json:"dynamic_discovery" yaml:"dynamic_discovery" toml:"dynamic_discovery"`
	KillSwitch       bool     `json:"kill_switch" yaml:"kill_switch" toml:"kill_switch"`
	AutoDeploy       bool     `json:"auto_deploy" yaml:"auto_deploy" toml:"auto_deploy"`
	HumanGate        bool     `json:"human_gate" yaml:"human_gate" toml:"human_gate"`
	DeploymentGate   string   `json:"deployment_gate" yaml:"deployment_gate" toml:"deployment_gate"`
}

type declaration struct {
	Agents []AgentSpec `json:"agents" yaml:"agents" toml:"agents"`
}

type DetectorConfig struct {
	DetectorID string
	Framework  string
	ConfigPath string
	Format     string
}

func Detect(_ context.Context, scope detect.Scope, cfg DetectorConfig) ([]model.Finding, error) {
	return DetectMany(scope, []DetectorConfig{cfg})
}

func DetectMany(scope detect.Scope, configs []DetectorConfig) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	normalized := normalizeConfigs(configs)
	if len(normalized) == 0 {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	for _, cfg := range normalized {
		if !detect.FileExists(scope.Root, cfg.ConfigPath) {
			continue
		}
		fileFindings := detectOne(scope, cfg)
		findings = append(findings, fileFindings...)
	}

	sourcePlans := buildSourcePlans(normalized)
	if len(sourcePlans) > 0 {
		sourceFindings, err := detectFromSource(scope, sourcePlans)
		if err != nil {
			return nil, err
		}
		findings = append(findings, sourceFindings...)
	}

	if len(findings) == 0 {
		return nil, nil
	}
	findings = mergeFrameworkFindings(findings)
	model.SortFindings(findings)
	return findings, nil
}

func detectOne(scope detect.Scope, cfg DetectorConfig) []model.Finding {
	parsed, parseErr := parse(scope, cfg)
	if parseErr != nil {
		return []model.Finding{parseErrorFinding(scope, cfg, *parseErr)}
	}
	if len(parsed.Agents) == 0 {
		return []model.Finding{parseErrorFinding(scope, cfg, model.ParseError{
			Kind:     "schema_validation_error",
			Format:   cfg.Format,
			Path:     cfg.ConfigPath,
			Detector: cfg.DetectorID,
			Message:  "expected at least one agents entry",
		})}
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
			})}
		}
		findings = append(findings, frameworkFinding(scope, cfg, agent))
	}
	return findings
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
	case "toml":
		if parseErr := detect.ParseTOMLFile(cfg.DetectorID, scope.Root, cfg.ConfigPath, &parsed); parseErr != nil {
			return declaration{}, parseErr
		}
	default:
		return declaration{}, &model.ParseError{Kind: "parse_error", Format: cfg.Format, Path: cfg.ConfigPath, Detector: cfg.DetectorID, Message: "unsupported detector config format"}
	}
	return parsed, nil
}

func normalizeConfigs(configs []DetectorConfig) []DetectorConfig {
	if len(configs) == 0 {
		return nil
	}
	unique := map[string]DetectorConfig{}
	for _, cfg := range configs {
		detectorID := strings.TrimSpace(cfg.DetectorID)
		framework := strings.TrimSpace(cfg.Framework)
		configPath := strings.TrimSpace(cfg.ConfigPath)
		format := strings.ToLower(strings.TrimSpace(cfg.Format))
		if detectorID == "" || framework == "" || configPath == "" || format == "" {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s", configPath, format, detectorID)
		unique[key] = DetectorConfig{
			DetectorID: detectorID,
			Framework:  framework,
			ConfigPath: configPath,
			Format:     format,
		}
	}
	if len(unique) == 0 {
		return nil
	}
	out := make([]DetectorConfig, 0, len(unique))
	for _, cfg := range unique {
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ConfigPath != out[j].ConfigPath {
			return out[i].ConfigPath < out[j].ConfigPath
		}
		if out[i].Format != out[j].Format {
			return out[i].Format < out[j].Format
		}
		if out[i].DetectorID != out[j].DetectorID {
			return out[i].DetectorID < out[j].DetectorID
		}
		return out[i].Framework < out[j].Framework
	})
	return out
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
		case strings.Contains(lower, "token"),
			strings.Contains(lower, "secret"),
			strings.Contains(lower, "credential"),
			strings.Contains(lower, "api_key"),
			strings.HasSuffix(lower, "_key"),
			strings.HasSuffix(lower, ".key"),
			strings.Contains(lower, "authorization"):
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

func mergeFrameworkFindings(findings []model.Finding) []model.Finding {
	merged := make([]model.Finding, 0, len(findings))
	index := map[string]int{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.FindingType) != "agent_framework" {
			merged = append(merged, finding)
			continue
		}
		key := frameworkFindingKey(finding)
		if pos, exists := index[key]; exists {
			merged[pos] = mergeFrameworkFinding(merged[pos], finding)
			continue
		}
		index[key] = len(merged)
		merged = append(merged, finding)
	}
	return merged
}

func frameworkFindingKey(finding model.Finding) string {
	symbol := ""
	for _, evidence := range finding.Evidence {
		if strings.EqualFold(strings.TrimSpace(evidence.Key), "symbol") {
			symbol = strings.TrimSpace(evidence.Value)
			break
		}
	}
	return strings.Join([]string{
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.ToolType),
		strings.TrimSpace(finding.Location),
		symbol,
		strings.TrimSpace(finding.Repo),
		strings.TrimSpace(finding.Org),
	}, "::")
}

func mergeFrameworkFinding(current, incoming model.Finding) model.Finding {
	if severityRank(incoming.Severity) < severityRank(current.Severity) {
		current.Severity = incoming.Severity
	}
	current.Permissions = uniqueSorted(append(append([]string(nil), current.Permissions...), incoming.Permissions...))
	current.Evidence = mergeEvidence(current.Evidence, incoming.Evidence)
	if current.LocationRange == nil {
		current.LocationRange = incoming.LocationRange
	}
	if strings.TrimSpace(current.Remediation) == "" {
		current.Remediation = incoming.Remediation
	}
	return current
}

func mergeEvidence(current, incoming []model.Evidence) []model.Evidence {
	if len(current) == 0 {
		return incoming
	}
	if len(incoming) == 0 {
		return current
	}
	grouped := map[string][]string{}
	for _, item := range append(append([]model.Evidence(nil), current...), incoming...) {
		key := strings.TrimSpace(item.Key)
		if key == "" {
			continue
		}
		grouped[key] = append(grouped[key], strings.TrimSpace(item.Value))
	}
	out := make([]model.Evidence, 0, len(grouped))
	for key, values := range grouped {
		mergedValue := mergeEvidenceValue(key, values)
		if key == "" {
			continue
		}
		out = append(out, model.Evidence{Key: key, Value: mergedValue})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func mergeEvidenceValue(key string, values []string) string {
	normalizedKey := strings.ToLower(strings.TrimSpace(key))
	switch normalizedKey {
	case "bound_tools", "data_sources", "auth_surfaces", "deployment_artifacts":
		items := []string{}
		for _, value := range values {
			items = append(items, strings.Split(value, ",")...)
		}
		return strings.Join(uniqueSorted(items), ",")
	case "dynamic_discovery", "kill_switch", "auto_deploy", "human_gate":
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), "true") {
				return "true"
			}
		}
		return "false"
	case "data_class":
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" && trimmed != "unknown" && trimmed != "unclassified" {
				return trimmed
			}
		}
	case "approval_status", "deployment_status", "deployment_gate":
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" && trimmed != "missing" && trimmed != "unknown" {
				return trimmed
			}
		}
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func severityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case model.SeverityCritical:
		return 0
	case model.SeverityHigh:
		return 1
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 3
	default:
		return 4
	}
}
