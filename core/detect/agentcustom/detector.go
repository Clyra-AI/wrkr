package agentcustom

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "agentcustom"

const confidenceGate = 0.85

type Detector struct{}

type customAgent struct {
	Name       string   `json:"name" yaml:"name" toml:"name"`
	File       string   `json:"file" yaml:"file" toml:"file"`
	Tools      []string `json:"tools" yaml:"tools" toml:"tools"`
	Auth       []string `json:"auth_surfaces" yaml:"auth_surfaces" toml:"auth_surfaces"`
	Deploy     []string `json:"deployment_artifacts" yaml:"deployment_artifacts" toml:"deployment_artifacts"`
	AutoDeploy bool     `json:"auto_deploy" yaml:"auto_deploy" toml:"auto_deploy"`
	HumanGate  bool     `json:"human_gate" yaml:"human_gate" toml:"human_gate"`
}

type declaration struct {
	Agents []customAgent `json:"agents" yaml:"agents" toml:"agents"`
}

type signalSet struct {
	Names map[string]struct{}
}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	configs := []struct {
		Path   string
		Format string
	}{
		{Path: ".wrkr/agents/custom-agent.yaml", Format: "yaml"},
		{Path: ".wrkr/agents/custom-agent.yml", Format: "yaml"},
		{Path: ".wrkr/agents/custom-agent.json", Format: "json"},
		{Path: ".wrkr/agents/custom-agent.toml", Format: "toml"},
	}

	findings := make([]model.Finding, 0)
	workspaceSignals, err := detectWorkspaceSignals(scope)
	if err != nil {
		return nil, err
	}

	for _, cfg := range configs {
		if !detect.FileExists(scope.Root, cfg.Path) {
			continue
		}

		parsed, parseErr := parseConfig(scope.Root, cfg.Path, cfg.Format)
		if parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, cfg.Path, cfg.Format, *parseErr))
			continue
		}
		if len(parsed.Agents) == 0 {
			findings = append(findings, parseErrorFinding(scope, cfg.Path, cfg.Format, model.ParseError{
				Kind:     "schema_validation_error",
				Format:   cfg.Format,
				Path:     cfg.Path,
				Detector: detectorID,
				Message:  "expected at least one agents entry",
			}))
			continue
		}

		for _, agent := range parsed.Agents {
			if strings.TrimSpace(agent.Name) == "" || strings.TrimSpace(agent.File) == "" {
				findings = append(findings, parseErrorFinding(scope, cfg.Path, cfg.Format, model.ParseError{
					Kind:     "schema_validation_error",
					Format:   cfg.Format,
					Path:     cfg.Path,
					Detector: detectorID,
					Message:  "each agent requires non-empty name and file",
				}))
				continue
			}
			scored := scoreSignals(workspaceSignals, agent)
			if !meetsConfidenceGate(scored.score, scored.count, scored.operational) {
				continue
			}
			findings = append(findings, toFinding(scope, cfg.Path, agent, scored))
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseConfig(root, rel, format string) (declaration, *model.ParseError) {
	var parsed declaration
	switch format {
	case "yaml":
		if parseErr := detect.ParseYAMLFile(detectorID, root, rel, &parsed); parseErr != nil {
			return declaration{}, parseErr
		}
	case "json":
		if parseErr := detect.ParseJSONFile(detectorID, root, rel, &parsed); parseErr != nil {
			return declaration{}, parseErr
		}
	case "toml":
		if parseErr := detect.ParseTOMLFile(detectorID, root, rel, &parsed); parseErr != nil {
			return declaration{}, parseErr
		}
	default:
		return declaration{}, &model.ParseError{
			Kind:     "parse_error",
			Format:   format,
			Path:     rel,
			Detector: detectorID,
			Message:  "unsupported custom-agent config format",
		}
	}
	return parsed, nil
}

func detectWorkspaceSignals(scope detect.Scope) (signalSet, error) {
	signals := signalSet{Names: map[string]struct{}{}}

	if detect.FileExists(scope.Root, "AGENTS.md") || detect.FileExists(scope.Root, "AGENTS.override.md") || detect.FileExists(scope.Root, "CLAUDE.md") || detect.FileExists(scope.Root, ".claude/CLAUDE.md") {
		signals.Names["agent_instruction_surface"] = struct{}{}
	}

	skillPaths, err := detect.Glob(scope.Root, ".agents/skills/*/SKILL.md")
	if err != nil {
		return signalSet{}, err
	}
	claudeSkillPaths, err := detect.Glob(scope.Root, ".claude/skills/*/SKILL.md")
	if err != nil {
		return signalSet{}, err
	}
	if len(skillPaths)+len(claudeSkillPaths) > 0 {
		signals.Names["skill_pack_surface"] = struct{}{}
	}

	workflowFiles, err := detect.Glob(scope.Root, ".github/workflows/*")
	if err != nil {
		return signalSet{}, err
	}
	if detect.FileExists(scope.Root, "Jenkinsfile") {
		workflowFiles = append(workflowFiles, "Jenkinsfile")
	}
	sort.Strings(workflowFiles)

	for _, rel := range workflowFiles {
		path := filepath.Join(scope.Root, filepath.FromSlash(rel))
		// #nosec G304 -- reads workflow definitions from the selected repository root.
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return signalSet{}, readErr
		}
		lower := strings.ToLower(string(payload))
		if strings.Contains(lower, "codex --full-auto") || strings.Contains(lower, "claude -p") || strings.Contains(lower, "claude code -p") || strings.Contains(lower, "gait eval --script") {
			signals.Names["headless_agent_runtime"] = struct{}{}
			break
		}
	}

	return signals, nil
}

type scoredSignals struct {
	names       []string
	score       float64
	count       int
	operational bool
}

func scoreSignals(workspace signalSet, agent customAgent) scoredSignals {
	names := map[string]float64{
		"custom_config_declared": 0.45,
	}
	operational := false

	for name := range workspace.Names {
		switch name {
		case "skill_pack_surface":
			names[name] = 0.20
		case "agent_instruction_surface":
			names[name] = 0.15
		case "headless_agent_runtime":
			names[name] = 0.30
			operational = true
		}
	}

	if len(uniqueSorted(agent.Tools)) > 0 {
		names["tool_binding_declared"] = 0.20
		operational = true
	}
	if len(uniqueSorted(agent.Auth)) > 0 {
		names["auth_binding_declared"] = 0.15
		operational = true
	}
	if len(uniqueSorted(agent.Deploy)) > 0 || agent.AutoDeploy {
		names["deployment_signal_declared"] = 0.20
		operational = true
	}
	if agent.AutoDeploy && agent.HumanGate {
		names["deployment_gate_declared"] = 0.10
	}

	ordered := make([]string, 0, len(names))
	score := 0.0
	for name, weight := range names {
		ordered = append(ordered, name)
		score += weight
	}
	sort.Strings(ordered)
	return scoredSignals{
		names:       ordered,
		score:       score,
		count:       len(ordered),
		operational: operational,
	}
}

func meetsConfidenceGate(score float64, count int, operational bool) bool {
	return score >= confidenceGate && count >= 3 && operational
}

func toFinding(scope detect.Scope, declarationPath string, agent customAgent, scored scoredSignals) model.Finding {
	severity := model.SeverityLow
	if contains(scored.names, "headless_agent_runtime") {
		severity = model.SeverityMedium
	}
	if agent.AutoDeploy && !agent.HumanGate {
		severity = model.SeverityHigh
	}

	evidence := []model.Evidence{
		{Key: "reason_code", Value: "AGENT-CUSTOM-SCAFFOLD"},
		{Key: "confidence_score", Value: fmt.Sprintf("%.2f", scored.score)},
		{Key: "confidence_gate", Value: fmt.Sprintf("%.2f", confidenceGate)},
		{Key: "signal_count", Value: fmt.Sprintf("%d", scored.count)},
		{Key: "signal_set", Value: strings.Join(scored.names, ",")},
		{Key: "declaration_path", Value: strings.TrimSpace(declarationPath)},
	}

	return model.Finding{
		FindingType: "agent_custom_scaffold",
		Severity:    severity,
		ToolType:    "custom_agent",
		Location:    strings.TrimSpace(agent.File),
		Repo:        strings.TrimSpace(scope.Repo),
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		Permissions: derivePermissions(agent),
		Evidence:    evidence,
		Remediation: "Keep custom-agent scaffolding gated by deterministic approval and explicit runtime controls.",
	}
}

func parseErrorFinding(scope detect.Scope, path string, format string, parseErr model.ParseError) model.Finding {
	parseErr.Path = strings.TrimSpace(path)
	parseErr.Format = strings.TrimSpace(format)
	parseErr.Detector = detectorID
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    "custom_agent",
		Location:    strings.TrimSpace(path),
		Repo:        strings.TrimSpace(scope.Repo),
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		ParseError:  &parseErr,
		Remediation: "Fix malformed custom-agent declaration and preserve deterministic schema compliance.",
	}
}

func derivePermissions(agent customAgent) []string {
	perms := make([]string, 0)
	for _, tool := range uniqueSorted(agent.Tools) {
		lower := strings.ToLower(tool)
		if strings.Contains(lower, "write") || strings.Contains(lower, "deploy") {
			perms = append(perms, "deploy.write")
		}
		if strings.Contains(lower, "exec") {
			perms = append(perms, "proc.exec")
		}
	}
	for _, auth := range uniqueSorted(agent.Auth) {
		lower := strings.ToLower(auth)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "credential") {
			perms = append(perms, "secret.read")
		}
	}
	if agent.AutoDeploy {
		perms = append(perms, "deploy.write")
	}
	return uniqueSorted(perms)
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

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
