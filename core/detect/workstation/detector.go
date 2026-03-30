package workstation

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "workstation"

type markerSpec struct {
	Path     string
	ToolType string
}

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

var workspaceRoots = []string{"Projects", "Code", "Workspace", "Workspaces"}

var envKeyMatchers = []string{
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"AZURE_OPENAI_API_KEY",
	"GOOGLE_API_KEY",
	"GEMINI_API_KEY",
	"MISTRAL_API_KEY",
	"COHERE_API_KEY",
	"OPENROUTER_API_KEY",
}

var homeMarkers = []markerSpec{
	{Path: ".codex/config.toml", ToolType: "codex"},
	{Path: ".codex/config.yaml", ToolType: "codex"},
	{Path: ".codex/config.yml", ToolType: "codex"},
	{Path: ".claude/settings.json", ToolType: "claude"},
	{Path: ".claude/settings.local.json", ToolType: "claude"},
	{Path: ".cursor/mcp.json", ToolType: "cursor"},
	{Path: ".mcp.json", ToolType: "mcp"},
}

var projectMarkers = []markerSpec{
	{Path: "AGENTS.md", ToolType: "codex"},
	{Path: "AGENTS.override.md", ToolType: "codex"},
	{Path: "CLAUDE.md", ToolType: "claude"},
	{Path: ".claude", ToolType: "claude"},
	{Path: ".agents", ToolType: "skill"},
	{Path: ".codex/config.toml", ToolType: "codex"},
	{Path: ".codex/config.yaml", ToolType: "codex"},
	{Path: ".codex/config.yml", ToolType: "codex"},
	{Path: ".cursor/mcp.json", ToolType: "cursor"},
	{Path: ".mcp.json", ToolType: "mcp"},
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	if !detect.IsLocalMachineScope(scope) {
		return nil, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	if envKeys := presentEnvKeys(); len(envKeys) > 0 {
		findings = append(findings, model.Finding{
			FindingType: "secret_presence",
			Severity:    model.SeverityHigh,
			ToolType:    "secret",
			Location:    "process:env",
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "credential_keys", Value: strings.Join(envKeys, ",")},
				{Key: "value_redacted", Value: "true"},
				{Key: "source", Value: "process_env"},
			},
			Remediation: "Move long-lived API keys to managed secret stores and remove unused local environment credentials.",
		})
	}

	projects, err := discoverProjects(home)
	if err != nil {
		return nil, err
	}
	homeFindings, err := homeMarkerHits(home)
	if err != nil {
		return nil, err
	}
	findings = append(findings, homeFindings...)
	findings = append(findings, projects...)
	model.SortFindings(findings)
	return findings, nil
}

func presentEnvKeys() []string {
	keys := make([]string, 0, len(envKeyMatchers))
	for _, key := range envKeyMatchers {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func discoverProjects(home string) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	for _, rootName := range workspaceRoots {
		rootPath := filepath.Join(home, rootName)
		info, err := os.Stat(rootPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			projectName := entry.Name()
			if strings.HasPrefix(projectName, ".") {
				continue
			}
			projectRoot := filepath.Join(rootPath, projectName)
			markers, err := markerHits(projectRoot, rootName, projectName, projectMarkers)
			if err != nil {
				return nil, err
			}
			findings = append(findings, markers...)
		}
	}
	model.SortFindings(findings)
	return findings, nil
}

func homeMarkerHits(home string) ([]model.Finding, error) {
	return markerHits(home, "", "", homeMarkers)
}

func markerHits(root, workspaceRoot, projectName string, markers []markerSpec) ([]model.Finding, error) {
	findings := make([]model.Finding, 0)
	for _, marker := range markers {
		fileExists, fileErr := detect.FileExistsWithinRoot(detectorID, root, marker.Path)
		if fileErr != nil {
			return nil, detect.ParseErrorAsError(fileErr)
		}
		dirExists, dirErr := detect.DirExistsWithinRoot(detectorID, root, marker.Path)
		if dirErr != nil {
			return nil, detect.ParseErrorAsError(dirErr)
		}
		if !fileExists && !dirExists {
			continue
		}
		location := marker.Path
		if workspaceRoot != "" || projectName != "" {
			location = filepath.ToSlash(filepath.Join(workspaceRoot, projectName, marker.Path))
		}
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    marker.ToolType,
			Location:    location,
			Repo:        "local-machine",
			Org:         "local",
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "project_name", Value: projectName},
				{Key: "workspace_root", Value: workspaceRoot},
				{Key: "marker", Value: marker.Path},
			},
			Remediation: "Review local agent project boundaries and ensure tool access is intentional.",
		})
	}
	return findings, nil
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
