package claude

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "claude"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type settingsFile struct {
	AllowedTools []string         `json:"allowedTools"`
	Hooks        []string         `json:"hooks"`
	Commands     map[string]any   `json:"commands"`
	MCPServers   map[string]mcpV1 `json:"mcpServers"`
}

type mcpV1 struct {
	Command string `json:"command"`
	URL     string `json:"url"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	if detect.DirExists(scope.Root, ".claude") {
		findings = append(findings, baseFinding(scope, ".claude", "claude config directory discovered", nil))
	}
	if detect.FileExists(scope.Root, "CLAUDE.md") {
		findings = append(findings, baseFinding(scope, "CLAUDE.md", "claude instructions file discovered", nil))
	}
	if detect.DirExists(scope.Root, ".claude/commands") {
		findings = append(findings, baseFinding(scope, ".claude/commands", "claude commands discovered", []string{"proc.exec"}))
	}
	if detect.DirExists(scope.Root, ".claude/hooks") {
		findings = append(findings, baseFinding(scope, ".claude/hooks", "claude hooks discovered", []string{"proc.exec"}))
	}

	for _, rel := range []string{".claude/settings.json", ".claude/settings.local.json", ".mcp.json"} {
		if !detect.FileExists(scope.Root, rel) {
			continue
		}
		var parsed settingsFile
		if parseErr := detect.ParseJSONFile(detectorID, scope.Root, rel, &parsed); parseErr != nil {
			findings = append(findings, parseErrorFinding(scope, rel, parseErr))
			continue
		}
		perms := make([]string, 0, len(parsed.AllowedTools)+len(parsed.Hooks)+len(parsed.Commands))
		for _, item := range parsed.AllowedTools {
			perms = append(perms, normalizeToolPermission(item))
		}
		if len(parsed.Hooks) > 0 || len(parsed.Commands) > 0 {
			perms = append(perms, "proc.exec")
		}
		if len(parsed.MCPServers) > 0 {
			perms = append(perms, "mcp.access")
		}
		findings = append(findings, baseFinding(scope, rel, fmt.Sprintf("claude structured config parsed (%d MCP servers)", len(parsed.MCPServers)), perms))
	}

	model.SortFindings(findings)
	return findings, nil
}

func baseFinding(scope detect.Scope, location, note string, permissions []string) model.Finding {
	evidence := []model.Evidence{{Key: "note", Value: note}}
	if strings.TrimSpace(scope.Repo) != "" {
		evidence = append(evidence, model.Evidence{Key: "repo", Value: scope.Repo})
	}
	if strings.TrimSpace(scope.Org) != "" {
		evidence = append(evidence, model.Evidence{Key: "org", Value: scope.Org})
	}
	return model.Finding{
		FindingType: "tool_config",
		Severity:    model.SeverityLow,
		ToolType:    "claude",
		Location:    location,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		Permissions: permissions,
		Evidence:    evidence,
	}
}

func parseErrorFinding(scope detect.Scope, location string, parseErr *model.ParseError) model.Finding {
	parseErr.Detector = detectorID
	return model.Finding{
		FindingType: "parse_error",
		Severity:    model.SeverityMedium,
		ToolType:    "claude",
		Location:    location,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		ParseError:  parseErr,
		Remediation: "Fix malformed structured configuration so deterministic parsing can proceed.",
	}
}

func normalizeToolPermission(tool string) string {
	tool = strings.TrimSpace(strings.ToLower(tool))
	switch tool {
	case "bash", "shell", "proc.exec":
		return "proc.exec"
	case "file_edit", "file.write", "edit":
		return "filesystem.write"
	case "web_search", "web", "http":
		return "network.access"
	default:
		return tool
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

func normalizePermissions(in []string) []string {
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
	return out
}
