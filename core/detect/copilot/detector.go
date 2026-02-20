package copilot

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "copilot"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type mcpConfig struct {
	MCPServers map[string]struct {
		URL string `json:"url"`
	} `json:"mcpServers"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	copilotFiles, globErr := detect.Glob(scope.Root, ".github/copilot-*")
	if globErr != nil {
		return nil, fmt.Errorf("glob copilot files: %w", globErr)
	}
	for _, rel := range copilotFiles {
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "copilot",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
		})
	}

	if detect.FileExists(scope.Root, ".vscode/mcp.json") {
		var parsed mcpConfig
		if parseErr := detect.ParseJSONFile(detectorID, scope.Root, ".vscode/mcp.json", &parsed); parseErr != nil {
			parseErr.Detector = detectorID
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "copilot",
				Location:    ".vscode/mcp.json",
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
		} else {
			findings = append(findings, model.Finding{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "copilot",
				Location:    ".vscode/mcp.json",
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Permissions: []string{"mcp.access"},
				Evidence:    []model.Evidence{{Key: "mcp_server_count", Value: fmt.Sprintf("%d", len(parsed.MCPServers))}},
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
