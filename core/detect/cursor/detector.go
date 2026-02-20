package cursor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "cursor"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type cursorMCP struct {
	MCPServers map[string]struct {
		URL string `json:"url"`
	} `json:"mcpServers"`
}

type ruleFrontmatter struct {
	Description string   `yaml:"description"`
	AlwaysApply bool     `yaml:"alwaysApply"`
	Globs       []string `yaml:"globs"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	findings := make([]model.Finding, 0)
	if detect.FileExists(scope.Root, ".cursorrules") {
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "cursor",
			Location:    ".cursorrules",
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence:    []model.Evidence{{Key: "deprecated_surface", Value: "true"}},
		})
	}

	rules, globErr := detect.Glob(scope.Root, ".cursor/rules/*.mdc")
	if globErr != nil {
		return nil, fmt.Errorf("glob cursor rules: %w", globErr)
	}
	for _, rel := range rules {
		frontmatter, parseErr := parseMDCFrontmatter(scope.Root, rel)
		if parseErr != nil {
			parseErr.Detector = detectorID
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "cursor",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "cursor",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "always_apply", Value: fmt.Sprintf("%t", frontmatter.AlwaysApply)},
				{Key: "glob_count", Value: fmt.Sprintf("%d", len(frontmatter.Globs))},
			},
		})
	}

	if detect.FileExists(scope.Root, ".cursor/mcp.json") {
		var parsed cursorMCP
		if parseErr := detect.ParseJSONFile(detectorID, scope.Root, ".cursor/mcp.json", &parsed); parseErr != nil {
			parseErr.Detector = detectorID
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "cursor",
				Location:    ".cursor/mcp.json",
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
		} else {
			findings = append(findings, model.Finding{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "cursor",
				Location:    ".cursor/mcp.json",
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

func parseMDCFrontmatter(root, rel string) (ruleFrontmatter, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- reads fixture/config paths inside selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return ruleFrontmatter{}, &model.ParseError{Kind: "file_read_error", Path: rel, Message: err.Error()}
	}
	trimmed := string(payload)
	if !strings.HasPrefix(trimmed, "---\n") {
		return ruleFrontmatter{}, nil
	}
	idx := strings.Index(trimmed[4:], "\n---\n")
	if idx < 0 {
		return ruleFrontmatter{}, &model.ParseError{Kind: "parse_error", Format: "yaml", Path: rel, Message: "missing frontmatter terminator"}
	}
	section := trimmed[4 : 4+idx]
	var out ruleFrontmatter
	decoder := yaml.NewDecoder(bytes.NewBufferString(section))
	decoder.KnownFields(true)
	if decodeErr := decoder.Decode(&out); decodeErr != nil {
		return ruleFrontmatter{}, &model.ParseError{Kind: "parse_error", Format: "yaml", Path: rel, Message: decodeErr.Error()}
	}
	return out, nil
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
