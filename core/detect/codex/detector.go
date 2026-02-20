package codex

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "codex"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type configModel struct {
	SandboxMode    string `toml:"sandbox_mode" yaml:"sandbox_mode"`
	ApprovalPolicy string `toml:"approval_policy" yaml:"approval_policy"`
	NetworkAccess  bool   `toml:"network_access" yaml:"network_access"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}
	findings := make([]model.Finding, 0)

	for _, rel := range []string{"AGENTS.md", "AGENTS.override.md"} {
		if !detect.FileExists(scope.Root, rel) {
			continue
		}
		findings = append(findings, model.Finding{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "codex",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
		})
	}

	if detect.FileExists(scope.Root, ".codex/config.toml") {
		items, parseErr := parseConfig(scope, ".codex/config.toml", "toml")
		if parseErr != nil {
			findings = append(findings, *parseErr)
		} else {
			findings = append(findings, items)
		}
	}
	if detect.FileExists(scope.Root, ".codex/config.yaml") {
		items, parseErr := parseConfig(scope, ".codex/config.yaml", "yaml")
		if parseErr != nil {
			findings = append(findings, *parseErr)
		} else {
			findings = append(findings, items)
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseConfig(scope detect.Scope, rel, format string) (model.Finding, *model.Finding) {
	var parsed configModel
	var parseErr *model.ParseError
	switch format {
	case "toml":
		parseErr = detect.ParseTOMLFile(detectorID, scope.Root, rel, &parsed)
	case "yaml":
		parseErr = detect.ParseYAMLFile(detectorID, scope.Root, rel, &parsed)
	default:
		parseErr = &model.ParseError{Kind: "parse_error", Format: format, Path: rel, Detector: detectorID, Message: "unsupported format"}
	}
	if parseErr != nil {
		parseErr.Detector = detectorID
		finding := model.Finding{
			FindingType: "parse_error",
			Severity:    model.SeverityMedium,
			ToolType:    "codex",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			ParseError:  parseErr,
			Remediation: "Fix malformed Codex configuration.",
		}
		return model.Finding{}, &finding
	}

	permissions := make([]string, 0, 3)
	if strings.EqualFold(parsed.SandboxMode, "danger-full-access") {
		permissions = append(permissions, "filesystem.write")
	}
	if parsed.NetworkAccess {
		permissions = append(permissions, "network.access")
	}
	if strings.EqualFold(parsed.ApprovalPolicy, "never") {
		permissions = append(permissions, "proc.exec")
	}

	return model.Finding{
		FindingType: "tool_config",
		Severity:    model.SeverityLow,
		ToolType:    "codex",
		Location:    rel,
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		Permissions: permissions,
		Evidence: []model.Evidence{
			{Key: "sandbox_mode", Value: parsed.SandboxMode},
			{Key: "approval_policy", Value: parsed.ApprovalPolicy},
			{Key: "network_access", Value: fmt.Sprintf("%t", parsed.NetworkAccess)},
		},
	}, nil
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
