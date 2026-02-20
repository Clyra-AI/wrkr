package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/supplychain"
	"gopkg.in/yaml.v3"
)

const detectorID = "mcp"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type serverDef struct {
	Command   string            `json:"command" yaml:"command" toml:"command"`
	Args      []string          `json:"args" yaml:"args" toml:"args"`
	URL       string            `json:"url" yaml:"url" toml:"url"`
	Transport string            `json:"transport" yaml:"transport" toml:"transport"`
	Env       map[string]string `json:"env" yaml:"env" toml:"env"`
}

type mcpDoc struct {
	MCPServers map[string]serverDef `json:"mcpServers" yaml:"mcpServers" toml:"mcp_servers"`
}

var pinRE = regexp.MustCompile(`@[0-9]+`)

func (Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	lockfilePresent := hasLockfile(scope.Root)
	findings := make([]model.Finding, 0)
	paths := []string{
		".mcp.json",
		".cursor/mcp.json",
		".vscode/mcp.json",
		"mcp.json",
		"managed-mcp.json",
		".claude/settings.json",
		".claude/settings.local.json",
		".codex/config.toml",
		".codex/config.yaml",
	}
	for _, rel := range paths {
		if !detect.FileExists(scope.Root, rel) {
			continue
		}
		doc, parseErr := parseMCPDocument(scope.Root, rel)
		if parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}
		for name, server := range doc.MCPServers {
			transport := inferTransport(server)
			credentialRefs := countCredentialRefs(server)
			pinned := isPinned(server)
			trustScore := supplychain.ScoreMCP(supplychain.MCPInput{
				Transport:      transport,
				Pinned:         pinned,
				HasLockfile:    lockfilePresent,
				CredentialRefs: credentialRefs,
			})
			severity := supplychain.SeverityFromTrust(trustScore)
			evidence := []model.Evidence{
				{Key: "server", Value: name},
				{Key: "transport", Value: transport},
				{Key: "pinned", Value: fmt.Sprintf("%t", pinned)},
				{Key: "lockfile", Value: fmt.Sprintf("%t", lockfilePresent)},
				{Key: "credential_refs", Value: fmt.Sprintf("%d", credentialRefs)},
				{Key: "trust_score", Value: fmt.Sprintf("%.1f", trustScore)},
			}
			if options.Enrich {
				evidence = append(evidence,
					model.Evidence{Key: "enrich_mode", Value: "true"},
					model.Evidence{Key: "advisory_lookup", Value: "not_implemented"},
				)
			}
			findings = append(findings, model.Finding{
				FindingType: "mcp_server",
				Severity:    severity,
				ToolType:    "mcp",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Permissions: []string{"mcp.access"},
				Evidence:    evidence,
				Remediation: "Pin MCP server package versions and remove credential-bearing transports where possible.",
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseMCPDocument(root, rel string) (mcpDoc, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- parser reads repository files selected by user.
	payload, err := os.ReadFile(path)
	if err != nil {
		return mcpDoc{}, &model.ParseError{Kind: "file_read_error", Path: rel, Detector: detectorID, Message: err.Error()}
	}

	var parsed mcpDoc
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		if decodeErr := json.Unmarshal(payload, &parsed); decodeErr != nil {
			return mcpDoc{}, &model.ParseError{Kind: "parse_error", Format: "json", Path: rel, Detector: detectorID, Message: decodeErr.Error()}
		}
	case ".toml":
		if _, decodeErr := toml.Decode(string(payload), &parsed); decodeErr != nil {
			return mcpDoc{}, &model.ParseError{Kind: "parse_error", Format: "toml", Path: rel, Detector: detectorID, Message: decodeErr.Error()}
		}
	case ".yaml", ".yml":
		if decodeErr := yaml.Unmarshal(payload, &parsed); decodeErr != nil {
			return mcpDoc{}, &model.ParseError{Kind: "parse_error", Format: "yaml", Path: rel, Detector: detectorID, Message: decodeErr.Error()}
		}
	default:
		return mcpDoc{}, nil
	}
	return parsed, nil
}

func inferTransport(server serverDef) string {
	if strings.TrimSpace(server.Transport) != "" {
		return strings.ToLower(strings.TrimSpace(server.Transport))
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(server.URL)), "http") {
		return "http"
	}
	if strings.TrimSpace(server.Command) != "" {
		return "stdio"
	}
	return "unknown"
}

func countCredentialRefs(server serverDef) int {
	count := 0
	for _, field := range []string{server.Command, server.URL} {
		if containsCredentialRef(field) {
			count++
		}
	}
	for _, arg := range server.Args {
		if containsCredentialRef(arg) {
			count++
		}
	}
	for key, value := range server.Env {
		if containsCredentialRef(key) || containsCredentialRef(value) {
			count++
		}
	}
	return count
}

func containsCredentialRef(in string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(in))
	if trimmed == "" {
		return false
	}
	return strings.Contains(trimmed, "secrets.") || strings.Contains(trimmed, "${") || strings.Contains(trimmed, "token") || strings.Contains(trimmed, "api_key")
}

func isPinned(server serverDef) bool {
	if pinRE.MatchString(server.Command) || pinRE.MatchString(server.URL) {
		return true
	}
	for _, arg := range server.Args {
		if pinRE.MatchString(arg) {
			return true
		}
	}
	return false
}

func hasLockfile(root string) bool {
	lockfiles := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "uv.lock"}
	for _, rel := range lockfiles {
		if detect.FileExists(root, rel) {
			return true
		}
	}
	return false
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
