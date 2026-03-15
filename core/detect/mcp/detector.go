package mcp

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mcp/enrich"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/supplychain"
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
var packageRE = regexp.MustCompile(`(@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9._-]+)(?:@([A-Za-z0-9._-]+))?`)

func (Detector) Detect(ctx context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	var enrichService enrich.Service
	if options.Enrich {
		enrichService = enrich.NewDefault()
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
		exists, fileErr := detect.FileExistsWithinRoot(detectorID, scope.Root, rel)
		if fileErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  fileErr,
			})
			continue
		}
		if !exists {
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
		for _, name := range sortedServerNames(doc.MCPServers) {
			server := doc.MCPServers[name]
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
				pkg, version := extractPackageVersion(server)
				enrichResult := enrichService.Lookup(ctx, pkg, version)
				enrichErrors := "none"
				if len(enrichResult.Errors) > 0 {
					enrichErrors = strings.Join(enrichResult.Errors, ",")
				}
				evidence = append(evidence,
					model.Evidence{Key: "enrich_mode", Value: "true"},
					model.Evidence{Key: "enrich_quality", Value: enrichResult.Quality},
					model.Evidence{Key: "enrich_errors", Value: enrichErrors},
					model.Evidence{Key: "source", Value: enrichResult.Source},
					model.Evidence{Key: "as_of", Value: enrichResult.AsOf},
					model.Evidence{Key: "advisory_schema", Value: enrichResult.AdvisorySchema},
					model.Evidence{Key: "registry_schema", Value: enrichResult.RegistrySchema},
					model.Evidence{Key: "package", Value: fallbackValue(enrichResult.Package, "unknown")},
					model.Evidence{Key: "version", Value: fallbackValue(enrichResult.Version, "unknown")},
					model.Evidence{Key: "advisory_count", Value: fmt.Sprintf("%d", enrichResult.AdvisoryCount)},
					model.Evidence{Key: "registry_status", Value: enrichResult.RegistryStatus},
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
	var parsed mcpDoc
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		if parseErr := detect.ParseJSONFileAllowUnknownFields(detectorID, root, rel, &parsed); parseErr != nil {
			return mcpDoc{}, parseErr
		}
	case ".toml":
		if parseErr := detect.ParseTOMLFileAllowUnknownFields(detectorID, root, rel, &parsed); parseErr != nil {
			return mcpDoc{}, parseErr
		}
	case ".yaml", ".yml":
		if parseErr := detect.ParseYAMLFileAllowUnknownFields(detectorID, root, rel, &parsed); parseErr != nil {
			return mcpDoc{}, parseErr
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

func extractPackageVersion(server serverDef) (string, string) {
	fields := append([]string{}, server.Args...)
	fields = append(fields, server.Command, server.URL)
	fallbackPkg := ""
	fallbackVersion := ""
	for _, field := range fields {
		for _, match := range packageRE.FindAllStringSubmatch(field, -1) {
			if len(match) < 2 {
				continue
			}
			pkg := strings.TrimSpace(match[1])
			version := ""
			if len(match) > 2 {
				version = strings.TrimSpace(match[2])
			}
			if pkg == "" || strings.HasPrefix(pkg, "-") {
				continue
			}
			if fallbackPkg == "" {
				fallbackPkg = pkg
				fallbackVersion = version
			}
			if isLauncherPackage(pkg) {
				continue
			}
			return pkg, version
		}
	}
	return fallbackPkg, fallbackVersion
}

func isLauncherPackage(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "npx", "pnpm", "yarn", "bunx", "node", "python", "python3", "pipx", "uv", "uvx":
		return true
	default:
		return false
	}
}

func fallbackValue(value string, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

func sortedServerNames(in map[string]serverDef) []string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
