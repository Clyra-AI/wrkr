package mcp

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

var (
	scriptCredentialRefPattern = regexp.MustCompile(`(?:\$\{?([A-Z][A-Z0-9_]+)\}?|process\.env\.([A-Z][A-Z0-9_]+)|os\.environ\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\])`)
	fastMCPNamePattern         = regexp.MustCompile(`(?i)\bFastMCP\s*\(\s*["']([^"']+)["']`)
	mcpSDKImportPattern        = regexp.MustCompile(`(?i)(@modelcontextprotocol/sdk|modelcontextprotocol|fastmcp)`)
)

var knownMCPPackageNames = []string{
	"@modelcontextprotocol/sdk",
	"fastmcp",
	"modelcontextprotocol",
	"mcp-proxy",
	"mcp-server",
	"@anthropic-ai/mcp",
}

type packageManifest struct {
	Dependencies         map[string]string
	DevDependencies      map[string]string
	OptionalDependencies map[string]string
	PeerDependencies     map[string]string
	Scripts              map[string]string
	WorkspacePackages    []string
}

type candidateFinding struct {
	name              string
	location          string
	evidenceType      string
	confidence        string
	declarationType   string
	transportHint     string
	credentialRefs    []string
	unsupportedReason string
}

func detectAdditionalCandidates(scope detect.Scope, options detect.Options) []model.Finding {
	files, err := detect.WalkFilesWithOptions(scope.Root, options)
	if err != nil {
		return nil
	}

	seen := map[string]candidateFinding{}
	for _, rel := range files {
		switch {
		case strings.EqualFold(filepath.Base(rel), "package.json"):
			for _, item := range packageCandidates(scope.Root, rel) {
				key := strings.Join([]string{item.location, item.name, item.evidenceType, item.declarationType}, "|")
				seen[key] = item
			}
		case isCandidateSourceFile(rel):
			for _, item := range sourceCandidates(scope.Root, rel) {
				key := strings.Join([]string{item.location, item.name, item.evidenceType, item.declarationType}, "|")
				seen[key] = item
			}
		}
	}

	if len(seen) == 0 {
		return nil
	}
	findings := make([]model.Finding, 0, len(seen))
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := seen[key]
		evidence := []model.Evidence{
			{Key: "candidate_name", Value: strings.TrimSpace(item.name)},
			{Key: "evidence_type", Value: strings.TrimSpace(item.evidenceType)},
			{Key: "confidence", Value: normalizeConfidence(item.confidence)},
			{Key: "declaration_type", Value: strings.TrimSpace(item.declarationType)},
			{Key: "transport_hint", Value: firstNonEmptyCandidateValue(item.transportHint, "unknown")},
			{Key: "credential_refs", Value: strings.Join(uniqueSortedCandidateStrings(item.credentialRefs), ",")},
		}
		if strings.TrimSpace(item.unsupportedReason) != "" {
			evidence = append(evidence, model.Evidence{Key: "unsupported_declaration_reason", Value: strings.TrimSpace(item.unsupportedReason)})
		}
		findings = append(findings, model.Finding{
			FindingType: "mcp_server_candidate",
			Severity:    model.SeverityLow,
			ToolType:    "mcp",
			Location:    strings.TrimSpace(item.location),
			Repo:        strings.TrimSpace(scope.Repo),
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence:    evidence,
			Remediation: "Confirm MCP declaration evidence, attach the fixed config or source binding, and rerun the scan before treating this server as authoritative.",
		})
	}
	return findings
}

func packageCandidates(root, rel string) []candidateFinding {
	manifest, ok := parsePackageManifest(root, rel)
	if !ok {
		return nil
	}

	out := make([]candidateFinding, 0)
	for _, dep := range allPackageDependencies(manifest) {
		if !isKnownMCPPackage(dep) {
			continue
		}
		out = append(out, candidateFinding{
			name:            dep,
			location:        rel,
			evidenceType:    "package_dependency",
			confidence:      "medium",
			declarationType: "package_dependency",
			transportHint:   "stdio",
		})
	}
	for _, scriptName := range sortedPackageScripts(manifest.Scripts) {
		command := strings.TrimSpace(manifest.Scripts[scriptName])
		if !looksLikeMCPCommand(scriptName, command) {
			continue
		}
		out = append(out, candidateFinding{
			name:              inferCandidateNameFromScript(scriptName, command),
			location:          rel,
			evidenceType:      "package_script",
			confidence:        inferScriptCandidateConfidence(command),
			declarationType:   "script_command",
			transportHint:     inferTransportHint(command),
			credentialRefs:    extractCredentialRefs(command),
			unsupportedReason: unsupportedScriptReason(command),
		})
	}
	for _, workspacePackage := range manifest.WorkspacePackages {
		if !strings.Contains(strings.ToLower(strings.TrimSpace(workspacePackage)), "mcp") {
			continue
		}
		out = append(out, candidateFinding{
			name:            filepath.Base(strings.TrimSpace(workspacePackage)),
			location:        rel,
			evidenceType:    "workspace_package",
			confidence:      "low",
			declarationType: "workspace_package",
			transportHint:   "unknown",
		})
	}
	return out
}

func parsePackageManifest(root, rel string) (packageManifest, bool) {
	var raw map[string]json.RawMessage
	if parseErr := detect.ParseJSONFileTolerant(detectorID, root, rel, &raw); parseErr != nil {
		return packageManifest{}, false
	}
	return packageManifest{
		Dependencies:         decodeStringMap(raw["dependencies"]),
		DevDependencies:      decodeStringMap(raw["devDependencies"]),
		OptionalDependencies: decodeStringMap(raw["optionalDependencies"]),
		PeerDependencies:     decodeStringMap(raw["peerDependencies"]),
		Scripts:              decodeStringMap(raw["scripts"]),
		WorkspacePackages:    decodeWorkspacePackages(raw["workspaces"]),
	}, true
}

func decodeStringMap(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	parsed := map[string]string{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	if len(parsed) == 0 {
		return nil
	}
	return parsed
}

func decodeWorkspacePackages(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return uniqueSortedCandidateStrings(list)
	}
	var object struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil
	}
	return uniqueSortedCandidateStrings(object.Packages)
}

func allPackageDependencies(manifest packageManifest) []string {
	set := map[string]struct{}{}
	for _, source := range []map[string]string{
		manifest.Dependencies,
		manifest.DevDependencies,
		manifest.OptionalDependencies,
		manifest.PeerDependencies,
	} {
		for name := range source {
			trimmed := strings.TrimSpace(name)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	return sortedCandidateSet(set)
}

func sortedPackageScripts(scripts map[string]string) []string {
	if len(scripts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(scripts))
	for key := range scripts {
		if strings.TrimSpace(key) == "" {
			continue
		}
		keys = append(keys, strings.TrimSpace(key))
	}
	sort.Strings(keys)
	return keys
}

func looksLikeMCPCommand(scriptName, command string) bool {
	combined := strings.ToLower(strings.TrimSpace(scriptName + " " + command))
	if combined == "" {
		return false
	}
	for _, marker := range []string{"mcp", "fastmcp", "modelcontextprotocol", ".well-known/webmcp"} {
		if strings.Contains(combined, marker) {
			return true
		}
	}
	return false
}

func inferCandidateNameFromScript(scriptName, command string) string {
	for _, field := range strings.Fields(command) {
		trimmed := strings.Trim(strings.TrimSpace(field), `"'`)
		if isKnownMCPPackage(trimmed) {
			return trimmed
		}
	}
	if strings.TrimSpace(scriptName) != "" {
		return strings.TrimSpace(scriptName)
	}
	return "mcp-candidate"
}

func inferScriptCandidateConfidence(command string) string {
	lower := strings.ToLower(strings.TrimSpace(command))
	switch {
	case strings.Contains(lower, "@modelcontextprotocol/sdk"),
		strings.Contains(lower, "fastmcp"),
		strings.Contains(lower, "mcp-server"),
		strings.Contains(lower, ".well-known/webmcp"):
		return "medium"
	default:
		return "low"
	}
}

func inferTransportHint(command string) string {
	lower := strings.ToLower(strings.TrimSpace(command))
	switch {
	case strings.Contains(lower, "http://"), strings.Contains(lower, "https://"), strings.Contains(lower, ".well-known/webmcp"):
		return "http"
	case strings.Contains(lower, "npx"), strings.Contains(lower, "uvx"), strings.Contains(lower, "python"), strings.Contains(lower, "node"), strings.Contains(lower, "mcp"):
		return "stdio"
	default:
		return "unknown"
	}
}

func unsupportedScriptReason(command string) string {
	lower := strings.ToLower(strings.TrimSpace(command))
	if lower == "" {
		return "empty_script_command"
	}
	if strings.Contains(lower, "mcp") && !strings.Contains(lower, "npx") && !strings.Contains(lower, "uvx") && !strings.Contains(lower, "node") && !strings.Contains(lower, "python") && !strings.Contains(lower, ".well-known/webmcp") {
		return "ambiguous_script_invocation"
	}
	return ""
}

func extractCredentialRefs(command string) []string {
	matches := scriptCredentialRefPattern.FindAllStringSubmatch(command, -1)
	if len(matches) == 0 {
		return nil
	}
	refs := make([]string, 0, len(matches))
	for _, match := range matches {
		for _, value := range match[1:] {
			if strings.TrimSpace(value) != "" {
				refs = append(refs, strings.TrimSpace(value))
			}
		}
	}
	return uniqueSortedCandidateStrings(refs)
}

func isKnownMCPPackage(name string) bool {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		return false
	}
	for _, known := range knownMCPPackageNames {
		if normalized == known {
			return true
		}
	}
	return strings.Contains(normalized, "mcp-server") || strings.HasPrefix(normalized, "@modelcontextprotocol/")
}

func isCandidateSourceFile(rel string) bool {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func sourceCandidates(root, rel string) []candidateFinding {
	payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
	if parseErr != nil {
		return nil
	}
	content := string(payload)
	lower := strings.ToLower(content)
	if !strings.Contains(lower, "mcp") && !mcpSDKImportPattern.MatchString(content) {
		return nil
	}

	out := make([]candidateFinding, 0, 2)
	if match := fastMCPNamePattern.FindStringSubmatch(content); len(match) == 2 {
		out = append(out, candidateFinding{
			name:            strings.TrimSpace(match[1]),
			location:        rel,
			evidenceType:    "source_hint",
			confidence:      "medium",
			declarationType: "source_literal",
			transportHint:   "http",
			credentialRefs:  extractCredentialRefs(content),
		})
	}
	if mcpSDKImportPattern.MatchString(content) || strings.Contains(lower, ".well-known/webmcp") {
		out = append(out, candidateFinding{
			name:            firstNonEmptyCandidateValue(filepath.Base(rel), "mcp-source-hint"),
			location:        rel,
			evidenceType:    "source_hint",
			confidence:      "low",
			declarationType: "source_import",
			transportHint:   inferTransportHint(content),
			credentialRefs:  extractCredentialRefs(content),
		})
	}
	return out
}

func normalizeConfidence(value string) string {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "high", "medium":
		return strings.TrimSpace(strings.ToLower(value))
	default:
		return "low"
	}
}

func firstNonEmptyCandidateValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func uniqueSortedCandidateStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return sortedCandidateSet(set)
}

func sortedCandidateSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
