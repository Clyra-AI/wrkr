package model

import (
	"regexp"
	"strings"

	"github.com/Clyra-AI/wrkr/core/manifest"
)

var legacyToolIDPattern = regexp.MustCompile(`^(.+?)(?:-inst)?-[0-9a-f]{10}$`)

// IsIdentityBearingFinding returns whether a finding participates in lifecycle/regress identity state.
func IsIdentityBearingFinding(f Finding) bool {
	return isBearingFinding(f, identityBearingFindingTypes)
}

// IsInventoryBearingFinding returns whether a finding should materialize inventory entities.
func IsInventoryBearingFinding(f Finding) bool {
	return isBearingFinding(f, inventoryBearingFindingTypes)
}

// IsLegacyArtifactIdentityCandidate rejects only the non-tool identities older runtimes could materialize.
// When older artifacts do not retain enough type information to decide safely, this helper preserves them.
func IsLegacyArtifactIdentityCandidate(toolType, toolID, agentID string) bool {
	normalizedToolType := normalizeIdentityScopeToken(toolType)
	if normalizedToolType == "" {
		normalizedToolType = normalizeIdentityScopeToken(extractToolTypeFromToolID(toolID))
	}
	if normalizedToolType == "" {
		normalizedToolType = normalizeIdentityScopeToken(extractToolTypeFromAgentID(agentID))
	}
	if normalizedToolType == "" {
		return true
	}
	_, excluded := legacyNonToolArtifactTypes[normalizedToolType]
	return !excluded
}

// FilterLegacyArtifactIdentityRecords preserves only lifecycle-bearing tool identities from older artifacts.
func FilterLegacyArtifactIdentityRecords(records []manifest.IdentityRecord) []manifest.IdentityRecord {
	filtered := make([]manifest.IdentityRecord, 0, len(records))
	for _, record := range records {
		if !IsLegacyArtifactIdentityCandidate(record.ToolType, record.ToolID, record.AgentID) {
			continue
		}
		filtered = append(filtered, record)
	}
	return filtered
}

var identityBearingFindingTypes = map[string]struct{}{
	"a2a_agent_card":        {},
	"agent_custom_scaffold": {},
	"agent_custom_source":   {},
	"agent_framework":       {},
	"ai_dependency":         {},
	"ci_autonomy":           {},
	"compiled_action":       {},
	"mcp_server":            {},
	"skill":                 {},
	"tool_config":           {},
	"webmcp_declaration":    {},
}

var inventoryBearingFindingTypes = map[string]struct{}{
	"a2a_agent_card":        {},
	"agent_custom_scaffold": {},
	"agent_custom_source":   {},
	"agent_framework":       {},
	"ai_dependency":         {},
	"ci_autonomy":           {},
	"compiled_action":       {},
	"mcp_server":            {},
	"skill":                 {},
	"tool_config":           {},
	"webmcp_declaration":    {},
}

var legacyNonToolArtifactTypes = map[string]struct{}{
	"json":           {},
	"mcp_gateway":    {},
	"policy":         {},
	"prompt_channel": {},
	"secret":         {},
	"source_repo":    {},
	"toml":           {},
	"yaml":           {},
}

func isBearingFinding(f Finding, allowlist map[string]struct{}) bool {
	normalizedToolType := normalizeIdentityScopeToken(f.ToolType)
	if normalizedToolType == "" {
		return false
	}
	if _, allowed := allowlist[normalizeIdentityScopeToken(f.FindingType)]; allowed {
		return true
	}
	if normalizeIdentityScopeToken(f.Detector) != "extension" {
		return false
	}
	_, excluded := legacyNonToolArtifactTypes[normalizedToolType]
	return !excluded
}

func normalizeIdentityScopeToken(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	trimmed = strings.ReplaceAll(trimmed, "-", "_")
	return trimmed
}

func extractToolTypeFromAgentID(agentID string) string {
	parts := strings.SplitN(strings.TrimSpace(agentID), ":", 3)
	if len(parts) != 3 || parts[0] != "wrkr" {
		return ""
	}
	return extractToolTypeFromToolID(parts[1])
}

func extractToolTypeFromToolID(toolID string) string {
	matches := legacyToolIDPattern.FindStringSubmatch(strings.TrimSpace(toolID))
	if len(matches) != 2 {
		return ""
	}
	return matches[1]
}
