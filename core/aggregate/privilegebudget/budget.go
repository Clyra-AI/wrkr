package privilegebudget

import (
	"net/url"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy/productiontargets"
)

type findingSignals struct {
	Repos      []string
	Locations  []string
	EvidenceKV map[string][]string
	Values     []string
}

func Build(
	tools []agginventory.Tool,
	findings []model.Finding,
	productionRules *productiontargets.Config,
) (agginventory.PrivilegeBudget, []agginventory.AgentPrivilegeMapEntry) {
	writeSet := mapFromList(productiontargets.DefaultWritePermissions())
	productionConfigured := false
	if productionRules != nil {
		writeSet = mapFromList(productionRules.WritePermissions)
		productionConfigured = productionRules.HasTargets()
	}

	signalsByAgent := buildSignalsByAgent(findings)
	budget := agginventory.PrivilegeBudget{
		TotalTools: len(tools),
		ProductionWrite: agginventory.ProductionWriteBudget{
			Configured: productionConfigured,
			Status:     agginventory.ProductionTargetsStatusNotConfigured,
			Count:      nil,
		},
	}
	if productionConfigured {
		zero := 0
		budget.ProductionWrite.Status = agginventory.ProductionTargetsStatusConfigured
		budget.ProductionWrite.Count = &zero
	}

	entries := make([]agginventory.AgentPrivilegeMapEntry, 0, len(tools))
	for _, tool := range tools {
		writeCapable := hasAnyPermission(tool.Permissions, writeSet)
		credentialAccess := hasCredentialAccess(tool)
		execCapable := hasExecPermission(tool.Permissions)
		if writeCapable {
			budget.WriteCapableTools++
		}
		if credentialAccess {
			budget.CredentialAccessTools++
		}
		if execCapable {
			budget.ExecCapableTools++
		}

		matchedTargets := []string{}
		productionWrite := false
		if productionConfigured && writeCapable {
			signal := signalsByAgent[tool.AgentID]
			matchedTargets = matchedProductionTargets(tool, signal, *productionRules)
			productionWrite = len(matchedTargets) > 0
			if productionWrite && budget.ProductionWrite.Count != nil {
				*budget.ProductionWrite.Count = *budget.ProductionWrite.Count + 1
			}
		}

		entries = append(entries, agginventory.AgentPrivilegeMapEntry{
			AgentID:                  tool.AgentID,
			ToolID:                   tool.ToolID,
			ToolType:                 tool.ToolType,
			Org:                      tool.Org,
			Repos:                    cloneStringSlice(tool.Repos),
			Permissions:              cloneStringSlice(tool.Permissions),
			EndpointClass:            tool.EndpointClass,
			DataClass:                tool.DataClass,
			AutonomyLevel:            tool.AutonomyLevel,
			RiskScore:                tool.RiskScore,
			WriteCapable:             writeCapable,
			CredentialAccess:         credentialAccess,
			ExecCapable:              execCapable,
			ProductionWrite:          productionWrite,
			MatchedProductionTargets: append([]string(nil), matchedTargets...),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].AgentID != entries[j].AgentID {
			return entries[i].AgentID < entries[j].AgentID
		}
		if entries[i].ToolType != entries[j].ToolType {
			return entries[i].ToolType < entries[j].ToolType
		}
		return entries[i].ToolID < entries[j].ToolID
	})

	return budget, entries
}

func buildSignalsByAgent(findings []model.Finding) map[string]findingSignals {
	out := map[string]findingSignals{}
	for _, finding := range findings {
		agentID := identity.AgentID(identity.ToolID(finding.ToolType, finding.Location), fallbackOrg(finding.Org))
		entry := out[agentID]
		if entry.EvidenceKV == nil {
			entry.EvidenceKV = map[string][]string{}
		}
		if repo := normalizeToken(finding.Repo); repo != "" {
			entry.Repos = append(entry.Repos, repo)
			entry.Values = append(entry.Values, repo)
		}
		if location := normalizeToken(finding.Location); location != "" {
			entry.Locations = append(entry.Locations, location)
			entry.Values = append(entry.Values, location)
			entry.Values = append(entry.Values, extractHost(location)...)
		}
		for _, permission := range finding.Permissions {
			if normalized := normalizeToken(permission); normalized != "" {
				entry.Values = append(entry.Values, normalized)
			}
		}
		for _, evidence := range finding.Evidence {
			key := normalizeToken(evidence.Key)
			value := normalizeToken(evidence.Value)
			if key != "" {
				entry.Values = append(entry.Values, key)
			}
			if value != "" {
				entry.Values = append(entry.Values, value)
				entry.Values = append(entry.Values, extractHost(value)...)
			}
			if key != "" && value != "" {
				entry.EvidenceKV[key] = append(entry.EvidenceKV[key], value)
			}
		}
		entry.Repos = dedupeSorted(entry.Repos)
		entry.Locations = dedupeSorted(entry.Locations)
		entry.Values = dedupeSorted(entry.Values)
		for key, values := range entry.EvidenceKV {
			entry.EvidenceKV[key] = dedupeSorted(values)
		}
		out[agentID] = entry
	}
	return out
}

func matchedProductionTargets(
	tool agginventory.Tool,
	signals findingSignals,
	rules productiontargets.Config,
) []string {
	matches := map[string]struct{}{}
	addMatchSet(matches, "repo", rules.Targets.Repos, append(append([]string(nil), tool.Repos...), signals.Repos...))
	addMatchSet(matches, "mcp_server", rules.Targets.MCPServers, signals.EvidenceKV["server"])
	hostCandidates := append([]string{}, signals.EvidenceKV["url"]...)
	hostCandidates = append(hostCandidates, signals.Values...)
	addMatchSet(matches, "host", rules.Targets.Hosts, hostCandidates)

	envKeyCandidates := append([]string{}, signals.EvidenceKV["env_key"]...)
	envKeyCandidates = append(envKeyCandidates, signals.Values...)
	addMatchSet(matches, "workflow_env_key", rules.Targets.WorkflowEnvKeys, envKeyCandidates)

	envValueCandidates := append([]string{}, signals.EvidenceKV["env_value"]...)
	envValueCandidates = append(envValueCandidates, signals.Values...)
	addMatchSet(matches, "workflow_env_value", rules.Targets.WorkflowEnvValues, envValueCandidates)

	out := make([]string, 0, len(matches))
	for item := range matches {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func addMatchSet(out map[string]struct{}, label string, set productiontargets.MatchSet, candidates []string) {
	for _, candidate := range candidates {
		normalized := normalizeToken(candidate)
		if normalized == "" {
			continue
		}
		if set.Match(normalized) {
			out[label+":"+normalized] = struct{}{}
		}
	}
}

func hasAnyPermission(permissions []string, allowed map[string]struct{}) bool {
	for _, permission := range permissions {
		if _, ok := allowed[normalizeToken(permission)]; ok {
			return true
		}
	}
	return false
}

func hasCredentialAccess(tool agginventory.Tool) bool {
	if normalizeToken(tool.DataClass) == "credentials" {
		return true
	}
	for _, permission := range tool.Permissions {
		normalized := normalizeToken(permission)
		if strings.Contains(normalized, "secret") || strings.Contains(normalized, "token") || strings.Contains(normalized, "credential") {
			return true
		}
	}
	return false
}

func hasExecPermission(permissions []string) bool {
	for _, permission := range permissions {
		if normalizeToken(permission) == "proc.exec" {
			return true
		}
	}
	return false
}

func mapFromList(items []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		normalized := normalizeToken(item)
		if normalized == "" {
			continue
		}
		out[normalized] = struct{}{}
	}
	return out
}

func extractHost(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	if parsed, err := url.Parse(trimmed); err == nil {
		host := normalizeToken(parsed.Hostname())
		if host != "" {
			return []string{host}
		}
	}
	return nil
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		normalized := normalizeToken(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func normalizeToken(in string) string {
	return strings.ToLower(strings.TrimSpace(in))
}

func fallbackOrg(org string) string {
	trimmed := strings.TrimSpace(org)
	if trimmed == "" {
		return "local"
	}
	return trimmed
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(values))
	out = append(out, values...)
	return out
}
