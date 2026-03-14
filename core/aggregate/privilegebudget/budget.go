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
	Repos       []string
	Locations   []string
	Permissions []string
	EvidenceKV  map[string][]string
	Values      []string
}

func Build(
	tools []agginventory.Tool,
	agents []agginventory.Agent,
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

		productionWrite := false
		if productionConfigured && writeCapable {
			signal := signalsByAgent[tool.AgentID]
			productionWrite = len(matchedProductionTargets(tool.Repos, signal, *productionRules)) > 0
			if productionWrite && budget.ProductionWrite.Count != nil {
				*budget.ProductionWrite.Count = *budget.ProductionWrite.Count + 1
			}
		}
	}

	if len(agents) == 0 {
		agentContextByID := mapAgentsByID(agents)
		entries := make([]agginventory.AgentPrivilegeMapEntry, 0, len(tools))
		for _, tool := range tools {
			writeCapable := hasAnyPermission(tool.Permissions, writeSet)
			credentialAccess := hasCredentialAccess(tool)
			execCapable := hasExecPermission(tool.Permissions)

			matchedTargets := []string{}
			productionWrite := false
			if productionConfigured && writeCapable {
				signal := signalsByAgent[tool.AgentID]
				matchedTargets = matchedProductionTargets(tool.Repos, signal, *productionRules)
				productionWrite = len(matchedTargets) > 0
			}

			agentContext := agentContextByID[tool.AgentID]
			deploymentStatus := strings.TrimSpace(agentContext.DeploymentStatus)
			if deploymentStatus == "" {
				deploymentStatus = "unknown"
			}

			entries = append(entries, agginventory.AgentPrivilegeMapEntry{
				AgentID:                  tool.AgentID,
				ToolID:                   tool.ToolID,
				ToolType:                 tool.ToolType,
				Framework:                fallbackFramework(agentContext.Framework, tool.ToolType),
				Org:                      tool.Org,
				Repos:                    cloneStringSlice(tool.Repos),
				Permissions:              cloneStringSlice(tool.Permissions),
				EndpointClass:            tool.EndpointClass,
				DataClass:                tool.DataClass,
				AutonomyLevel:            tool.AutonomyLevel,
				RiskScore:                tool.RiskScore,
				ApprovalClassification:   strings.TrimSpace(tool.ApprovalClass),
				BoundTools:               cloneStringSlice(agentContext.BoundTools),
				BoundDataSources:         cloneStringSlice(agentContext.BoundDataSources),
				BoundAuthSurfaces:        cloneStringSlice(agentContext.BoundAuthSurfaces),
				BindingEvidenceKeys:      cloneStringSlice(agentContext.BindingEvidenceKeys),
				MissingBindings:          cloneStringSlice(agentContext.MissingBindings),
				DeploymentStatus:         deploymentStatus,
				DeploymentArtifacts:      cloneStringSlice(agentContext.DeploymentArtifacts),
				DeploymentEvidenceKeys:   cloneStringSlice(agentContext.DeploymentEvidenceKeys),
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

	entries := buildInstanceEntries(tools, agents, findings, writeSet, productionRules, productionConfigured)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Org != entries[j].Org {
			return entries[i].Org < entries[j].Org
		}
		if entries[i].Framework != entries[j].Framework {
			return entries[i].Framework < entries[j].Framework
		}
		if entries[i].Location != entries[j].Location {
			return entries[i].Location < entries[j].Location
		}
		iStart, iEnd := locationRangeBounds(entries[i].LocationRange)
		jStart, jEnd := locationRangeBounds(entries[j].LocationRange)
		if iStart != jStart {
			return iStart < jStart
		}
		if iEnd != jEnd {
			return iEnd < jEnd
		}
		if entries[i].AgentInstanceID != entries[j].AgentInstanceID {
			return entries[i].AgentInstanceID < entries[j].AgentInstanceID
		}
		if entries[i].Symbol != entries[j].Symbol {
			return entries[i].Symbol < entries[j].Symbol
		}
		return entries[i].AgentID < entries[j].AgentID
	})

	return budget, entries
}

func mapAgentsByID(agents []agginventory.Agent) map[string]agginventory.Agent {
	out := map[string]agginventory.Agent{}
	for _, agent := range agents {
		keys := agentLookupKeys(agent)
		if len(keys) == 0 {
			continue
		}
		for _, key := range keys {
			current := out[key]
			out[key] = mergeAgentContext(current, agent, key)
		}
	}
	return out
}

func buildInstanceEntries(
	tools []agginventory.Tool,
	agents []agginventory.Agent,
	findings []model.Finding,
	writeSet map[string]struct{},
	productionRules *productiontargets.Config,
	productionConfigured bool,
) []agginventory.AgentPrivilegeMapEntry {
	signalsByInstance := buildSignalsByInstance(findings)
	toolIndex := buildToolIndex(tools)
	entries := make([]agginventory.AgentPrivilegeMapEntry, 0, len(agents))

	for _, agent := range agents {
		instanceID := strings.TrimSpace(agent.AgentInstanceID)
		if instanceID == "" {
			continue
		}
		tool := lookupToolForAgent(agent, toolIndex)
		signals := signalsByInstance[instanceID]
		permissions := cloneStringSlice(signals.Permissions)
		if len(permissions) == 0 {
			permissions = cloneStringSlice(tool.Permissions)
		}
		repos := cloneStringSlice(signals.Repos)
		if len(repos) == 0 {
			repos = cloneStringSlice(tool.Repos)
		}
		if len(repos) == 0 && strings.TrimSpace(agent.Repo) != "" {
			repos = []string{strings.TrimSpace(agent.Repo)}
		}

		framework := fallbackFramework(agent.Framework, tool.ToolType)
		toolID := tool.ToolID
		if strings.TrimSpace(toolID) == "" {
			toolID = identity.ToolID(framework, agent.Location)
		}
		org := strings.TrimSpace(agent.Org)
		if org == "" {
			org = fallbackOrg(tool.Org)
		}
		endpointClass := firstNonEmptyString(tool.EndpointClass, "workspace")
		dataClass := firstNonEmptyString(tool.DataClass, inferAgentDataClass(agent, permissions))
		autonomyLevel := firstNonEmptyString(tool.AutonomyLevel, "interactive")
		riskScore := tool.RiskScore
		approvalClassification := strings.TrimSpace(tool.ApprovalClass)
		if approvalClassification == "" {
			approvalClassification = "unapproved"
		}

		writeCapable := hasAnyPermission(permissions, writeSet)
		credentialAccess := hasCredentialAccessForSurface(dataClass, permissions, agent.BoundAuthSurfaces)
		execCapable := hasExecPermission(permissions)
		matchedTargets := []string{}
		productionWrite := false
		if productionConfigured && productionRules != nil && writeCapable {
			matchedTargets = matchedProductionTargets(repos, signals, *productionRules)
			productionWrite = len(matchedTargets) > 0
		}

		deploymentStatus := strings.TrimSpace(agent.DeploymentStatus)
		if deploymentStatus == "" {
			deploymentStatus = "unknown"
		}

		entries = append(entries, agginventory.AgentPrivilegeMapEntry{
			AgentID:                  strings.TrimSpace(agent.AgentID),
			AgentInstanceID:          instanceID,
			ToolID:                   toolID,
			ToolType:                 firstNonEmptyString(tool.ToolType, framework),
			Framework:                framework,
			Symbol:                   strings.TrimSpace(agent.Symbol),
			Org:                      org,
			Repos:                    repos,
			Permissions:              permissions,
			Location:                 strings.TrimSpace(agent.Location),
			LocationRange:            cloneLocationRange(agent.LocationRange),
			EndpointClass:            endpointClass,
			DataClass:                dataClass,
			AutonomyLevel:            autonomyLevel,
			RiskScore:                riskScore,
			ApprovalClassification:   approvalClassification,
			BoundTools:               cloneStringSlice(agent.BoundTools),
			BoundDataSources:         cloneStringSlice(agent.BoundDataSources),
			BoundAuthSurfaces:        cloneStringSlice(agent.BoundAuthSurfaces),
			BindingEvidenceKeys:      cloneStringSlice(agent.BindingEvidenceKeys),
			MissingBindings:          cloneStringSlice(agent.MissingBindings),
			DeploymentStatus:         deploymentStatus,
			DeploymentArtifacts:      cloneStringSlice(agent.DeploymentArtifacts),
			DeploymentEvidenceKeys:   cloneStringSlice(agent.DeploymentEvidenceKeys),
			WriteCapable:             writeCapable,
			CredentialAccess:         credentialAccess,
			ExecCapable:              execCapable,
			ProductionWrite:          productionWrite,
			MatchedProductionTargets: append([]string(nil), matchedTargets...),
		})
	}

	return entries
}

func buildSignalsByInstance(findings []model.Finding) map[string]findingSignals {
	out := map[string]findingSignals{}
	for _, finding := range findings {
		instanceID := agentInstanceIDForFinding(finding)
		if instanceID == "" {
			continue
		}
		entry := out[instanceID]
		if entry.EvidenceKV == nil {
			entry.EvidenceKV = map[string][]string{}
		}
		if repo := strings.TrimSpace(finding.Repo); repo != "" {
			entry.Repos = append(entry.Repos, repo)
			entry.Values = append(entry.Values, normalizeToken(repo))
		}
		if location := strings.TrimSpace(finding.Location); location != "" {
			entry.Locations = append(entry.Locations, location)
			entry.Values = append(entry.Values, normalizeToken(location))
			entry.Values = append(entry.Values, extractHost(location)...)
		}
		entry.Permissions = append(entry.Permissions, finding.Permissions...)
		for _, permission := range finding.Permissions {
			if normalized := normalizeToken(permission); normalized != "" {
				entry.Values = append(entry.Values, normalized)
			}
		}
		for _, evidence := range finding.Evidence {
			key := normalizeToken(evidence.Key)
			value := strings.TrimSpace(evidence.Value)
			normalizedValue := normalizeToken(value)
			if key != "" {
				entry.Values = append(entry.Values, key)
			}
			if normalizedValue != "" {
				entry.Values = append(entry.Values, normalizedValue)
				entry.Values = append(entry.Values, extractHost(value)...)
			}
			if key != "" && normalizedValue != "" {
				entry.EvidenceKV[key] = append(entry.EvidenceKV[key], normalizedValue)
			}
		}
		entry.Repos = dedupeSortedPreserveCase(entry.Repos)
		entry.Locations = dedupeSortedPreserveCase(entry.Locations)
		entry.Permissions = dedupeSortedPreserveCase(entry.Permissions)
		entry.Values = dedupeSorted(entry.Values)
		for key, values := range entry.EvidenceKV {
			entry.EvidenceKV[key] = dedupeSorted(values)
		}
		out[instanceID] = entry
	}
	return out
}

type toolIndex struct {
	byRepoLocation map[string]agginventory.Tool
	byLocation     map[string]agginventory.Tool
}

func buildToolIndex(tools []agginventory.Tool) toolIndex {
	index := toolIndex{
		byRepoLocation: map[string]agginventory.Tool{},
		byLocation:     map[string]agginventory.Tool{},
	}
	for _, tool := range tools {
		org := fallbackOrg(tool.Org)
		framework := strings.TrimSpace(tool.ToolType)
		for _, location := range tool.Locations {
			repo := strings.TrimSpace(location.Repo)
			path := strings.TrimSpace(location.Location)
			if path == "" {
				continue
			}
			index.byLocation[org+"::"+framework+"::"+path] = tool
			if repo != "" {
				index.byRepoLocation[org+"::"+framework+"::"+repo+"::"+path] = tool
			}
		}
	}
	return index
}

func lookupToolForAgent(agent agginventory.Agent, index toolIndex) agginventory.Tool {
	org := fallbackOrg(agent.Org)
	framework := strings.TrimSpace(agent.Framework)
	location := strings.TrimSpace(agent.Location)
	repo := strings.TrimSpace(agent.Repo)
	if repo != "" {
		if item, ok := index.byRepoLocation[org+"::"+framework+"::"+repo+"::"+location]; ok {
			return item
		}
	}
	if item, ok := index.byLocation[org+"::"+framework+"::"+location]; ok {
		return item
	}
	return agginventory.Tool{}
}

func agentInstanceIDForFinding(finding model.Finding) string {
	symbol := ""
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "symbol" || key == "name" || key == "agent_name" {
			symbol = strings.TrimSpace(evidence.Value)
			break
		}
	}
	startLine := 0
	endLine := 0
	if finding.LocationRange != nil {
		startLine = finding.LocationRange.StartLine
		endLine = finding.LocationRange.EndLine
	}
	return identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
}

func inferAgentDataClass(agent agginventory.Agent, permissions []string) string {
	for _, item := range agent.BoundDataSources {
		lower := normalizeToken(item)
		switch {
		case strings.Contains(lower, "db"), strings.Contains(lower, "warehouse"), strings.Contains(lower, "table"), strings.Contains(lower, "dataset"), strings.Contains(lower, "postgres"):
			return "database"
		case strings.Contains(lower, "customer"), strings.Contains(lower, "profile"), strings.Contains(lower, "user"):
			return "pii"
		}
	}
	for _, item := range permissions {
		lower := normalizeToken(item)
		switch {
		case strings.Contains(lower, "secret"), strings.Contains(lower, "token"), strings.Contains(lower, "credential"):
			return "credentials"
		case strings.Contains(lower, "db.write"), strings.Contains(lower, "db.read"):
			return "database"
		}
	}
	return "code"
}

func agentLookupKeys(agent agginventory.Agent) []string {
	keys := map[string]struct{}{}
	if agentID := strings.TrimSpace(agent.AgentID); agentID != "" {
		keys[agentID] = struct{}{}
	}
	framework := strings.TrimSpace(agent.Framework)
	location := strings.TrimSpace(agent.Location)
	if framework != "" && location != "" {
		toolScoped := identity.AgentID(identity.ToolID(framework, location), fallbackOrg(agent.Org))
		keys[toolScoped] = struct{}{}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func mergeAgentContext(current, incoming agginventory.Agent, key string) agginventory.Agent {
	merged := current
	if strings.TrimSpace(merged.AgentID) == "" {
		merged.AgentID = strings.TrimSpace(key)
	}
	if strings.TrimSpace(merged.AgentInstanceID) == "" {
		merged.AgentInstanceID = strings.TrimSpace(incoming.AgentInstanceID)
	}
	if strings.TrimSpace(merged.Framework) == "" {
		merged.Framework = strings.TrimSpace(incoming.Framework)
	}
	merged.BoundTools = dedupeSorted(append(append([]string(nil), merged.BoundTools...), incoming.BoundTools...))
	merged.BoundDataSources = dedupeSorted(append(append([]string(nil), merged.BoundDataSources...), incoming.BoundDataSources...))
	merged.BoundAuthSurfaces = dedupeSorted(append(append([]string(nil), merged.BoundAuthSurfaces...), incoming.BoundAuthSurfaces...))
	merged.BindingEvidenceKeys = dedupeSorted(append(append([]string(nil), merged.BindingEvidenceKeys...), incoming.BindingEvidenceKeys...))
	merged.MissingBindings = dedupeSorted(append(append([]string(nil), merged.MissingBindings...), incoming.MissingBindings...))
	merged.DeploymentStatus = mergeDeploymentStatus(merged.DeploymentStatus, incoming.DeploymentStatus)
	merged.DeploymentArtifacts = dedupeSortedPreserveCase(append(append([]string(nil), merged.DeploymentArtifacts...), incoming.DeploymentArtifacts...))
	merged.DeploymentEvidenceKeys = dedupeSortedPreserveCase(append(append([]string(nil), merged.DeploymentEvidenceKeys...), incoming.DeploymentEvidenceKeys...))
	return merged
}

func mergeDeploymentStatus(current, incoming string) string {
	currentNormalized := normalizeToken(current)
	incomingNormalized := normalizeToken(incoming)
	switch {
	case currentNormalized == "deployed" || incomingNormalized == "deployed":
		return "deployed"
	case currentNormalized == "" || currentNormalized == "unknown":
		if incomingNormalized != "" {
			return incomingNormalized
		}
	case incomingNormalized == "" || incomingNormalized == "unknown":
		if currentNormalized != "" {
			return currentNormalized
		}
	}
	if currentNormalized == "" {
		return incomingNormalized
	}
	if incomingNormalized == "" {
		return currentNormalized
	}
	if currentNormalized <= incomingNormalized {
		return currentNormalized
	}
	return incomingNormalized
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
		entry.Permissions = append(entry.Permissions, finding.Permissions...)
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
		entry.Permissions = dedupeSorted(entry.Permissions)
		entry.Values = dedupeSorted(entry.Values)
		for key, values := range entry.EvidenceKV {
			entry.EvidenceKV[key] = dedupeSorted(values)
		}
		out[agentID] = entry
	}
	return out
}

func matchedProductionTargets(
	repos []string,
	signals findingSignals,
	rules productiontargets.Config,
) []string {
	matches := map[string]struct{}{}
	addMatchSet(matches, "repo", rules.Targets.Repos, append(append([]string(nil), repos...), signals.Repos...))
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
	return hasCredentialAccessForSurface(tool.DataClass, tool.Permissions, nil)
}

func hasCredentialAccessForSurface(dataClass string, permissions []string, authSurfaces []string) bool {
	if normalizeToken(dataClass) == "credentials" {
		return true
	}
	for _, permission := range permissions {
		normalized := normalizeToken(permission)
		if strings.Contains(normalized, "secret") || strings.Contains(normalized, "token") || strings.Contains(normalized, "credential") {
			return true
		}
	}
	for _, authSurface := range authSurfaces {
		normalized := normalizeToken(authSurface)
		if strings.Contains(normalized, "secret") || strings.Contains(normalized, "token") || strings.Contains(normalized, "credential") || strings.HasSuffix(normalized, "_key") || strings.Contains(normalized, "api_key") {
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

func dedupeSortedPreserveCase(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
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

func cloneLocationRange(value *model.LocationRange) *model.LocationRange {
	if value == nil {
		return nil
	}
	return &model.LocationRange{StartLine: value.StartLine, EndLine: value.EndLine}
}

func locationRangeBounds(value *model.LocationRange) (int, int) {
	if value == nil {
		return 0, 0
	}
	return value.StartLine, value.EndLine
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fallbackFramework(framework, toolType string) string {
	trimmed := strings.TrimSpace(framework)
	if trimmed != "" {
		return trimmed
	}
	return strings.TrimSpace(toolType)
}
