package agentframework

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

type sourcePlan struct {
	DetectorID    string
	Framework     string
	Profile       sourceProfile
	pythonPattern *regexp.Regexp
	jsPattern     *regexp.Regexp
}

type sourceProfile struct {
	importMarkers        []string
	requiredImportedName []string
	callNames            []string
	nameKeys             []string
	toolKeys             []string
	dataKeys             []string
	authKeys             []string
	deploymentKeys       []string
}

type importSummary struct {
	Modules []string
	Names   []string
}

var (
	pythonImportPattern     = regexp.MustCompile(`^\s*import\s+(.+)$`)
	pythonFromImportPattern = regexp.MustCompile(`^\s*from\s+([A-Za-z0-9_\.]+)\s+import\s+(.+)$`)
	jsFromImportPattern     = regexp.MustCompile(`^\s*import\s+(.+?)\s+from\s+['"]([^'"]+)['"]`)
	jsBareImportPattern     = regexp.MustCompile(`^\s*import\s+['"]([^'"]+)['"]`)
	jsRequirePattern        = regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`)
	processEnvPattern       = regexp.MustCompile(`process\.env\.([A-Z][A-Z0-9_]+)`)
	osGetEnvPattern         = regexp.MustCompile(`(?:os\.getenv|env\.get)\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)`)
	osEnvironPattern        = regexp.MustCompile(`os\.environ\[\s*["']([A-Z][A-Z0-9_]+)["']\s*\]`)
	genericEnvPattern       = regexp.MustCompile(`\b(?:getenv|env)\(\s*["']([A-Z][A-Z0-9_]+)["']\s*\)`)
)

func buildSourcePlans(configs []DetectorConfig) []sourcePlan {
	unique := map[string]sourcePlan{}
	for _, cfg := range configs {
		profile, ok := sourceProfileForFramework(cfg.Framework)
		if !ok {
			continue
		}
		key := strings.TrimSpace(cfg.DetectorID) + "::" + strings.TrimSpace(cfg.Framework)
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = sourcePlan{
			DetectorID:    strings.TrimSpace(cfg.DetectorID),
			Framework:     strings.TrimSpace(cfg.Framework),
			Profile:       profile,
			pythonPattern: buildSourceAssignmentPattern("python", profile.callNames),
			jsPattern:     buildSourceAssignmentPattern("javascript", profile.callNames),
		}
	}

	if len(unique) == 0 {
		return nil
	}
	out := make([]sourcePlan, 0, len(unique))
	for _, plan := range unique {
		out = append(out, plan)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DetectorID != out[j].DetectorID {
			return out[i].DetectorID < out[j].DetectorID
		}
		return out[i].Framework < out[j].Framework
	})
	return out
}

func detectFromSource(scope detect.Scope, plans []sourcePlan) ([]model.Finding, error) {
	if len(plans) == 0 {
		return nil, nil
	}

	files, err := detect.WalkFiles(scope.Root)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, rel := range files {
		language := sourceLanguage(rel)
		if language == "" || shouldSkipSourceFile(rel) {
			continue
		}

		path := filepath.Join(scope.Root, filepath.FromSlash(rel))
		// #nosec G304 -- detector reads source files from the selected repository root.
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read source file %s: %w", rel, readErr)
		}
		content := string(payload)
		imports := parseImportSummary(language, content)
		if len(imports.Modules) == 0 && len(imports.Names) == 0 {
			continue
		}

		for _, plan := range plans {
			if !matchesSourceImports(imports, plan.Profile) {
				continue
			}
			findings = append(findings, detectSourceAgents(scope, rel, content, language, plan)...)
		}
	}

	return findings, nil
}

func sourceProfileForFramework(framework string) (sourceProfile, bool) {
	switch strings.ToLower(strings.TrimSpace(framework)) {
	case "langchain":
		return sourceProfile{
			importMarkers:  []string{"langchain", "@langchain"},
			callNames:      []string{"initializeAgentExecutorWithOptions", "create_openai_functions_agent", "create_openai_tools_agent", "create_react_agent", "createToolCallingAgent", "createReactAgent", "initialize_agent", "AgentExecutor", "StructuredChatAgent"},
			nameKeys:       []string{"name", "agent_name", "agentName", "id"},
			toolKeys:       []string{"tools"},
			dataKeys:       []string{"data_sources", "dataSources", "retriever", "retrievers", "knowledge_base", "knowledgeBase", "vector_store", "vectorStore", "memory", "datasets"},
			authKeys:       []string{"auth_surfaces", "authSurfaces", "auth", "credentials", "credential", "api_key", "apiKey", "token", "headers"},
			deploymentKeys: []string{"deployment_artifacts", "deploymentArtifacts", "entrypoint", "entryPoint", "workflow", "dockerfile", "manifest"},
		}, true
	case "crewai":
		return sourceProfile{
			importMarkers:        []string{"crewai"},
			requiredImportedName: []string{"Agent"},
			callNames:            []string{"Agent"},
			nameKeys:             []string{"name", "agent_name", "agentName", "role"},
			toolKeys:             []string{"tools"},
			dataKeys:             []string{"data_sources", "dataSources", "knowledge_sources", "knowledgeSources", "memory"},
			authKeys:             []string{"auth_surfaces", "authSurfaces", "auth", "credentials", "credential", "api_key", "apiKey", "token", "headers"},
			deploymentKeys:       []string{"deployment_artifacts", "deploymentArtifacts", "entrypoint", "entryPoint", "workflow", "dockerfile", "manifest"},
		}, true
	case "openai_agents":
		return sourceProfile{
			importMarkers:        []string{"@openai/agents", "agents"},
			requiredImportedName: []string{"Agent"},
			callNames:            []string{"Agent"},
			nameKeys:             []string{"name", "agent_name", "agentName", "id"},
			toolKeys:             []string{"tools", "handoffs"},
			dataKeys:             []string{"data_sources", "dataSources", "context", "knowledge", "memory"},
			authKeys:             []string{"auth_surfaces", "authSurfaces", "auth", "credentials", "credential", "api_key", "apiKey", "token", "headers"},
			deploymentKeys:       []string{"deployment_artifacts", "deploymentArtifacts", "entrypoint", "entryPoint", "workflow", "dockerfile", "manifest"},
		}, true
	case "autogen":
		return sourceProfile{
			importMarkers:        []string{"autogen"},
			requiredImportedName: []string{"AssistantAgent", "UserProxyAgent", "ConversableAgent", "GroupChatManager"},
			callNames:            []string{"GroupChatManager", "AssistantAgent", "UserProxyAgent", "ConversableAgent"},
			nameKeys:             []string{"name", "agent_name", "agentName"},
			toolKeys:             []string{"tools", "functions"},
			dataKeys:             []string{"data_sources", "dataSources", "memory", "knowledge_base", "knowledgeBase"},
			authKeys:             []string{"auth_surfaces", "authSurfaces", "auth", "credentials", "credential", "api_key", "apiKey", "token", "headers"},
			deploymentKeys:       []string{"deployment_artifacts", "deploymentArtifacts", "entrypoint", "entryPoint", "workflow", "dockerfile", "manifest"},
		}, true
	case "llamaindex":
		return sourceProfile{
			importMarkers:  []string{"llamaindex", "llama_index", "@llamaindex"},
			callNames:      []string{"FunctionAgent", "OpenAIAgent", "AgentRunner", "ReActAgent"},
			nameKeys:       []string{"name", "agent_name", "agentName", "id"},
			toolKeys:       []string{"tools"},
			dataKeys:       []string{"data_sources", "dataSources", "knowledge_base", "knowledgeBase", "memory", "retriever", "retrievers"},
			authKeys:       []string{"auth_surfaces", "authSurfaces", "auth", "credentials", "credential", "api_key", "apiKey", "token", "headers"},
			deploymentKeys: []string{"deployment_artifacts", "deploymentArtifacts", "entrypoint", "entryPoint", "workflow", "dockerfile", "manifest"},
		}, true
	case "mcp_client":
		return sourceProfile{
			importMarkers:        []string{"@modelcontextprotocol/sdk", "modelcontextprotocol", "mcp"},
			requiredImportedName: []string{"Client", "ClientSession", "MCPClient"},
			callNames:            []string{"ClientSession", "MCPClient", "Client"},
			nameKeys:             []string{"name", "client_name", "clientName", "id"},
			toolKeys:             []string{"servers", "mcp_servers", "mcpServers", "tools"},
			dataKeys:             []string{"resources", "data_sources", "dataSources"},
			authKeys:             []string{"auth_surfaces", "authSurfaces", "auth", "credentials", "credential", "api_key", "apiKey", "token", "headers"},
			deploymentKeys:       []string{"deployment_artifacts", "deploymentArtifacts", "entrypoint", "entryPoint", "transport", "workflow"},
		}, true
	default:
		return sourceProfile{}, false
	}
}

func buildSourceAssignmentPattern(language string, callNames []string) *regexp.Regexp {
	escaped := make([]string, 0, len(callNames))
	sorted := append([]string(nil), callNames...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, name := range sorted {
		escaped = append(escaped, regexp.QuoteMeta(strings.TrimSpace(name)))
	}
	if len(escaped) == 0 {
		return nil
	}
	alt := strings.Join(escaped, "|")
	switch language {
	case "python":
		return regexp.MustCompile(`^\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:await\s+)?(?:[A-Za-z_][A-Za-z0-9_]*\.)?(` + alt + `)\s*\(`)
	default:
		return regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:await\s+)?(?:new\s+)?(?:[A-Za-z_$][A-Za-z0-9_$]*\.)?(` + alt + `)\s*\(`)
	}
}

func sourceLanguage(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".py":
		return "python"
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts":
		return "javascript"
	default:
		return ""
	}
}

func shouldSkipSourceFile(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	if lower == "" {
		return true
	}
	for _, prefix := range []string{
		".git/",
		".wrkr/",
		".tmp/",
		"node_modules/",
		"vendor/",
		"dist/",
		"build/",
		".venv/",
		"venv/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func parseImportSummary(language, content string) importSummary {
	moduleSet := map[string]struct{}{}
	nameSet := map[string]struct{}{}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		switch language {
		case "python":
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if match := pythonImportPattern.FindStringSubmatch(trimmed); len(match) == 2 {
				for _, item := range strings.Split(match[1], ",") {
					module := normalizeImportToken(item)
					if module != "" {
						moduleSet[module] = struct{}{}
					}
				}
				continue
			}
			if match := pythonFromImportPattern.FindStringSubmatch(trimmed); len(match) == 3 {
				module := normalizeImportToken(match[1])
				if module != "" {
					moduleSet[module] = struct{}{}
				}
				for _, item := range splitImportNames(match[2]) {
					nameSet[item] = struct{}{}
				}
			}
		default:
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if match := jsFromImportPattern.FindStringSubmatch(trimmed); len(match) == 3 {
				moduleSet[strings.ToLower(strings.TrimSpace(match[2]))] = struct{}{}
				for _, item := range splitJSImportNames(match[1]) {
					nameSet[item] = struct{}{}
				}
				continue
			}
			if match := jsBareImportPattern.FindStringSubmatch(trimmed); len(match) == 2 {
				moduleSet[strings.ToLower(strings.TrimSpace(match[1]))] = struct{}{}
			}
			for _, match := range jsRequirePattern.FindAllStringSubmatch(trimmed, -1) {
				if len(match) == 2 {
					moduleSet[strings.ToLower(strings.TrimSpace(match[1]))] = struct{}{}
				}
			}
		}
	}
	return importSummary{
		Modules: sortedKeys(moduleSet),
		Names:   sortedKeys(nameSet),
	}
}

func normalizeImportToken(token string) string {
	trimmed := strings.TrimSpace(token)
	trimmed = strings.TrimPrefix(trimmed, "import ")
	trimmed = strings.TrimPrefix(trimmed, "from ")
	trimmed = strings.Split(trimmed, " as ")[0]
	return strings.ToLower(strings.TrimSpace(trimmed))
}

func splitImportNames(raw string) []string {
	out := make([]string, 0)
	for _, item := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		trimmed = strings.Trim(trimmed, "()")
		trimmed = strings.Split(trimmed, " as ")[0]
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func splitJSImportNames(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	out := make([]string, 0)
	if open := strings.Index(trimmed, "{"); open >= 0 {
		if close := strings.Index(trimmed[open:], "}"); close >= 0 {
			for _, item := range strings.Split(trimmed[open+1:open+close], ",") {
				part := strings.TrimSpace(item)
				if part == "" {
					continue
				}
				part = strings.Split(part, " as ")[0]
				part = strings.TrimSpace(part)
				if part != "" {
					out = append(out, part)
				}
			}
		}
	}
	defaultPart := strings.TrimSpace(strings.Split(trimmed, "{")[0])
	defaultPart = strings.TrimSuffix(defaultPart, ",")
	defaultPart = strings.TrimSpace(defaultPart)
	if defaultPart != "" {
		out = append(out, defaultPart)
	}
	sort.Strings(out)
	return out
}

func matchesSourceImports(imports importSummary, profile sourceProfile) bool {
	moduleMatched := false
	for _, module := range imports.Modules {
		for _, marker := range profile.importMarkers {
			if strings.Contains(module, strings.ToLower(strings.TrimSpace(marker))) {
				moduleMatched = true
				break
			}
		}
		if moduleMatched {
			break
		}
	}
	if !moduleMatched {
		return false
	}
	if len(profile.requiredImportedName) == 0 {
		return true
	}
	for _, name := range imports.Names {
		for _, required := range profile.requiredImportedName {
			if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(required)) {
				return true
			}
		}
	}
	return false
}

func detectSourceAgents(scope detect.Scope, rel, content, language string, plan sourcePlan) []model.Finding {
	lines := strings.Split(content, "\n")
	findings := make([]model.Finding, 0)
	for idx, line := range lines {
		var match []int
		switch language {
		case "python":
			if plan.pythonPattern == nil {
				continue
			}
			match = plan.pythonPattern.FindStringSubmatchIndex(line)
		default:
			if plan.jsPattern == nil {
				continue
			}
			match = plan.jsPattern.FindStringSubmatchIndex(line)
		}
		if len(match) != 6 {
			continue
		}

		variableName := strings.TrimSpace(line[match[2]:match[3]])
		callName := strings.TrimSpace(line[match[4]:match[5]])
		block, endLine := captureInvocation(lines, idx, match[4])
		if strings.TrimSpace(block) == "" {
			continue
		}

		agent := sourceAgentSpec(rel, content, block, variableName, callName, idx+1, endLine, plan.Profile)
		if strings.TrimSpace(agent.Name) == "" || strings.TrimSpace(agent.File) == "" {
			continue
		}
		findings = append(findings, sourceFinding(scope, plan, agent, language, callName))
	}
	return findings
}

func captureInvocation(lines []string, startLine, startCol int) (string, int) {
	var builder strings.Builder
	paren := 0
	bracket := 0
	brace := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false

	for idx := startLine; idx < len(lines); idx++ {
		segment := lines[idx]
		if idx == startLine {
			segment = segment[startCol:]
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(segment)

		for _, ch := range segment {
			switch {
			case escaped:
				escaped = false
				continue
			case ch == '\\':
				escaped = true
				continue
			case ch == '\'' && !inDouble && !inBacktick:
				inSingle = !inSingle
				continue
			case ch == '"' && !inSingle && !inBacktick:
				inDouble = !inDouble
				continue
			case ch == '`' && !inSingle && !inDouble:
				inBacktick = !inBacktick
				continue
			case inSingle || inDouble || inBacktick:
				continue
			}

			switch ch {
			case '(':
				paren++
			case ')':
				if paren > 0 {
					paren--
				}
			case '[':
				bracket++
			case ']':
				if bracket > 0 {
					bracket--
				}
			case '{':
				brace++
			case '}':
				if brace > 0 {
					brace--
				}
			}
		}

		if paren == 0 && bracket == 0 && brace == 0 && strings.Contains(segment, ")") {
			return builder.String(), idx + 1
		}
	}

	return builder.String(), len(lines)
}

func sourceAgentSpec(rel, content, block, variableName, callName string, startLine, endLine int, profile sourceProfile) AgentSpec {
	explicitName := firstNamedString(block, profile.nameKeys)
	symbol := explicitName
	if strings.TrimSpace(symbol) == "" {
		symbol = strings.TrimSpace(variableName)
	}

	tools := extractNamedValues(block, profile.toolKeys)
	if len(tools) == 0 && expectsPositionalTools(callName) {
		tools = firstPositionalValues(block)
	}

	dataSources := extractNamedValues(block, profile.dataKeys)
	authSurfaces := uniqueSorted(append(extractNamedValues(block, profile.authKeys), extractEnvVars(block)...))
	deployment := extractNamedValues(block, profile.deploymentKeys)
	deployment = append(deployment, deploymentHints(rel, content, block)...)
	dataClass := inferSourceDataClass(dataSources, authSurfaces)
	approvalStatus := firstNonEmpty(
		firstNamedString(block, []string{"approval_status", "approvalStatus"}),
		"missing",
	)

	return AgentSpec{
		Name:             symbol,
		File:             rel,
		StartLine:        startLine,
		EndLine:          endLine,
		Tools:            tools,
		DataSources:      dataSources,
		AuthSurfaces:     authSurfaces,
		Deployment:       uniqueSorted(deployment),
		DataClass:        dataClass,
		ApprovalStatus:   approvalStatus,
		DynamicDiscovery: hasAnyKeyword(block, "handoff", "handoffs", "delegate", "delegation", "dynamic_discovery", "discover_tools", "tool_registry", "register_tool"),
		KillSwitch:       extractNamedBool(block, []string{"kill_switch", "killSwitch"}),
		AutoDeploy:       extractNamedBool(block, []string{"auto_deploy", "autoDeploy"}),
		HumanGate:        extractNamedBool(block, []string{"human_gate", "humanGate", "approval_required", "approvalRequired"}),
		DeploymentGate:   firstNamedString(block, []string{"deployment_gate", "deploymentGate"}),
	}
}

func sourceFinding(scope detect.Scope, plan sourcePlan, agent AgentSpec, language, callName string) model.Finding {
	permissions := derivePermissions(agent)
	tools := uniqueSorted(agent.Tools)
	dataSources := uniqueSorted(agent.DataSources)
	authSurfaces := uniqueSorted(agent.AuthSurfaces)
	deployment := uniqueSorted(agent.Deployment)
	deploymentStatus := sourceDeploymentStatus(deployment)

	evidence := []model.Evidence{
		{Key: "framework", Value: strings.TrimSpace(plan.Framework)},
		{Key: "symbol", Value: strings.TrimSpace(agent.Name)},
		{Key: "source_path", Value: strings.TrimSpace(agent.File)},
		{Key: "source_language", Value: strings.TrimSpace(language)},
		{Key: "source_call", Value: strings.TrimSpace(callName)},
		{Key: "bound_tools", Value: strings.Join(tools, ",")},
		{Key: "data_sources", Value: strings.Join(dataSources, ",")},
		{Key: "auth_surfaces", Value: strings.Join(authSurfaces, ",")},
		{Key: "deployment_artifacts", Value: strings.Join(deployment, ",")},
		{Key: "deployment_status", Value: deploymentStatus},
		{Key: "data_class", Value: fallback(strings.TrimSpace(agent.DataClass), "unknown")},
		{Key: "approval_status", Value: fallback(strings.TrimSpace(agent.ApprovalStatus), "missing")},
		{Key: "dynamic_discovery", Value: fmt.Sprintf("%t", agent.DynamicDiscovery)},
		{Key: "kill_switch", Value: fmt.Sprintf("%t", agent.KillSwitch)},
		{Key: "auto_deploy", Value: fmt.Sprintf("%t", agent.AutoDeploy)},
		{Key: "human_gate", Value: fmt.Sprintf("%t", agent.HumanGate)},
		{Key: "deployment_gate", Value: deriveDeploymentGate(agent)},
	}

	severity := model.SeverityLow
	if agent.AutoDeploy {
		severity = model.SeverityMedium
	}
	if agent.AutoDeploy && !agent.HumanGate {
		severity = model.SeverityHigh
	}

	var locationRange *model.LocationRange
	if agent.StartLine > 0 || agent.EndLine > 0 {
		locationRange = &model.LocationRange{StartLine: agent.StartLine, EndLine: agent.EndLine}
	}

	return model.Finding{
		FindingType:   "agent_framework",
		Severity:      severity,
		ToolType:      strings.TrimSpace(plan.Framework),
		Location:      strings.TrimSpace(agent.File),
		LocationRange: locationRange,
		Repo:          strings.TrimSpace(scope.Repo),
		Org:           fallbackOrg(scope.Org),
		Detector:      strings.TrimSpace(plan.DetectorID),
		Permissions:   permissions,
		Evidence:      evidence,
		Remediation:   "Declare deterministic agent bindings, deployment context, and governance controls.",
	}
}

func sourceDeploymentStatus(deployment []string) string {
	for _, item := range deployment {
		lower := strings.ToLower(strings.TrimSpace(item))
		switch {
		case strings.Contains(lower, ".github/workflows"),
			strings.Contains(lower, "jenkinsfile"),
			strings.Contains(lower, "dockerfile"),
			strings.Contains(lower, "helm"),
			strings.Contains(lower, "k8s"),
			strings.Contains(lower, "deployment"):
			return "deployed"
		}
	}
	return "unknown"
}

func extractNamedValues(block string, keys []string) []string {
	values := make([]string, 0)
	for _, key := range keys {
		for _, expr := range namedExpressions(block, key) {
			values = append(values, parseExpressionValues(expr)...)
		}
	}
	return uniqueSorted(values)
}

func firstNamedString(block string, keys []string) string {
	for _, key := range keys {
		for _, expr := range namedExpressions(block, key) {
			for _, value := range parseExpressionValues(expr) {
				if strings.TrimSpace(value) != "" {
					return strings.TrimSpace(value)
				}
			}
		}
	}
	return ""
}

func extractNamedBool(block string, keys []string) bool {
	for _, key := range keys {
		for _, expr := range namedExpressions(block, key) {
			normalized := strings.ToLower(strings.TrimSpace(expr))
			switch normalized {
			case "true", "yes":
				return true
			case "false", "no":
				return false
			}
		}
	}
	return false
}

func namedExpressions(block, key string) []string {
	pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(strings.TrimSpace(key)) + `\b\s*(?:=|:)`)
	matches := pattern.FindAllStringIndex(block, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		expr, _ := parseExpression(block[match[1]:])
		if strings.TrimSpace(expr) != "" {
			out = append(out, expr)
		}
	}
	return out
}

func parseExpression(raw string) (string, int) {
	trimmed := strings.TrimLeft(raw, " \t")
	offset := len(raw) - len(trimmed)
	if trimmed == "" {
		return "", offset
	}

	switch trimmed[0] {
	case '[', '{', '(':
		return captureBalancedFragment(trimmed, 0)
	case '\'', '"', '`':
		return captureQuotedFragment(trimmed)
	}

	end := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false
	for idx, ch := range trimmed {
		switch {
		case escaped:
			escaped = false
			continue
		case ch == '\\':
			escaped = true
			continue
		case ch == '\'' && !inDouble && !inBacktick:
			inSingle = !inSingle
		case ch == '"' && !inSingle && !inBacktick:
			inDouble = !inDouble
		case ch == '`' && !inSingle && !inDouble:
			inBacktick = !inBacktick
		}
		if inSingle || inDouble || inBacktick {
			continue
		}
		switch ch {
		case ',', '\n', ')', '}', ']':
			return strings.TrimSpace(trimmed[:idx]), offset + idx
		}
		end = idx + 1
	}
	return strings.TrimSpace(trimmed[:end]), offset + end
}

func captureBalancedFragment(raw string, start int) (string, int) {
	open := raw[start]
	close := byte(']')
	switch open {
	case '{':
		close = '}'
	case '(':
		close = ')'
	}
	depth := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false
	for idx := start; idx < len(raw); idx++ {
		ch := raw[idx]
		switch {
		case escaped:
			escaped = false
			continue
		case ch == '\\':
			escaped = true
			continue
		case ch == '\'' && !inDouble && !inBacktick:
			inSingle = !inSingle
			continue
		case ch == '"' && !inSingle && !inBacktick:
			inDouble = !inDouble
			continue
		case ch == '`' && !inSingle && !inDouble:
			inBacktick = !inBacktick
			continue
		case inSingle || inDouble || inBacktick:
			continue
		}

		if ch == open {
			depth++
		}
		if ch == close {
			depth--
			if depth == 0 {
				return strings.TrimSpace(raw[start : idx+1]), idx + 1
			}
		}
	}
	return strings.TrimSpace(raw[start:]), len(raw)
}

func captureQuotedFragment(raw string) (string, int) {
	quote := raw[0]
	escaped := false
	for idx := 1; idx < len(raw); idx++ {
		switch {
		case escaped:
			escaped = false
		case raw[idx] == '\\':
			escaped = true
		case raw[idx] == quote:
			return strings.TrimSpace(raw[:idx+1]), idx + 1
		}
	}
	return strings.TrimSpace(raw), len(raw)
}

func parseExpressionValues(expr string) []string {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
		return normalizeExpressionItems(splitTopLevel(inner, ','))
	case '{':
		return normalizeObjectLiteral(trimmed)
	default:
		return normalizeExpressionItems([]string{trimmed})
	}
}

func splitTopLevel(raw string, delimiter rune) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := make([]string, 0)
	start := 0
	paren := 0
	bracket := 0
	brace := 0
	inSingle := false
	inDouble := false
	inBacktick := false
	escaped := false

	for idx, ch := range raw {
		switch {
		case escaped:
			escaped = false
			continue
		case ch == '\\':
			escaped = true
			continue
		case ch == '\'' && !inDouble && !inBacktick:
			inSingle = !inSingle
			continue
		case ch == '"' && !inSingle && !inBacktick:
			inDouble = !inDouble
			continue
		case ch == '`' && !inSingle && !inDouble:
			inBacktick = !inBacktick
			continue
		case inSingle || inDouble || inBacktick:
			continue
		}

		switch ch {
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case '[':
			bracket++
		case ']':
			if bracket > 0 {
				bracket--
			}
		case '{':
			brace++
		case '}':
			if brace > 0 {
				brace--
			}
		}

		if ch == delimiter && paren == 0 && bracket == 0 && brace == 0 {
			out = append(out, strings.TrimSpace(raw[start:idx]))
			start = idx + 1
		}
	}

	out = append(out, strings.TrimSpace(raw[start:]))
	return out
}

func normalizeExpressionItems(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		for _, normalized := range normalizeExpressionItem(item) {
			out = append(out, normalized)
		}
	}
	return uniqueSorted(out)
}

func normalizeExpressionItem(item string) []string {
	trimmed := strings.TrimSpace(strings.TrimSuffix(item, ","))
	if trimmed == "" {
		return nil
	}
	if value := quotedValue(trimmed); value != "" {
		return []string{value}
	}
	for _, match := range processEnvPattern.FindAllStringSubmatch(trimmed, -1) {
		if len(match) == 2 {
			return []string{strings.TrimSpace(match[1])}
		}
	}
	for _, match := range osGetEnvPattern.FindAllStringSubmatch(trimmed, -1) {
		if len(match) == 2 {
			return []string{strings.TrimSpace(match[1])}
		}
	}
	for _, match := range osEnvironPattern.FindAllStringSubmatch(trimmed, -1) {
		if len(match) == 2 {
			return []string{strings.TrimSpace(match[1])}
		}
	}
	if open := strings.Index(trimmed, "("); open >= 0 {
		inner, _ := parseExpression(trimmed[open+1:])
		values := parseExpressionValues(inner)
		if len(values) > 0 {
			return values
		}
		trimmed = strings.TrimSpace(trimmed[:open])
	}
	trimmed = strings.Trim(trimmed, "{}")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return nil
	}
	return []string{trimmed}
}

func normalizeObjectLiteral(expr string) []string {
	values := make([]string, 0)
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "{"), "}"))
	for _, item := range splitTopLevel(inner, ',') {
		if !strings.Contains(item, ":") {
			trimmed := strings.TrimSpace(item)
			if trimmed != "" {
				values = append(values, trimmed)
			}
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		values = append(values, normalizeExpressionItems([]string{parts[1]})...)
	}
	return uniqueSorted(values)
}

func quotedValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 2 {
		return ""
	}
	first := trimmed[0]
	last := trimmed[len(trimmed)-1]
	if (first == '\'' || first == '"' || first == '`') && last == first {
		return strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	}
	return ""
}

func firstPositionalValues(block string) []string {
	open := strings.Index(block, "(")
	close := strings.LastIndex(block, ")")
	if open < 0 || close <= open {
		return nil
	}
	args := splitTopLevel(block[open+1:close], ',')
	if len(args) == 0 {
		return nil
	}
	return normalizeExpressionItems([]string{args[0]})
}

func expectsPositionalTools(callName string) bool {
	switch strings.TrimSpace(callName) {
	case "initialize_agent", "initializeAgentExecutorWithOptions", "createReactAgent", "create_react_agent":
		return true
	default:
		return false
	}
}

func extractEnvVars(block string) []string {
	out := make([]string, 0)
	for _, pattern := range []*regexp.Regexp{processEnvPattern, osGetEnvPattern, osEnvironPattern, genericEnvPattern} {
		for _, match := range pattern.FindAllStringSubmatch(block, -1) {
			if len(match) == 2 {
				out = append(out, strings.TrimSpace(match[1]))
			}
		}
	}
	return uniqueSorted(out)
}

func deploymentHints(rel, content, block string) []string {
	hints := make([]string, 0)
	lower := strings.ToLower(content + "\n" + block)
	if hasAnyKeyword(lower,
		"if __name__ == \"__main__\"",
		"if __name__ == '__main__'",
		"uvicorn.run",
		"fastapi(",
		"app.listen(",
		"server.listen(",
		"crew.kickoff",
		"runner.run(",
		"serve(",
		"lambda_handler",
	) {
		hints = append(hints, rel)
	}
	return uniqueSorted(hints)
}

func inferSourceDataClass(dataSources, authSurfaces []string) string {
	for _, item := range dataSources {
		lower := strings.ToLower(strings.TrimSpace(item))
		switch {
		case strings.Contains(lower, "warehouse"), strings.Contains(lower, "db"), strings.Contains(lower, "postgres"), strings.Contains(lower, "table"), strings.Contains(lower, "dataset"):
			return "database"
		case strings.Contains(lower, "customer"), strings.Contains(lower, "user"), strings.Contains(lower, "profile"):
			return "pii"
		}
	}
	if len(authSurfaces) > 0 {
		return "credentials"
	}
	return "code"
}

func hasAnyKeyword(value string, keywords ...string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, keyword := range keywords {
		if strings.Contains(lower, strings.ToLower(strings.TrimSpace(keyword))) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
