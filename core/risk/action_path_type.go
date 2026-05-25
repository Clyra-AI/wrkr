package risk

import (
	"path/filepath"
	"strings"
)

const (
	ActionPathTypeAIAssistedWorkflow = "ai_assisted_workflow"
	ActionPathTypeAgentFramework     = "agent_framework"
	ActionPathTypeAutomationBot      = "automation_bot"
	ActionPathTypeCICDWorkflow       = "ci_cd_workflow"
	ActionPathTypeLegacyScript       = "legacy_script"
	ActionPathTypePlainSourceCode    = "plain_source_code"
	ActionPathTypeUnknownExecutablePath = "unknown_executable_path"
)

func ValidActionPathType(value string) bool {
	switch strings.TrimSpace(value) {
	case ActionPathTypeAIAssistedWorkflow,
		ActionPathTypeAgentFramework,
		ActionPathTypeAutomationBot,
		ActionPathTypeCICDWorkflow,
		ActionPathTypeLegacyScript,
		ActionPathTypePlainSourceCode,
		ActionPathTypeUnknownExecutablePath:
		return true
	default:
		return false
	}
}

func deriveActionPathType(path ActionPath) (string, []string, []string) {
	reasons := []string{}
	refs := []string{}
	addReason := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}
	addRef := func(ref string) {
		if strings.TrimSpace(ref) != "" {
			refs = append(refs, strings.TrimSpace(ref))
		}
	}
	for _, key := range path.SourceFindingKeys {
		addRef("finding:" + strings.TrimSpace(key))
	}

	location := strings.ToLower(strings.TrimSpace(path.Location))
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	switch {
	case strings.Contains(location, ".github/workflows") || strings.Contains(location, "jenkinsfile") || toolType == "ci_agent" || (toolType == "compiled_action" && (strings.Contains(location, ".github/workflows") || strings.Contains(location, "jenkinsfile"))):
		addReason("workflow_surface:true")
		return ActionPathTypeCICDWorkflow, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case isAgentFrameworkToolType(toolType):
		addReason("framework_tool_type:" + strings.TrimSpace(path.ToolType))
		return ActionPathTypeAgentFramework, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case actionPathHasBotIdentity(path):
		addReason("bot_identity:" + strings.TrimSpace(path.ExecutionIdentityType))
		return ActionPathTypeAutomationBot, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case pathIsPromptOrInstructionSurface(path) || pathIsDeveloperProductivity(path):
		addReason("ai_workflow_surface:true")
		return ActionPathTypeAIAssistedWorkflow, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case toolType == "openapi" || toolType == "route":
		addReason("static_source_surface:" + strings.TrimSpace(path.ToolType))
		return ActionPathTypePlainSourceCode, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case hasScriptExtension(location):
		addReason("script_entrypoint:true")
		return ActionPathTypeLegacyScript, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case actionPathDependencyOnly(path):
		addReason("dependency_only:true")
		return ActionPathTypeUnknownExecutablePath, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	case pathHasExecutableBinding(path):
		addReason("source_execution_linkage:true")
		return ActionPathTypePlainSourceCode, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	default:
		return ActionPathTypeUnknownExecutablePath, []string{"action_path_type:unknown"}, dedupeSortedStrings(refs)
	}
}

func chooseActionPathType(current, incoming string) string {
	current = normalizeActionPathType(current)
	incoming = normalizeActionPathType(incoming)
	switch {
	case current == "":
		return incoming
	case incoming == "":
		return current
	case current == incoming:
		return current
	default:
		if actionPathTypeRank(incoming) < actionPathTypeRank(current) {
			return incoming
		}
		return current
	}
}

func normalizeActionPathType(value string) string {
	value = strings.TrimSpace(value)
	if !ValidActionPathType(value) {
		return ""
	}
	return value
}

func actionPathTypeRank(value string) int {
	switch strings.TrimSpace(value) {
	case ActionPathTypeCICDWorkflow:
		return 0
	case ActionPathTypeAgentFramework:
		return 1
	case ActionPathTypeAutomationBot:
		return 2
	case ActionPathTypeAIAssistedWorkflow:
		return 3
	case ActionPathTypeLegacyScript:
		return 4
	case ActionPathTypePlainSourceCode:
		return 5
	case ActionPathTypeUnknownExecutablePath:
		return 6
	default:
		return 99
	}
}

func isAgentFrameworkToolType(toolType string) bool {
	switch strings.TrimSpace(toolType) {
	case "langchain", "langgraph", "crewai", "autogen", "llamaindex", "openai_agents", "semantic_kernel", "haystack", "custom_agent":
		return true
	default:
		return false
	}
}

func actionPathHasBotIdentity(path ActionPath) bool {
	identityType := strings.TrimSpace(path.ExecutionIdentityType)
	identity := strings.ToLower(strings.TrimSpace(path.ExecutionIdentity))
	switch {
	case identityType == "bot_user" || identityType == "github_app":
		return true
	case strings.Contains(identity, "[bot]") || strings.Contains(identity, "bot"):
		return true
	default:
		return false
	}
}

func hasScriptExtension(location string) bool {
	switch strings.ToLower(strings.TrimSpace(filepath.Ext(location))) {
	case ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd":
		return true
	default:
		return false
	}
}
