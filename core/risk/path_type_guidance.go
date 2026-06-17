package risk

import "strings"

const (
	pathGuidanceGenericTarget = "generic_target"
	pathGuidanceOpenAPI       = "openapi"
	pathGuidanceRoute         = "route"
	pathGuidanceInstruction   = "instruction"
	pathGuidanceMCPConfig     = "mcp_config"
	pathGuidanceDependency    = "dependency"
	pathGuidanceCIWorkflow    = "ci_workflow"
	pathGuidanceRelease       = "release_workflow"
	pathGuidanceGenericPath   = "generic_path"
)

func pathGuidanceClass(path ActionPath) string {
	switch {
	case pathTargetsCorrelationContext(path) && pathIsOpenAPISurface(path):
		return pathGuidanceOpenAPI
	case pathTargetsCorrelationContext(path) && pathIsRouteSurface(path):
		return pathGuidanceRoute
	case actionPathDependencyOnly(path):
		return pathGuidanceDependency
	case pathIsMCPConfigurationSurface(path):
		return pathGuidanceMCPConfig
	case pathIsAgentInstructionControlSurface(path):
		return pathGuidanceInstruction
	case pathIsReleaseWorkflowSurface(path):
		return pathGuidanceRelease
	case pathIsWorkflowSurface(path):
		return pathGuidanceCIWorkflow
	case pathTargetsCorrelationContext(path):
		return pathGuidanceGenericTarget
	default:
		return pathGuidanceGenericPath
	}
}

func pathSurfaceLabel(path ActionPath) string {
	switch pathGuidanceClass(path) {
	case pathGuidanceOpenAPI:
		return "API specification surface"
	case pathGuidanceRoute:
		return "route surface"
	case pathGuidanceInstruction:
		return "instruction surface"
	case pathGuidanceMCPConfig:
		return "MCP configuration surface"
	case pathGuidanceDependency:
		return "dependency inventory signal"
	case pathGuidanceCIWorkflow:
		return "workflow path"
	case pathGuidanceRelease:
		return "release workflow path"
	case pathGuidanceGenericTarget:
		return "target surface"
	default:
		return "path"
	}
}

func pathCorrelationClosureCopy(path ActionPath) (required string, examples []string, guidance string) {
	switch pathGuidanceClass(path) {
	case pathGuidanceOpenAPI:
		return "Correlation evidence that links this API specification surface to the workflow, runtime caller, tool binding, deploy path, or recent change that actually consumes it.",
			[]string{
				"Attach the workflow, runtime caller, or MCP/tool reference that consumes operations declared in this spec.",
				"Attach a recent change, deployment mapping, or owner-reviewed declaration that links the spec to the execution path it governs.",
			},
			"Correlate this API specification surface to the workflow, runtime caller, deploy path, MCP/tool binding, or recent change that actually consumes it before promoting it into Top Action Paths or Action Contracts."
	case pathGuidanceRoute:
		return "Correlation evidence that links this route surface to the workflow, runtime caller, deploy path, or tool binding that actually executes it.",
			[]string{
				"Attach the workflow, runtime caller, or service binding that executes this route directly.",
				"Attach a recent change, deploy mapping, or owner-reviewed declaration that links the route to the path it governs.",
			},
			"Correlate this route surface to the workflow, runtime caller, deploy path, or tool binding that actually executes it before promoting it into Top Action Paths or Action Contracts."
	case pathGuidanceInstruction:
		return "Correlation evidence plus owner/review evidence that links this instruction surface to the workflow, agent runtime, tool config, or provider boundary that consumes it.",
			[]string{
				"Attach CODEOWNERS, branch-protection, provider-team, app-catalog, or customer-owner evidence for the instruction surface.",
				"Attach the workflow, runtime, or tool-binding evidence that proves which execution path consumes this instruction file or config.",
			},
			"Correlate this instruction surface to the workflow, agent runtime, MCP/tool path, or recent change that consumes it, then attach owner and review evidence before treating it as governable."
	case pathGuidanceMCPConfig:
		return "Correlation evidence plus owner/review evidence that links this MCP configuration surface to the server, workflow, runtime, or tool binding that consumes it.",
			[]string{
				"Attach the MCP server or tool-binding evidence that proves which workflow or runtime loads this configuration.",
				"Attach CODEOWNERS, provider-team, app-catalog, or customer-owner evidence for the MCP configuration surface.",
			},
			"Correlate this MCP configuration surface to the server, workflow, runtime, or tool binding that consumes it, then attach owner and review evidence before treating it as governable."
	case pathGuidanceDependency:
		return "Executable or runtime/control evidence that proves this dependency inventory signal governs a real path.",
			[]string{
				"Attach the workflow, runtime, or tool path that loads or executes the dependency.",
				"Keep the dependency signal in context-only output until a governable binding is proven.",
			},
			"Keep this dependency inventory signal in context until executable, runtime, or control evidence proves it governs a real path."
	default:
		return "Correlation evidence that links this surface to a real workflow, credential use, tool binding, deploy path, runtime caller, or recent change.",
			[]string{
				"Attach a workflow, runtime, or MCP/tool reference that consumes this surface directly.",
				"Attach a recent change or owner-reviewed declaration that links this surface to the execution path it governs.",
			},
			"Correlate this surface to a real executable or governable path before promoting it into Top Action Paths or Action Contracts."
	}
}

func pathOwnerClosureGuidance(path ActionPath) string {
	return "Assign explicit owner evidence for this " + pathSurfaceLabel(path) + " and attach a linked owner record before approving or expanding it."
}

func pathApprovalClosureGuidance(path ActionPath) string {
	return "Attach approval evidence for this exact " + pathSurfaceLabel(path) + " with scope and expiry before treating it as governed."
}

func pathPolicyClosureGuidance(path ActionPath) string {
	return "Attach a path-specific policy or proof reference for this exact " + pathSurfaceLabel(path) + " and rescan so proof is no longer inferred or absent."
}

func pathProofClosureGuidance(path ActionPath) string {
	return "Attach path-specific proof for the current control claim on this " + pathSurfaceLabel(path) + " before treating it as fully verified."
}

func pathRuntimeClosureGuidance(path ActionPath) string {
	return "Collect runtime evidence for this " + pathSurfaceLabel(path) + " and correlate it back to the saved path before treating runtime claims as verified."
}

func pathJITClosureGuidance(path ActionPath) string {
	return "Provide JIT credential evidence for this " + pathSurfaceLabel(path) + " and correlate it back to the saved path before treating standing-access risk as reduced."
}

func pathIsOpenAPISurface(path ActionPath) bool {
	location := normalizedGuidanceLocation(path.Location)
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	return toolType == "openapi" || strings.Contains(location, "openapi") || strings.Contains(location, "swagger")
}

func pathIsRouteSurface(path ActionPath) bool {
	location := normalizedGuidanceLocation(path.Location)
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	return toolType == "route" || strings.Contains(location, "/routes") || strings.Contains(location, "/route")
}

func pathIsMCPConfigurationSurface(path ActionPath) bool {
	location := normalizedGuidanceLocation(path.Location)
	switch {
	case strings.HasSuffix(location, ".mcp.json"),
		strings.HasSuffix(location, ".cursor/mcp.json"),
		strings.HasSuffix(location, ".vscode/mcp.json"),
		strings.HasSuffix(location, ".github/copilot-mcp.json"),
		strings.HasSuffix(location, ".github/copilot-mcp.yaml"),
		strings.HasSuffix(location, ".github/copilot-mcp.yml"):
		return true
	default:
		return false
	}
}

func pathIsWorkflowSurface(path ActionPath) bool {
	location := normalizedGuidanceLocation(path.Location)
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	return strings.TrimSpace(path.ActionPathType) == ActionPathTypeCICDWorkflow ||
		strings.Contains(location, ".github/workflows") ||
		strings.Contains(location, "jenkinsfile") ||
		toolType == "ci_agent" ||
		(toolType == "compiled_action" && strings.Contains(location, ".github/workflows"))
}

func pathIsReleaseWorkflowSurface(path ActionPath) bool {
	if !pathIsWorkflowSurface(path) {
		return false
	}
	location := normalizedGuidanceLocation(path.Location)
	switch {
	case path.ProductionWrite,
		path.DeployWrite,
		strings.Contains(location, "release"),
		strings.Contains(location, "deploy"),
		strings.Contains(location, "publish"):
		return true
	default:
		return false
	}
}

func normalizedGuidanceLocation(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "\\", "/"))
}
