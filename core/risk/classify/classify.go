package classify

import (
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
)

func EndpointClass(finding model.Finding) string {
	location := strings.ToLower(strings.TrimSpace(finding.Location))
	toolType := strings.ToLower(strings.TrimSpace(finding.ToolType))

	switch {
	case finding.FindingType == "ci_autonomy" || strings.Contains(location, ".github/workflows") || strings.Contains(location, "jenkinsfile"):
		return "ci_pipeline"
	case finding.FindingType == "compiled_action" || strings.Contains(location, "agent-plans") || strings.Contains(location, "workflows/"):
		return "compiled_action"
	case finding.FindingType == "mcp_server" || toolType == "mcp":
		if transport := evidenceValue(finding, "transport"); transport == "http" || transport == "sse" || transport == "streamable_http" {
			return "network_service"
		}
		return "local_service"
	case strings.Contains(location, ".claude/"), strings.Contains(location, ".cursor/"), strings.Contains(location, ".codex/"), strings.Contains(location, "agents.md"):
		return "repo_config"
	default:
		return "workspace"
	}
}

func DataClass(finding model.Finding) string {
	location := strings.ToLower(strings.TrimSpace(finding.Location))
	if finding.FindingType == "secret_presence" {
		return "credentials"
	}
	for _, permission := range finding.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		switch {
		case strings.Contains(normalized, "db.write"), strings.Contains(normalized, "db.read"):
			return "database"
		case strings.Contains(normalized, "secret"), strings.Contains(normalized, "token"):
			return "credentials"
		}
	}
	if strings.Contains(location, "customer") || strings.Contains(location, "profile") || strings.Contains(location, "user") {
		return "pii"
	}
	if strings.Contains(location, ".github/workflows") || strings.Contains(location, "deploy") {
		return "delivery"
	}
	return "code"
}

func AutonomyLevel(finding model.Finding) string {
	if strings.TrimSpace(finding.Autonomy) != "" {
		return strings.TrimSpace(finding.Autonomy)
	}
	if finding.FindingType == "ci_autonomy" {
		headless := evidenceBool(finding, "headless")
		hasGate := evidenceBool(finding, "approval_gate")
		return autonomy.Classify(autonomy.Signals{Headless: headless, HasApprovalGate: hasGate})
	}
	if strings.Contains(strings.ToLower(finding.ToolType), "copilot") {
		return autonomy.LevelCopilot
	}
	return autonomy.LevelInteractive
}

func evidenceValue(finding model.Finding, key string) string {
	needle := strings.ToLower(strings.TrimSpace(key))
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) == needle {
			return strings.ToLower(strings.TrimSpace(item.Value))
		}
	}
	return ""
}

func evidenceBool(finding model.Finding, key string) bool {
	value := evidenceValue(finding, key)
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}
