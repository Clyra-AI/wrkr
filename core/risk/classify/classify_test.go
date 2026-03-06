package classify

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk/autonomy"
)

func TestEndpointClass(t *testing.T) {
	t.Parallel()
	finding := model.Finding{
		FindingType: "mcp_server",
		ToolType:    "mcp",
		Evidence:    []model.Evidence{{Key: "transport", Value: "http"}},
	}
	if got := EndpointClass(finding); got != "network_service" {
		t.Fatalf("unexpected endpoint class: %s", got)
	}
}

func TestDataClass(t *testing.T) {
	t.Parallel()
	finding := model.Finding{FindingType: "secret_presence", Location: ".env"}
	if got := DataClass(finding); got != "credentials" {
		t.Fatalf("unexpected data class: %s", got)
	}
}

func TestAutonomyLevelDefaults(t *testing.T) {
	t.Parallel()
	finding := model.Finding{FindingType: "tool_config", ToolType: "copilot"}
	if got := AutonomyLevel(finding); got != "copilot" {
		t.Fatalf("unexpected autonomy level: %s", got)
	}
}

func TestAgentFrameworkClassificationUsesEvidence(t *testing.T) {
	t.Parallel()

	finding := model.Finding{
		FindingType: "agent_framework",
		ToolType:    "langchain",
		Location:    "agents/release.py",
		Evidence: []model.Evidence{
			{Key: "data_class", Value: "pii"},
			{Key: "deployment_status", Value: "deployed"},
			{Key: "auto_deploy", Value: "true"},
			{Key: "human_gate", Value: "false"},
		},
	}

	if got := EndpointClass(finding); got != "ci_pipeline" {
		t.Fatalf("unexpected agent endpoint class: %s", got)
	}
	if got := DataClass(finding); got != "pii" {
		t.Fatalf("unexpected agent data class: %s", got)
	}
	if got := AutonomyLevel(finding); got != autonomy.LevelHeadlessAuto {
		t.Fatalf("unexpected agent autonomy level: %s", got)
	}
}
