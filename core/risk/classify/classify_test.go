package classify

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
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
