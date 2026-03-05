package agentresolver

import (
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestAgentResolver_BindsToolsDataAuthDeterministically(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "langchain",
			Location:    "agents/main.py",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "release_agent"},
				{Key: "bound_tools", Value: "mcp.deploy,search.read"},
				{Key: "data_sources", Value: "warehouse.events"},
				{Key: "auth_surfaces", Value: "oauth2,token"},
			},
		},
	}

	first := Resolve(findings)
	second := Resolve(findings)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic resolver output\nfirst=%+v\nsecond=%+v", first, second)
	}

	instanceID := identity.AgentInstanceID("langchain", "agents/main.py", "release_agent", 0, 0)
	binding, ok := first[instanceID]
	if !ok {
		t.Fatalf("expected binding for %s", instanceID)
	}
	if !reflect.DeepEqual(binding.BoundTools, []string{"mcp.deploy", "search.read"}) {
		t.Fatalf("unexpected bound tools: %+v", binding.BoundTools)
	}
	if !reflect.DeepEqual(binding.BoundDataSources, []string{"warehouse.events"}) {
		t.Fatalf("unexpected data sources: %+v", binding.BoundDataSources)
	}
	if !reflect.DeepEqual(binding.BoundAuthSurfaces, []string{"oauth2", "token"}) {
		t.Fatalf("unexpected auth surfaces: %+v", binding.BoundAuthSurfaces)
	}
	if len(binding.BindingEvidenceKeys) == 0 {
		t.Fatalf("expected stable evidence keys, got %+v", binding.BindingEvidenceKeys)
	}
}

func TestAgentResolver_PartialExtractionMarksMissingLinks(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "crewai",
			Location:    "crews/ops.py",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "ops_agent"},
				{Key: "bound_tools", Value: "deploy.write"},
			},
		},
	}

	instanceID := identity.AgentInstanceID("crewai", "crews/ops.py", "ops_agent", 0, 0)
	binding := Resolve(findings)[instanceID]
	if !reflect.DeepEqual(binding.MissingBindings, []string{"auth_binding_unknown", "data_binding_unknown"}) {
		t.Fatalf("expected deterministic missing links, got %+v", binding.MissingBindings)
	}
}
