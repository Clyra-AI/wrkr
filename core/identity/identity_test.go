package identity

import "testing"

func TestAgentIDDeterministic(t *testing.T) {
	t.Parallel()

	toolID := ToolID("mcp", ".mcp.json")
	got := AgentID(toolID, "acme")
	want := AgentID(toolID, "acme")
	if got != want {
		t.Fatalf("expected deterministic id, got %q want %q", got, want)
	}
	if got != "wrkr:"+toolID+":acme" {
		t.Fatalf("unexpected format %q", got)
	}
}

func TestToolIDStable(t *testing.T) {
	t.Parallel()

	a := ToolID("cursor", ".cursor/mcp.json")
	b := ToolID("cursor", ".cursor/mcp.json")
	if a != b {
		t.Fatalf("expected stable tool id, got %q and %q", a, b)
	}
	if a == ToolID("cursor", ".cursor/rules/security.mdc") {
		t.Fatal("expected different locations to produce different tool ids")
	}
}

func TestAgentInstanceID_TwoDefinitionsSameFile_AreDistinct(t *testing.T) {
	t.Parallel()

	first := AgentInstanceID("langchain", "agents.py", "research_agent", 12, 28)
	second := AgentInstanceID("langchain", "agents.py", "ops_agent", 30, 45)
	if first == second {
		t.Fatalf("expected distinct instance IDs for separate definitions, got %q", first)
	}
	repeat := AgentInstanceID("langchain", "agents.py", "research_agent", 12, 28)
	if first != repeat {
		t.Fatalf("expected deterministic instance ID, got %q and %q", first, repeat)
	}
}

func TestAgentIDBackwardCompatibility_ToolIDFlowStillResolves(t *testing.T) {
	t.Parallel()

	legacyToolID := ToolID("codex", "AGENTS.md")
	instanceID := AgentInstanceID("codex", "AGENTS.md", "", 0, 0)
	if instanceID != legacyToolID {
		t.Fatalf("expected missing metadata to preserve legacy tool_id, got %q want %q", instanceID, legacyToolID)
	}
	legacyAgentID := AgentID(legacyToolID, "acme")
	if agentID := LegacyAgentID("codex", "AGENTS.md", "acme"); agentID != legacyAgentID {
		t.Fatalf("expected legacy agent id compatibility, got %q want %q", agentID, legacyAgentID)
	}
}

func TestIsValidState(t *testing.T) {
	t.Parallel()
	if !IsValidState(StateUnderReview) {
		t.Fatal("expected under_review to be valid")
	}
	if IsValidState("removed") {
		t.Fatal("removed must not be a lifecycle enum value")
	}
}
