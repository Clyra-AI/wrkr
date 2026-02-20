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

func TestIsValidState(t *testing.T) {
	t.Parallel()
	if !IsValidState(StateUnderReview) {
		t.Fatal("expected under_review to be valid")
	}
	if IsValidState("removed") {
		t.Fatal("removed must not be a lifecycle enum value")
	}
}
