package identity

import "testing"

func TestAgentReadModelIdentityKeyUsesCanonicalWrkrFormat(t *testing.T) {
	t.Parallel()

	key := AgentID(ToolID("codex", "AGENTS.md"), "acme")
	if key == "" {
		t.Fatal("expected canonical identity key")
	}
	if key[:5] != "wrkr:" {
		t.Fatalf("expected wrkr identity prefix, got %q", key)
	}
}
