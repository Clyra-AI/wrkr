package lifecycle

import (
	"path/filepath"
	"testing"
	"time"
)

func TestChainAppendAndQueryByAgent(t *testing.T) {
	t.Parallel()
	chainPath := filepath.Join(t.TempDir(), "identity-chain.json")
	chain, err := LoadChain(chainPath)
	if err != nil {
		t.Fatalf("load chain: %v", err)
	}
	transition := Transition{AgentID: "wrkr:mcp-1:acme", PreviousState: "under_review", NewState: "active", Trigger: "manual_transition", Timestamp: time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)}
	if err := AppendTransitionRecord(chain, transition, "approval"); err != nil {
		t.Fatalf("append transition: %v", err)
	}
	if err := SaveChain(chainPath, chain); err != nil {
		t.Fatalf("save chain: %v", err)
	}
	loaded, err := LoadChain(chainPath)
	if err != nil {
		t.Fatalf("reload chain: %v", err)
	}
	if got := len(RecordsForAgent(loaded, transition.AgentID)); got != 1 {
		t.Fatalf("expected 1 agent record, got %d", got)
	}
}
