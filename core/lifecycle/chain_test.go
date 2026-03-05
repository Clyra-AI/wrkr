package lifecycle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
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

func TestLifecycleChainSaveHandlesWriteContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity-chain.json")
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)

	chains := make([]*proof.Chain, 0, 6)
	expectedPayloads := map[string]struct{}{}
	for i := 0; i < 6; i++ {
		chain := proof.NewChain("wrkr-identity")
		transition := Transition{
			AgentID:       fmt.Sprintf("wrkr:codex:%d", i),
			PreviousState: "under_review",
			NewState:      "active",
			Trigger:       "manual_transition",
			Timestamp:     now.Add(time.Duration(i) * time.Second).Format(time.RFC3339),
		}
		if err := AppendTransitionRecord(chain, transition, "approval"); err != nil {
			t.Fatalf("append transition %d: %v", i, err)
		}
		payload, err := json.MarshalIndent(chain, "", "  ")
		if err != nil {
			t.Fatalf("marshal chain %d: %v", i, err)
		}
		payload = append(payload, '\n')
		expectedPayloads[string(payload)] = struct{}{}
		chains = append(chains, chain)
	}

	const writers = 48
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		chain := chains[i%len(chains)]
		wg.Add(1)
		go func(candidate *proof.Chain) {
			defer wg.Done()
			<-start
			if err := SaveChain(path, candidate); err != nil {
				errCh <- err
			}
		}(chain)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("unexpected write contention error: %v", err)
		}
	}

	finalPayload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read final chain: %v", err)
	}
	if _, ok := expectedPayloads[string(finalPayload)]; !ok {
		t.Fatalf("final chain payload did not match any valid serialized candidate")
	}
	if _, err := LoadChain(path); err != nil {
		t.Fatalf("expected final chain to remain parseable under contention: %v", err)
	}
}
