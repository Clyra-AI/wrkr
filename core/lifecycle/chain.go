package lifecycle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
)

func ChainPath(statePath string) string {
	dir := filepath.Dir(statePath)
	if dir == "." || dir == "" {
		dir = ".wrkr"
	}
	return filepath.Join(dir, "identity-chain.json")
}

func LoadChain(path string) (*proof.Chain, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return proof.NewChain("wrkr-identity"), nil
		}
		return nil, fmt.Errorf("read chain: %w", err)
	}
	var chain proof.Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		return nil, fmt.Errorf("parse chain: %w", err)
	}
	if chain.ChainID == "" {
		chain.ChainID = "wrkr-identity"
	}
	return &chain, nil
}

func SaveChain(path string, chain *proof.Chain) error {
	if chain == nil {
		return fmt.Errorf("chain is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir chain dir: %w", err)
	}
	payload, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chain: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write chain: %w", err)
	}
	return nil
}

func AppendTransitionRecord(chain *proof.Chain, transition Transition, eventType string) error {
	if chain == nil {
		return fmt.Errorf("chain is required")
	}
	ts, err := time.Parse(time.RFC3339, transition.Timestamp)
	if err != nil {
		ts = time.Now().UTC().Truncate(time.Second)
	}
	recordType := strings.TrimSpace(eventType)
	if recordType == "" {
		recordType = "decision"
	}
	if recordType == "lifecycle_transition" {
		recordType = "decision"
	}
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     ts,
		Source:        "wrkr",
		SourceProduct: "wrkr",
		AgentID:       transition.AgentID,
		Type:          recordType,
		Event: map[string]any{
			"event_type":      eventType,
			"previous_state": transition.PreviousState,
			"new_state":      transition.NewState,
			"trigger":        transition.Trigger,
			"diff":           transition.Diff,
		},
		Controls: proof.Controls{PermissionsEnforced: true},
	})
	if err != nil {
		return fmt.Errorf("build transition record: %w", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		return fmt.Errorf("append transition record: %w", err)
	}
	return nil
}

func RecordsForAgent(chain *proof.Chain, agentID string) []proof.Record {
	if chain == nil {
		return nil
	}
	out := make([]proof.Record, 0)
	for _, record := range chain.Records {
		if record.AgentID == agentID {
			out = append(out, record)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].RecordID < out[j].RecordID
		}
		return out[i].Timestamp.Before(out[j].Timestamp)
	})
	return out
}
