package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/core/source"
)

const SnapshotVersion = "v1"

// Snapshot stores deterministic scan material for diff mode.
type Snapshot struct {
	Version  string           `json:"version"`
	Target   source.Target    `json:"target"`
	Findings []source.Finding `json:"findings"`
}

func ResolvePath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if fromEnv := strings.TrimSpace(os.Getenv("WRKR_STATE_PATH")); fromEnv != "" {
		return fromEnv
	}
	return filepath.Join(".wrkr", "last-scan.json")
}

func Save(path string, snapshot Snapshot) error {
	snapshot.Version = SnapshotVersion
	source.SortFindings(snapshot.Findings)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	payload, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	return nil
}

func Load(path string) (Snapshot, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read state: %w", err)
	}
	var snapshot Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("parse state: %w", err)
	}
	if snapshot.Version == "" {
		snapshot.Version = SnapshotVersion
	}
	source.SortFindings(snapshot.Findings)
	return snapshot, nil
}
