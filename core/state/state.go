package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
)

const SnapshotVersion = "v1"

// Snapshot stores deterministic scan material for diff mode.
type Snapshot struct {
	Version      string                    `json:"version"`
	Target       source.Target             `json:"target"`
	Findings     []source.Finding          `json:"findings"`
	Inventory    *agginventory.Inventory   `json:"inventory,omitempty"`
	RiskReport   *risk.Report              `json:"risk_report,omitempty"`
	Profile      *profileeval.Result       `json:"profile,omitempty"`
	PostureScore *score.Result             `json:"posture_score,omitempty"`
	Identities   []manifest.IdentityRecord `json:"identities,omitempty"`
	Transitions  []lifecycle.Transition    `json:"lifecycle_transitions,omitempty"`
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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
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
	// #nosec G304 -- caller controls state path selection; reading that explicit path is intended.
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
