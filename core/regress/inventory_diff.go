package regress

import (
	"github.com/Clyra-AI/wrkr/core/diff"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

type InventoryDiffResult struct {
	Status       string             `json:"status"`
	Drift        bool               `json:"drift_detected"`
	BaselinePath string             `json:"baseline_path,omitempty"`
	AddedCount   int                `json:"added_count"`
	RemovedCount int                `json:"removed_count"`
	ChangedCount int                `json:"changed_count"`
	Added        []source.Finding   `json:"added"`
	Removed      []source.Finding   `json:"removed"`
	Changed      []diff.ChangedItem `json:"changed"`
}

func CompareInventory(baseline, current state.Snapshot) InventoryDiffResult {
	computed := diff.Compute(baseline.Findings, current.Findings)
	drift := !diff.Empty(computed)
	status := "ok"
	if drift {
		status = "drift"
	}
	return InventoryDiffResult{
		Status:       status,
		Drift:        drift,
		AddedCount:   len(computed.Added),
		RemovedCount: len(computed.Removed),
		ChangedCount: len(computed.Changed),
		Added:        computed.Added,
		Removed:      computed.Removed,
		Changed:      computed.Changed,
	}
}
