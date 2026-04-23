package regress

import (
	"github.com/Clyra-AI/wrkr/core/diff"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

type InventoryDiffResult struct {
	Status                 string             `json:"status"`
	Drift                  bool               `json:"drift_detected"`
	BaselinePath           string             `json:"baseline_path,omitempty"`
	AddedCount             int                `json:"added_count"`
	RemovedCount           int                `json:"removed_count"`
	ChangedCount           int                `json:"changed_count"`
	ControlPathDrift       bool               `json:"control_path_drift_detected,omitempty"`
	ControlPathReasonCount int                `json:"control_path_reason_count,omitempty"`
	ControlPathReasons     []Reason           `json:"control_path_reasons,omitempty"`
	Added                  []source.Finding   `json:"added"`
	Removed                []source.Finding   `json:"removed"`
	Changed                []diff.ChangedItem `json:"changed"`
}

func CompareInventory(baseline, current state.Snapshot) InventoryDiffResult {
	computed := diff.Compute(baseline.Findings, current.Findings)
	controlPath := Compare(BuildBaselineFromSnapshot(baseline), current)
	drift := !diff.Empty(computed) || controlPath.Drift
	status := "ok"
	if drift {
		status = "drift"
	}
	return InventoryDiffResult{
		Status:                 status,
		Drift:                  drift,
		AddedCount:             len(computed.Added),
		RemovedCount:           len(computed.Removed),
		ChangedCount:           len(computed.Changed),
		ControlPathDrift:       controlPath.Drift,
		ControlPathReasonCount: controlPath.ReasonCount,
		ControlPathReasons:     controlPath.Reasons,
		Added:                  computed.Added,
		Removed:                computed.Removed,
		Changed:                computed.Changed,
	}
}
