package state

import (
	"path/filepath"
	"testing"
)

func TestScanStatusSaveLoadAtomicSidecar(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "last-scan.json")
	in := ScanStatus{
		Status:              ScanStatusRunning,
		CurrentPhase:        "source_acquire",
		LastSuccessfulPhase: "repo_discovery",
		RepoTotal:           3,
		ReposCompleted:      1,
		PartialResult:       true,
		PartialResultMarker: "partial_result",
		ArtifactPaths:       map[string]string{"state": statePath},
		PhaseTimings:        []PhaseTiming{{Phase: "source_acquire", StartedAt: "2026-02-21T12:00:00Z"}},
	}
	if err := SaveScanStatus(statePath, in); err != nil {
		t.Fatalf("save scan status: %v", err)
	}
	got, err := LoadScanStatus(statePath)
	if err != nil {
		t.Fatalf("load scan status: %v", err)
	}
	if got.Status != ScanStatusRunning || got.CurrentPhase != "source_acquire" || got.RepoTotal != 3 {
		t.Fatalf("unexpected status: %+v", got)
	}
	if got.ArtifactPaths["state"] != statePath {
		t.Fatalf("expected state artifact path, got %+v", got.ArtifactPaths)
	}
}

func TestLoadScanStatusInfersCompletedFromExistingState(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := Save(statePath, Snapshot{}); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	status, err := LoadScanStatus(statePath)
	if err != nil {
		t.Fatalf("load scan status: %v", err)
	}
	if status.Status != ScanStatusCompleted || status.LastSuccessfulPhase != "artifact_commit" {
		t.Fatalf("expected completed inferred status, got %+v", status)
	}
}
