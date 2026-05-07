package state

import (
	"os"
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

func TestScanStatusSaveLoadProgressFields(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "last-scan.json")
	in := ScanStatus{
		Status:          ScanStatusRunning,
		CurrentPhase:    "detectors",
		ProgressPercent: 64,
		ProgressMessage: "running detector codex on alpha",
		LastProgressAt:  "2026-05-07T14:40:30Z",
		ElapsedSeconds:  12,
		PhaseProgress:   &ScanPhaseProgress{Phase: "detectors", Percent: 36},
		RepoProgress:    &ScanRepoProgress{Total: 2, Completed: 1, Pending: 1},
		DetectorProgress: &ScanDetectorProgress{
			Total:          8,
			Completed:      3,
			Pending:        5,
			ActiveDetector: "codex",
		},
	}
	if err := SaveScanStatus(statePath, in); err != nil {
		t.Fatalf("save scan status: %v", err)
	}
	got, err := LoadScanStatus(statePath)
	if err != nil {
		t.Fatalf("load scan status: %v", err)
	}
	if got.ProgressPercent != 64 || got.ProgressMessage != "running detector codex on alpha" {
		t.Fatalf("expected additive progress fields, got %+v", got)
	}
	if got.PhaseProgress == nil || got.PhaseProgress.Phase != "detectors" {
		t.Fatalf("expected phase progress, got %+v", got)
	}
	if got.RepoProgress == nil || got.RepoProgress.Total != 2 {
		t.Fatalf("expected repo progress, got %+v", got)
	}
	if got.DetectorProgress == nil || got.DetectorProgress.ActiveDetector != "codex" {
		t.Fatalf("expected detector progress, got %+v", got)
	}
}

func TestScanStatusLoadsLegacySidecarWithoutProgress(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "last-scan.json")
	payload := []byte("{\n  \"scan_status_version\": \"1\",\n  \"status\": \"running\",\n  \"state_path\": \"" + statePath + "\",\n  \"current_phase\": \"source_acquire\"\n}\n")
	if err := os.WriteFile(ScanStatusPath(statePath), payload, 0o600); err != nil {
		t.Fatalf("write legacy sidecar: %v", err)
	}
	got, err := LoadScanStatus(statePath)
	if err != nil {
		t.Fatalf("load legacy sidecar: %v", err)
	}
	if got.Status != ScanStatusRunning || got.CurrentPhase != "source_acquire" {
		t.Fatalf("unexpected legacy status: %+v", got)
	}
	if got.ProgressPercent != 0 || got.PhaseProgress != nil || got.RepoProgress != nil || got.DetectorProgress != nil {
		t.Fatalf("expected legacy sidecar to load without additive progress fields, got %+v", got)
	}
}
