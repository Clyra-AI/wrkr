package cli

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestScanProgressPercentMonotonicSuccessfulRun(t *testing.T) {
	t.Parallel()

	percents := []int{}
	progress := newScanProgressReporter(scanProgressReporterOptions{
		RequestedMode: scanProgressModeNone,
		StartedAt:     time.Unix(0, 0).UTC(),
		TargetMode:    "path",
		TargetValue:   "/tmp/repos",
		StatusSink: func(snapshot scanProgressSnapshot) {
			percents = append(percents, snapshot.ProgressPercent)
		},
	})

	progress.ScanPhase("path", "/tmp/repos", "source_acquire_start")
	progress.PathDiscovery("/tmp/repos", 2)
	progress.PathRepo("/tmp/repos", 1, 2, "alpha")
	progress.PathRepo("/tmp/repos", 2, 2, "beta")
	progress.ScanPhase("path", "/tmp/repos", "source_acquire_complete")
	progress.ScanPhase("path", "/tmp/repos", "detectors_start")
	progress.DetectorStart(detect.DetectorProgressEvent{DetectorID: "codex", Scope: detect.Scope{Org: "local", Repo: "alpha"}, Index: 1, Total: 2})
	progress.DetectorComplete(detect.DetectorProgressEvent{DetectorID: "codex", Scope: detect.Scope{Org: "local", Repo: "alpha"}, Index: 1, Total: 2})
	progress.DetectorStart(detect.DetectorProgressEvent{DetectorID: "mcp", Scope: detect.Scope{Org: "local", Repo: "beta"}, Index: 2, Total: 2})
	progress.DetectorComplete(detect.DetectorProgressEvent{DetectorID: "mcp", Scope: detect.Scope{Org: "local", Repo: "beta"}, Index: 2, Total: 2})
	progress.ScanPhase("path", "/tmp/repos", "detectors_complete")
	progress.ScanPhase("path", "/tmp/repos", "analysis_start")
	progress.ScanPhase("path", "/tmp/repos", "artifact_commit_start")

	if len(percents) == 0 {
		t.Fatalf("expected progress snapshots")
	}
	for i := 1; i < len(percents); i++ {
		if percents[i] < percents[i-1] {
			t.Fatalf("expected monotonic progress percent, got %v", percents)
		}
	}
}

func TestScanProgressPercentDoesNotExceedHundredWhenFailuresAccumulate(t *testing.T) {
	t.Parallel()

	overall, phase := computeScanProgressPercent("source_acquire", state.ScanRepoProgress{
		Total:     4,
		Completed: 4,
		Failed:    2,
	}, state.ScanDetectorProgress{})
	if overall > 100 || phase > 100 {
		t.Fatalf("expected source progress to stay bounded, got overall=%d phase=%d", overall, phase)
	}

	overall, phase = computeScanProgressPercent("detectors", state.ScanRepoProgress{}, state.ScanDetectorProgress{
		Total:     4,
		Completed: 4,
		Failed:    2,
	})
	if overall > 100 || phase > 100 {
		t.Fatalf("expected detector progress to stay bounded, got overall=%d phase=%d", overall, phase)
	}
}
