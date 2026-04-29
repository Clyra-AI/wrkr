package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
)

type scanStatusTracker struct {
	statePath    string
	status       state.ScanStatus
	phaseStarted map[string]time.Time
}

func runScanStatus(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("scan status", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(fs.Output(), "Usage of scan status:")
		_, _ = fmt.Fprintln(fs.Output(), "  wrkr scan status --state <path> [--json]")
		fs.PrintDefaults()
	}
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "scan status does not accept positional arguments", exitInvalidInput)
	}
	status, err := state.LoadScanStatus(*statePathFlag)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(status)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "scan status=%s current_phase=%s last_successful_phase=%s state=%s\n",
		status.Status,
		status.CurrentPhase,
		status.LastSuccessfulPhase,
		status.StatePath,
	)
	if status.SourcePrivacy != nil {
		privacy := sourceprivacy.Normalize(*status.SourcePrivacy)
		_, _ = fmt.Fprintf(stdout, "source privacy: retention=%s retained=%t cleanup=%s locations=%s raw_source_in_artifacts=%t\n",
			privacy.RetentionMode,
			privacy.MaterializedSourceRetained,
			privacy.CleanupStatus,
			privacy.SerializedLocations,
			privacy.RawSourceInArtifacts,
		)
		for _, warning := range privacy.Warnings {
			_, _ = fmt.Fprintf(stdout, "source privacy warning: %s\n", warning)
		}
	}
	return exitSuccess
}

func newScanStatusTracker(statePath string, target source.Target, targets []source.Target, startedAt time.Time, artifactPaths map[string]string, sourcePrivacy sourceprivacy.Contract) *scanStatusTracker {
	now := startedAt.UTC().Truncate(time.Second)
	normalizedPrivacy := sourceprivacy.Normalize(sourcePrivacy)
	status := state.ScanStatus{
		Status:        state.ScanStatusRunning,
		StatePath:     filepath.Clean(state.ResolvePath(statePath)),
		Target:        target,
		Targets:       source.SortTargets(targets),
		StartedAt:     now.Format(time.RFC3339),
		UpdatedAt:     now.Format(time.RFC3339),
		ArtifactPaths: cleanArtifactPaths(artifactPaths),
		SourcePrivacy: &normalizedPrivacy,
	}
	return &scanStatusTracker{statePath: statePath, status: status, phaseStarted: map[string]time.Time{}}
}

func (t *scanStatusTracker) Start() error {
	if t == nil {
		return nil
	}
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) Phase(rawPhase string) error {
	if t == nil {
		return nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	phase := normalizeScanStatusPhase(rawPhase)
	if phase == "" {
		return nil
	}
	t.status.CurrentPhase = phase
	t.status.UpdatedAt = now.Format(time.RFC3339)
	if strings.HasSuffix(strings.TrimSpace(rawPhase), "_start") {
		t.phaseStarted[phase] = now
		t.upsertPhaseTiming(phase, now, time.Time{})
		return state.SaveScanStatus(t.statePath, t.status)
	}
	if strings.HasSuffix(strings.TrimSpace(rawPhase), "_complete") {
		started := t.phaseStarted[phase]
		t.status.LastSuccessfulPhase = phase
		t.upsertPhaseTiming(phase, started, now)
		return state.SaveScanStatus(t.statePath, t.status)
	}
	t.upsertPhaseTiming(phase, t.phaseStarted[phase], time.Time{})
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) Repos(total, completed, failed int) error {
	if t == nil {
		return nil
	}
	t.status.RepoTotal = total
	t.status.ReposCompleted = completed
	t.status.ReposFailed = failed
	t.status.UpdatedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) SetSourcePrivacy(sourcePrivacy sourceprivacy.Contract) {
	if t == nil {
		return
	}
	normalized := sourceprivacy.Normalize(sourcePrivacy)
	t.status.SourcePrivacy = &normalized
}

func (t *scanStatusTracker) Complete(artifactPaths map[string]string) error {
	if t == nil {
		return nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	t.status.Status = state.ScanStatusCompleted
	t.status.CurrentPhase = "artifact_commit"
	t.status.LastSuccessfulPhase = "artifact_commit"
	t.status.PartialResult = false
	t.status.PartialResultMarker = ""
	t.status.CompletedAt = now.Format(time.RFC3339)
	t.status.UpdatedAt = t.status.CompletedAt
	t.status.ArtifactPaths = cleanArtifactPaths(artifactPaths)
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) Fail(err error, artifactPaths map[string]string) {
	if t == nil {
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	status := state.ScanStatusFailed
	if err != nil && (contextErr(err) || strings.Contains(strings.ToLower(err.Error()), "interrupted")) {
		status = state.ScanStatusInterrupted
	}
	t.status.Status = status
	t.status.PartialResult = true
	t.status.PartialResultMarker = "partial_result"
	if err != nil {
		t.status.Error = err.Error()
	}
	t.status.UpdatedAt = now.Format(time.RFC3339)
	t.status.ArtifactPaths = cleanArtifactPaths(artifactPaths)
	_ = state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) Footer() string {
	if t == nil {
		return ""
	}
	paths := make([]string, 0, len(t.status.ArtifactPaths))
	for key, value := range t.status.ArtifactPaths {
		if strings.TrimSpace(value) != "" {
			paths = append(paths, key+"="+value)
		}
	}
	sort.Strings(paths)
	return fmt.Sprintf("scan status=%s last_successful_phase=%s current_phase=%s partial_result=%t artifacts=%s",
		t.status.Status,
		t.status.LastSuccessfulPhase,
		t.status.CurrentPhase,
		t.status.PartialResult,
		strings.Join(paths, ","),
	)
}

func (t *scanStatusTracker) upsertPhaseTiming(phase string, startedAt time.Time, completedAt time.Time) {
	if phase == "" {
		return
	}
	timing := state.PhaseTiming{Phase: phase}
	if !startedAt.IsZero() {
		timing.StartedAt = startedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	if !completedAt.IsZero() {
		timing.CompletedAt = completedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	if !startedAt.IsZero() && !completedAt.IsZero() && !completedAt.Before(startedAt) {
		timing.DurationMillis = completedAt.Sub(startedAt).Milliseconds()
	}
	for idx := range t.status.PhaseTimings {
		if t.status.PhaseTimings[idx].Phase == phase {
			t.status.PhaseTimings[idx] = timing
			return
		}
	}
	t.status.PhaseTimings = append(t.status.PhaseTimings, timing)
}

func normalizeScanStatusPhase(raw string) string {
	phase := strings.TrimSpace(raw)
	phase = strings.TrimSuffix(phase, "_start")
	phase = strings.TrimSuffix(phase, "_complete")
	return strings.TrimSpace(phase)
}

func cleanArtifactPaths(paths map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range paths {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		out[key] = filepath.Clean(value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func contextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
