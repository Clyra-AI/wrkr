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
	"sync"
	"time"

	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
)

type scanStatusTracker struct {
	mu           sync.Mutex
	statePath    string
	status       state.ScanStatus
	phaseStarted map[string]time.Time
	targets      []source.Target
	lastProgress scanProgressSnapshot
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
	if status.ProgressPercent > 0 || status.ProgressMessage != "" || status.PhaseProgress != nil || status.RepoProgress != nil || status.DetectorProgress != nil {
		phase := status.CurrentPhase
		if status.PhaseProgress != nil && strings.TrimSpace(status.PhaseProgress.Phase) != "" {
			phase = status.PhaseProgress.Phase
		}
		_, _ = fmt.Fprintf(stdout, "progress percent=%d phase=%s elapsed_seconds=%d message=%s\n",
			status.ProgressPercent,
			phase,
			status.ElapsedSeconds,
			fallbackForExplain(status.ProgressMessage, "<none>"),
		)
	}
	if status.SourcePrivacy != nil {
		privacy := sourceprivacy.Normalize(*status.SourcePrivacy)
		_, _ = fmt.Fprintf(stdout, "source privacy: deployment_mode=%s retention=%s retained=%t cleanup=%s locations=%s raw_source_in_artifacts=%t\n",
			privacy.DeploymentMode,
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
	return &scanStatusTracker{
		statePath:    statePath,
		status:       status,
		phaseStarted: map[string]time.Time{},
		targets:      source.SortTargets(targets),
	}
}

func (t *scanStatusTracker) Start() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) Phase(rawPhase string) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
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

func (t *scanStatusTracker) Repos(total, succeeded, failed int) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	completed := maxProgressCount(succeeded+failed, 0)
	t.status.RepoTotal = total
	t.status.ReposCompleted = completed
	t.status.ReposSucceeded = succeeded
	t.status.ReposFailed = failed
	t.status.RepoProgress = &state.ScanRepoProgress{
		Total:     total,
		Succeeded: succeeded,
		Completed: completed,
		Failed:    failed,
		Pending:   maxProgressCount(total-completed, 0),
	}
	t.status.UpdatedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) SetSourcePrivacy(sourcePrivacy sourceprivacy.Contract) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	normalized := sourceprivacy.Normalize(sourcePrivacy)
	t.status.SourcePrivacy = &normalized
}

func (t *scanStatusTracker) Complete(artifactPaths map[string]string, partialResult bool) error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Second)
	t.status.Status = state.ScanStatusCompleted
	t.status.CurrentPhase = "artifact_commit"
	t.status.LastSuccessfulPhase = "artifact_commit"
	t.status.PartialResult = partialResult || t.status.PartialResult
	if t.status.PartialResult {
		t.status.PartialResultMarker = "partial_result"
	} else {
		t.status.PartialResultMarker = ""
	}
	t.status.CompletedAt = now.Format(time.RFC3339)
	t.status.UpdatedAt = t.status.CompletedAt
	t.status.ArtifactPaths = cleanArtifactPaths(artifactPaths)
	if t.lastProgress.ProgressPercent < 100 {
		t.applyProgressLocked(scanProgressSnapshot{
			ProgressPercent: 100,
			LastProgressAt:  now,
			ElapsedSeconds:  elapsedSecondsFromStartedAt(t.status.StartedAt, now),
			PhaseProgress: state.ScanPhaseProgress{
				Phase:   "artifact_commit",
				Percent: 100,
			},
			RepoProgress:     t.lastProgress.RepoProgress,
			DetectorProgress: t.lastProgress.DetectorProgress,
		})
	}
	return state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) Fail(err error, artifactPaths map[string]string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
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
	return formatScanProgressFooter(t.FooterData())
}

func (t *scanStatusTracker) Progress(snapshot scanProgressSnapshot) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.applyProgressLocked(snapshot)
	_ = state.SaveScanStatus(t.statePath, t.status)
}

func (t *scanStatusTracker) FooterData() scanProgressFooter {
	if t == nil {
		return scanProgressFooter{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	paths := make([]string, 0, len(t.status.ArtifactPaths))
	for key, value := range t.status.ArtifactPaths {
		if strings.TrimSpace(value) != "" {
			paths = append(paths, key+"="+value)
		}
	}
	sort.Strings(paths)
	return scanProgressFooter{
		Status:              t.status.Status,
		CurrentPhase:        t.status.CurrentPhase,
		LastSuccessfulPhase: t.status.LastSuccessfulPhase,
		ProgressPercent:     t.status.ProgressPercent,
		ProgressMessage:     t.status.ProgressMessage,
		ElapsedSeconds:      t.status.ElapsedSeconds,
		PartialResult:       t.status.PartialResult,
		RepoTotal:           t.status.RepoTotal,
		ReposCompleted:      t.status.ReposCompleted,
		ReposSucceeded:      t.status.ReposSucceeded,
		ReposFailed:         t.status.ReposFailed,
		DetectorProgress:    t.status.DetectorProgress,
		ArtifactPaths:       append([]string(nil), paths...),
		ResumeHint:          t.resumeHintLocked(),
	}
}

func (t *scanStatusTracker) applyProgressLocked(snapshot scanProgressSnapshot) {
	if t == nil {
		return
	}
	t.lastProgress = snapshot
	if snapshot.ProgressPercent > 0 {
		t.status.ProgressPercent = snapshot.ProgressPercent
	}
	if strings.TrimSpace(snapshot.ProgressMessage) != "" {
		t.status.ProgressMessage = strings.TrimSpace(snapshot.ProgressMessage)
	}
	if !snapshot.LastProgressAt.IsZero() {
		t.status.LastProgressAt = snapshot.LastProgressAt.UTC().Truncate(time.Second).Format(time.RFC3339)
		t.status.UpdatedAt = t.status.LastProgressAt
	}
	if snapshot.ElapsedSeconds > 0 {
		t.status.ElapsedSeconds = snapshot.ElapsedSeconds
	}
	if strings.TrimSpace(snapshot.PhaseProgress.Phase) != "" || snapshot.PhaseProgress.Percent > 0 {
		phaseProgress := snapshot.PhaseProgress
		t.status.PhaseProgress = &phaseProgress
	}
	if snapshot.RepoProgress.Total > 0 || snapshot.RepoProgress.Completed > 0 || snapshot.RepoProgress.Failed > 0 {
		repoProgress := snapshot.RepoProgress
		t.status.RepoProgress = &repoProgress
		t.status.RepoTotal = repoProgress.Total
		t.status.ReposCompleted = repoProgress.Completed
		t.status.ReposSucceeded = repoProgress.Succeeded
		t.status.ReposFailed = repoProgress.Failed
	}
	if snapshot.DetectorProgress.Total > 0 || snapshot.DetectorProgress.Completed > 0 || snapshot.DetectorProgress.Failed > 0 || snapshot.DetectorProgress.ActiveDetector != "" {
		detectorProgress := snapshot.DetectorProgress
		t.status.DetectorProgress = &detectorProgress
	}
}

func (t *scanStatusTracker) resumeHintLocked() string {
	if t == nil || t.status.Status != state.ScanStatusInterrupted {
		return ""
	}
	if len(t.targets) == 0 {
		return ""
	}
	for _, target := range t.targets {
		if strings.TrimSpace(target.Mode) != "org" {
			return ""
		}
	}
	return "rerun the same org scan with --resume and the same --state path"
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

func elapsedSecondsFromStartedAt(startedAt string, now time.Time) int64 {
	startedAt = strings.TrimSpace(startedAt)
	if startedAt == "" || now.IsZero() {
		return 0
	}
	parsed, err := time.Parse(time.RFC3339, startedAt)
	if err != nil || now.Before(parsed) {
		return 0
	}
	return int64(now.Sub(parsed).Seconds())
}
