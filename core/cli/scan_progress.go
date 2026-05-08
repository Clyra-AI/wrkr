package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/state"
)

type scanProgressMode string

const (
	scanProgressModeAuto   scanProgressMode = "auto"
	scanProgressModeBar    scanProgressMode = "bar"
	scanProgressModePlain  scanProgressMode = "plain"
	scanProgressModeEvents scanProgressMode = "events"
	scanProgressModeNone   scanProgressMode = "none"
)

const defaultScanProgressHeartbeatInterval = 5 * time.Second

type scanProgressReporterOptions struct {
	RequestedMode     scanProgressMode
	JSONOutput        bool
	Stderr            io.Writer
	StartedAt         time.Time
	TargetMode        string
	TargetValue       string
	StatusSink        func(scanProgressSnapshot)
	HeartbeatInterval time.Duration
}

type scanProgressHeartbeatIntervalProvider interface {
	ScanProgressHeartbeatInterval() time.Duration
}

type scanProgressSnapshot struct {
	TargetMode       string
	TargetValue      string
	ProgressPercent  int
	ProgressMessage  string
	LastProgressAt   time.Time
	ElapsedSeconds   int64
	PhaseProgress    state.ScanPhaseProgress
	RepoProgress     state.ScanRepoProgress
	DetectorProgress state.ScanDetectorProgress
}

type scanProgressFooter struct {
	Status              string
	CurrentPhase        string
	LastSuccessfulPhase string
	ProgressPercent     int
	ProgressMessage     string
	ElapsedSeconds      int64
	PartialResult       bool
	RepoTotal           int
	ReposCompleted      int
	ReposSucceeded      int
	ReposFailed         int
	DetectorProgress    *state.ScanDetectorProgress
	ArtifactPaths       []string
	ResumeHint          string
}

type scanProgressUpdate struct {
	Kind           string
	TargetMode     string
	TargetValue    string
	Phase          string
	DurationMillis int64
	Repo           string
	Status         string
	RepoIndex      int
	RepoTotal      int
	Completed      int
	Succeeded      int
	Failed         int
	Pending        int
	Attempt        int
	Delay          time.Duration
	StatusCode     int
	Until          time.Time
	Detector       string
	DetectorIndex  int
	DetectorTotal  int
	Message        string
	Footer         scanProgressFooter
}

type scanProgressState struct {
	startedAt           time.Time
	currentPhase        string
	lastSuccessfulPhase string
	lastProgressAt      time.Time
	progressMessage     string
	progressPercent     int
	phaseProgress       state.ScanPhaseProgress
	repoProgress        state.ScanRepoProgress
	detectorProgress    state.ScanDetectorProgress
	phaseStarted        map[string]time.Time
}

type scanProgressReporter struct {
	mu                sync.Mutex
	renderMu          sync.Mutex
	mode              scanProgressMode
	renderer          scanProgressRenderer
	statusSink        func(scanProgressSnapshot)
	heartbeatInterval time.Duration
	nowFn             func() time.Time
	targetMode        string
	targetValue       string
	state             scanProgressState
	started           bool
	stopOnce          sync.Once
	stopCh            chan struct{}
	doneCh            chan struct{}
	pendingNotice     string
}

func parseScanProgressMode(raw string) (scanProgressMode, error) {
	switch mode := scanProgressMode(strings.TrimSpace(raw)); mode {
	case "", scanProgressModeAuto:
		return scanProgressModeAuto, nil
	case scanProgressModeBar, scanProgressModePlain, scanProgressModeEvents, scanProgressModeNone:
		return mode, nil
	default:
		return "", fmt.Errorf("--progress must be one of auto, bar, plain, events, none")
	}
}

func newScanProgressReporter(opts scanProgressReporterOptions) *scanProgressReporter {
	if opts.HeartbeatInterval <= 0 {
		opts.HeartbeatInterval = defaultScanProgressHeartbeatInterval
	}
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now().UTC()
	}
	resolvedMode, notice := resolveScanProgressMode(opts.RequestedMode, opts.JSONOutput, opts.Stderr)
	renderer := newScanProgressRenderer(resolvedMode, opts.Stderr)
	return &scanProgressReporter{
		mode:              resolvedMode,
		renderer:          renderer,
		statusSink:        opts.StatusSink,
		heartbeatInterval: opts.HeartbeatInterval,
		nowFn:             time.Now,
		targetMode:        strings.TrimSpace(opts.TargetMode),
		targetValue:       strings.TrimSpace(opts.TargetValue),
		state: scanProgressState{
			startedAt:    opts.StartedAt.UTC(),
			phaseStarted: map[string]time.Time{},
		},
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		pendingNotice: notice,
	}
}

func (r *scanProgressReporter) Start(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go func() {
		defer close(r.doneCh)
		if r.heartbeatInterval <= 0 {
			<-ctx.Done()
			return
		}
		ticker := time.NewTicker(r.heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				r.Heartbeat()
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			}
		}
	}()
}

func (r *scanProgressReporter) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	started := r.started
	r.mu.Unlock()
	if !started {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
		<-r.doneCh
	})
}

func (r *scanProgressReporter) RepoDiscovery(org string, total int) {
	r.emit(scanProgressUpdate{
		Kind:        "repo_discovery",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		RepoTotal:   total,
		Message:     fmt.Sprintf("discovered %d repository target(s)", total),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.repoProgress = state.ScanRepoProgress{Total: total, Pending: total}
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) PathDiscovery(root string, total int) {
	r.emit(scanProgressUpdate{
		Kind:        "repo_discovery",
		TargetMode:  "path",
		TargetValue: strings.TrimSpace(root),
		RepoTotal:   total,
		Message:     fmt.Sprintf("discovered %d local repository target(s)", total),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.repoProgress = state.ScanRepoProgress{Total: total, Pending: total}
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) PathRepo(root string, index, total int, repo string) {
	r.emit(scanProgressUpdate{
		Kind:        "repo_discovered",
		TargetMode:  "path",
		TargetValue: strings.TrimSpace(root),
		Repo:        strings.TrimSpace(repo),
		RepoIndex:   index,
		RepoTotal:   total,
		Message:     fmt.Sprintf("queued local repo %s (%d/%d)", strings.TrimSpace(repo), index, total),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.repoProgress = state.ScanRepoProgress{
			Total:     total,
			Succeeded: index,
			Completed: index,
			Failed:    0,
			Pending:   maxProgressCount(total-index, 0),
		}
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) RepoMaterialize(org string, index, total int, repo string) {
	r.emit(scanProgressUpdate{
		Kind:        "repo_materialize",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		Repo:        strings.TrimSpace(repo),
		RepoIndex:   index,
		RepoTotal:   total,
		Message:     fmt.Sprintf("materializing %s (%d/%d)", strings.TrimSpace(repo), index, total),
	}, func(now time.Time) scanProgressSnapshot {
		if total > 0 {
			r.state.repoProgress.Total = total
			r.state.repoProgress.Pending = maxProgressCount(total-r.state.repoProgress.Completed, 0)
		}
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) RepoMaterializeDone(org string, succeeded, failed, total int, repo, status string) {
	completed := succeeded + failed
	r.emit(scanProgressUpdate{
		Kind:        "repo_materialize_done",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		Repo:        strings.TrimSpace(repo),
		RepoTotal:   total,
		Completed:   completed,
		Succeeded:   succeeded,
		Failed:      failed,
		Status:      strings.TrimSpace(status),
		Message:     repoMaterializeDoneMessage(repo, status, completed, total),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.repoProgress = state.ScanRepoProgress{
			Total:     total,
			Succeeded: succeeded,
			Completed: completed,
			Failed:    failed,
			Pending:   maxProgressCount(total-completed, 0),
		}
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) ScanPhase(targetMode, targetValue, phase string) {
	if r == nil {
		return
	}
	targetMode = strings.TrimSpace(targetMode)
	targetValue = strings.TrimSpace(targetValue)
	basePhase := normalizeScanStatusPhase(phase)
	now := r.nowFn().UTC()
	r.mu.Lock()
	durationMillis := r.recordPhaseTimingLocked(strings.TrimSpace(phase), now)
	r.state.currentPhase = basePhase
	r.state.progressMessage = phaseProgressMessage(phase)
	if strings.HasSuffix(strings.TrimSpace(phase), "_complete") {
		r.state.lastSuccessfulPhase = basePhase
	}
	r.recomputePercentLocked()
	snapshot := r.snapshotLocked(now)
	renderer := r.renderer
	statusSink := r.statusSink
	notice := r.pendingNotice
	r.pendingNotice = ""
	r.mu.Unlock()

	if statusSink != nil {
		statusSink(snapshot)
	}
	if renderer != nil {
		updates := make([]scanProgressUpdate, 0, 2)
		if notice != "" {
			updates = append(updates, scanProgressUpdate{
				Kind:        "notice",
				TargetMode:  targetMode,
				TargetValue: targetValue,
				Message:     notice,
			})
		}
		updates = append(updates, scanProgressUpdate{
			Kind:           "scan_phase",
			TargetMode:     targetMode,
			TargetValue:    targetValue,
			Phase:          strings.TrimSpace(phase),
			DurationMillis: durationMillis,
			Message:        phaseProgressMessage(phase),
		})
		r.render(snapshot, updates...)
	}
}

func (r *scanProgressReporter) Retry(org string, attempt int, delay time.Duration, statusCode int) {
	r.emit(scanProgressUpdate{
		Kind:        "retry",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		Attempt:     attempt,
		Delay:       delay,
		StatusCode:  statusCode,
		Message:     fmt.Sprintf("retrying after upstream status %d (attempt %d)", statusCode, attempt),
	}, func(now time.Time) scanProgressSnapshot {
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) Cooldown(org string, delay time.Duration, until time.Time) {
	r.emit(scanProgressUpdate{
		Kind:        "cooldown",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		Delay:       delay,
		Until:       until,
		Message:     cooldownProgressMessage(delay, until),
	}, func(now time.Time) scanProgressSnapshot {
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) Resume(org string, total, completed, pending int) {
	r.emit(scanProgressUpdate{
		Kind:        "resume",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		RepoTotal:   total,
		Completed:   completed,
		Succeeded:   completed,
		Pending:     pending,
		Message:     fmt.Sprintf("resumed org scan with %d completed and %d pending repo(s)", completed, pending),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.repoProgress = state.ScanRepoProgress{
			Total:     total,
			Succeeded: completed,
			Completed: completed,
			Failed:    r.state.repoProgress.Failed,
			Pending:   pending,
		}
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) Complete(org string, total, succeeded, failed int) {
	completed := succeeded + failed
	r.emit(scanProgressUpdate{
		Kind:        "complete",
		TargetMode:  "org",
		TargetValue: strings.TrimSpace(org),
		RepoTotal:   total,
		Completed:   completed,
		Succeeded:   succeeded,
		Failed:      failed,
		Message:     fmt.Sprintf("completed source acquisition for %d repo(s)", total),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.repoProgress = state.ScanRepoProgress{
			Total:     total,
			Succeeded: succeeded,
			Completed: completed,
			Failed:    failed,
			Pending:   maxProgressCount(total-completed, 0),
		}
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) DetectorStart(event detect.DetectorProgressEvent) {
	r.emit(scanProgressUpdate{
		Kind:          "detector_start",
		TargetMode:    r.targetMode,
		TargetValue:   r.targetValue,
		Detector:      strings.TrimSpace(event.DetectorID),
		DetectorIndex: event.Index,
		DetectorTotal: event.Total,
		Repo:          strings.TrimSpace(event.Scope.Repo),
		Message:       detectorProgressMessage("start", event),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.detectorProgress.Total = event.Total
		r.state.detectorProgress.ActiveDetector = strings.TrimSpace(event.DetectorID)
		r.state.detectorProgress.Pending = maxProgressCount(event.Total-r.state.detectorProgress.Completed-r.state.detectorProgress.Failed, 0)
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) DetectorComplete(event detect.DetectorProgressEvent) {
	r.emit(scanProgressUpdate{
		Kind:          "detector_complete",
		TargetMode:    r.targetMode,
		TargetValue:   r.targetValue,
		Detector:      strings.TrimSpace(event.DetectorID),
		DetectorIndex: event.Index,
		DetectorTotal: event.Total,
		Repo:          strings.TrimSpace(event.Scope.Repo),
		Status:        "ok",
		Message:       detectorProgressMessage("complete", event),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.detectorProgress.Total = event.Total
		r.state.detectorProgress.Completed = event.Index
		r.state.detectorProgress.Pending = maxProgressCount(event.Total-event.Index-r.state.detectorProgress.Failed, 0)
		r.state.detectorProgress.ActiveDetector = ""
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) DetectorError(event detect.DetectorProgressEvent) {
	r.emit(scanProgressUpdate{
		Kind:          "detector_complete",
		TargetMode:    r.targetMode,
		TargetValue:   r.targetValue,
		Detector:      strings.TrimSpace(event.DetectorID),
		DetectorIndex: event.Index,
		DetectorTotal: event.Total,
		Repo:          strings.TrimSpace(event.Scope.Repo),
		Status:        "failed",
		Message:       detectorProgressMessage("error", event),
	}, func(now time.Time) scanProgressSnapshot {
		r.state.detectorProgress.Total = event.Total
		r.state.detectorProgress.Completed = event.Index
		r.state.detectorProgress.Failed++
		r.state.detectorProgress.Pending = maxProgressCount(event.Total-event.Index-r.state.detectorProgress.Failed, 0)
		r.state.detectorProgress.ActiveDetector = ""
		r.recomputePercentLocked()
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) Heartbeat() {
	r.emit(scanProgressUpdate{
		Kind:        "heartbeat",
		TargetMode:  r.targetMode,
		TargetValue: r.targetValue,
	}, func(now time.Time) scanProgressSnapshot {
		return r.snapshotLocked(now)
	})
}

func (r *scanProgressReporter) Flush() {
	if r == nil {
		return
	}
	r.flush()
}

func (r *scanProgressReporter) Finish(footer scanProgressFooter) {
	if r == nil {
		return
	}
	r.renderAndFlush(r.snapshot(), scanProgressUpdate{
		Kind:        "footer",
		TargetMode:  r.targetMode,
		TargetValue: r.targetValue,
		Footer:      footer,
	})
}

func (r *scanProgressReporter) snapshot() scanProgressSnapshot {
	if r == nil {
		return scanProgressSnapshot{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotLocked(r.nowFn())
}

func (r *scanProgressReporter) emit(update scanProgressUpdate, mutate func(time.Time) scanProgressSnapshot) {
	if r == nil {
		return
	}
	now := r.nowFn().UTC()
	r.mu.Lock()
	if strings.TrimSpace(update.TargetMode) == "" {
		update.TargetMode = r.targetMode
	}
	if strings.TrimSpace(update.TargetValue) == "" {
		update.TargetValue = r.targetValue
	}
	if strings.TrimSpace(update.Message) != "" {
		r.state.progressMessage = strings.TrimSpace(update.Message)
	}
	snapshot := mutate(now)
	updates := make([]scanProgressUpdate, 0, 2)
	if r.pendingNotice != "" && r.renderer != nil {
		updates = append(updates, scanProgressUpdate{
			Kind:        "notice",
			TargetMode:  update.TargetMode,
			TargetValue: update.TargetValue,
			Message:     r.pendingNotice,
		})
		r.pendingNotice = ""
	}
	renderer := r.renderer
	statusSink := r.statusSink
	if renderer != nil {
		updates = append(updates, update)
	}
	r.mu.Unlock()

	if statusSink != nil {
		statusSink(snapshot)
	}
	if renderer != nil {
		r.render(snapshot, updates...)
	}
}

func (r *scanProgressReporter) render(snapshot scanProgressSnapshot, updates ...scanProgressUpdate) {
	if r == nil || r.renderer == nil || len(updates) == 0 {
		return
	}
	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	for _, update := range updates {
		r.renderer.Render(snapshot, update)
	}
}

func (r *scanProgressReporter) flush() {
	if r == nil || r.renderer == nil {
		return
	}
	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	r.renderer.Flush()
}

func (r *scanProgressReporter) renderAndFlush(snapshot scanProgressSnapshot, update scanProgressUpdate) {
	if r == nil || r.renderer == nil {
		return
	}
	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	r.renderer.Render(snapshot, update)
	r.renderer.Flush()
}

func (r *scanProgressReporter) snapshotLocked(now time.Time) scanProgressSnapshot {
	r.state.lastProgressAt = now
	r.state.progressMessage = strings.TrimSpace(r.state.progressMessage)
	return scanProgressSnapshot{
		TargetMode:      r.targetMode,
		TargetValue:     r.targetValue,
		ProgressPercent: r.state.progressPercent,
		ProgressMessage: r.state.progressMessage,
		LastProgressAt:  now,
		ElapsedSeconds:  elapsedSeconds(r.state.startedAt, now),
		PhaseProgress:   r.state.phaseProgress,
		RepoProgress:    r.state.repoProgress,
		DetectorProgress: state.ScanDetectorProgress{
			Total:          r.state.detectorProgress.Total,
			Completed:      r.state.detectorProgress.Completed,
			Failed:         r.state.detectorProgress.Failed,
			Pending:        maxProgressCount(r.state.detectorProgress.Total-r.state.detectorProgress.Completed-r.state.detectorProgress.Failed, 0),
			ActiveDetector: strings.TrimSpace(r.state.detectorProgress.ActiveDetector),
		},
	}
}

func (r *scanProgressReporter) recordPhaseTimingLocked(rawPhase string, now time.Time) int64 {
	phase := strings.TrimSpace(rawPhase)
	base := normalizeScanStatusPhase(phase)
	if base == "" {
		return 0
	}
	if strings.HasSuffix(phase, "_start") {
		r.state.phaseStarted[base] = now
		return 0
	}
	started := r.state.phaseStarted[base]
	if started.IsZero() {
		return 0
	}
	return now.Sub(started).Milliseconds()
}

func (r *scanProgressReporter) recomputePercentLocked() {
	phase := strings.TrimSpace(r.state.currentPhase)
	if phase == "" {
		r.state.phaseProgress = state.ScanPhaseProgress{}
		return
	}
	overallPercent, phasePercent := computeScanProgressPercent(phase, r.state.repoProgress, r.state.detectorProgress)
	if overallPercent < r.state.progressPercent {
		overallPercent = r.state.progressPercent
	}
	r.state.progressPercent = overallPercent
	r.state.phaseProgress = state.ScanPhaseProgress{
		Phase:   phase,
		Percent: phasePercent,
	}
}

func computeScanProgressPercent(phase string, repoProgress state.ScanRepoProgress, detectorProgress state.ScanDetectorProgress) (int, int) {
	switch strings.TrimSpace(phase) {
	case "source_acquire":
		if repoProgress.Total <= 0 {
			return 5, 5
		}
		phasePercent := int(float64(repoProgress.Completed) / float64(repoProgress.Total) * 100)
		return 5 + (phasePercent * 50 / 100), phasePercent
	case "detectors":
		if detectorProgress.Total <= 0 {
			return 55, 5
		}
		phasePercent := int(float64(detectorProgress.Completed) / float64(detectorProgress.Total) * 100)
		return 55 + (phasePercent * 25 / 100), phasePercent
	case "analysis":
		return 80, 10
	case "artifact_commit":
		return 92, 50
	default:
		return 0, 0
	}
}

func resolveScanProgressMode(requested scanProgressMode, jsonOutput bool, stderr io.Writer) (scanProgressMode, string) {
	capabilities := detectScanProgressCapabilities(stderr)
	switch requested {
	case scanProgressModeNone:
		return scanProgressModeNone, ""
	case scanProgressModeEvents:
		return scanProgressModeEvents, ""
	case scanProgressModePlain:
		return scanProgressModePlain, ""
	case scanProgressModeBar:
		if capabilities.SupportsBar {
			return scanProgressModeBar, ""
		}
		return scanProgressModePlain, "scan progress: requested --progress bar but this stderr target cannot safely render an updating bar; using plain progress lines"
	case scanProgressModeAuto, "":
		if jsonOutput {
			return scanProgressModeEvents, ""
		}
		if capabilities.SupportsBar {
			return scanProgressModeBar, ""
		}
		return scanProgressModePlain, ""
	default:
		return scanProgressModePlain, ""
	}
}

func phaseProgressMessage(phase string) string {
	base := normalizeScanStatusPhase(phase)
	switch {
	case strings.HasSuffix(strings.TrimSpace(phase), "_start"):
		return fmt.Sprintf("entered %s phase", base)
	case strings.HasSuffix(strings.TrimSpace(phase), "_complete"):
		return fmt.Sprintf("completed %s phase", base)
	case base != "":
		return fmt.Sprintf("running %s phase", base)
	default:
		return "scan progress updated"
	}
}

func cooldownProgressMessage(delay time.Duration, until time.Time) string {
	if until.IsZero() {
		return fmt.Sprintf("waiting %s before the next hosted source attempt", delay.Round(time.Second))
	}
	return fmt.Sprintf("waiting until %s before the next hosted source attempt", until.UTC().Format(time.RFC3339))
}

func detectorProgressMessage(kind string, event detect.DetectorProgressEvent) string {
	detectorID := strings.TrimSpace(event.DetectorID)
	repo := strings.TrimSpace(event.Scope.Repo)
	switch kind {
	case "start":
		return fmt.Sprintf("running detector %s on %s", detectorID, repo)
	case "error":
		return fmt.Sprintf("detector %s reported a non-fatal error on %s", detectorID, repo)
	default:
		return fmt.Sprintf("completed detector %s on %s", detectorID, repo)
	}
}

func repoMaterializeDoneMessage(repo, status string, completed, total int) string {
	repo = strings.TrimSpace(repo)
	status = strings.TrimSpace(status)
	if status == "failed" {
		return fmt.Sprintf("materialization failed for %s (%d/%d)", repo, completed, total)
	}
	return fmt.Sprintf("materialized %s (%d/%d)", repo, completed, total)
}

func formatScanProgressFooter(footer scanProgressFooter) string {
	parts := []string{
		"scan",
		fmt.Sprintf("status=%s", strings.TrimSpace(footer.Status)),
		fmt.Sprintf("progress=%d%%", footer.ProgressPercent),
		fmt.Sprintf("current_phase=%s", fallbackForExplain(footer.CurrentPhase, "unknown")),
		fmt.Sprintf("last_successful_phase=%s", fallbackForExplain(footer.LastSuccessfulPhase, "unknown")),
		fmt.Sprintf("partial_result=%t", footer.PartialResult),
		fmt.Sprintf("repos=%d/%d", footer.ReposCompleted, footer.RepoTotal),
		fmt.Sprintf("failed=%d", footer.ReposFailed),
		fmt.Sprintf("succeeded=%d", footer.ReposSucceeded),
		fmt.Sprintf("elapsed=%ds", footer.ElapsedSeconds),
	}
	if strings.TrimSpace(footer.ProgressMessage) != "" {
		parts = append(parts, fmt.Sprintf("message=%q", footer.ProgressMessage))
	}
	if footer.DetectorProgress != nil && (footer.DetectorProgress.Total > 0 || footer.DetectorProgress.Completed > 0 || footer.DetectorProgress.Failed > 0 || footer.DetectorProgress.ActiveDetector != "") {
		parts = append(parts, fmt.Sprintf(
			"detectors=%d/%d",
			footer.DetectorProgress.Completed,
			footer.DetectorProgress.Total,
		))
		if strings.TrimSpace(footer.DetectorProgress.ActiveDetector) != "" {
			parts = append(parts, fmt.Sprintf("active_detector=%s", footer.DetectorProgress.ActiveDetector))
		}
	}
	if len(footer.ArtifactPaths) > 0 {
		parts = append(parts, "artifacts="+strings.Join(footer.ArtifactPaths, ","))
	}
	if strings.TrimSpace(footer.ResumeHint) != "" {
		parts = append(parts, fmt.Sprintf("resume_hint=%q", footer.ResumeHint))
	}
	return strings.Join(parts, " ")
}

func elapsedSeconds(startedAt time.Time, now time.Time) int64 {
	if startedAt.IsZero() || now.Before(startedAt) {
		return 0
	}
	return int64(now.Sub(startedAt).Seconds())
}

func maxProgressCount(value int, fallback int) int {
	if value < 0 {
		return fallback
	}
	return value
}

func scanProgressHeartbeatInterval(stderr io.Writer) time.Duration {
	provider, ok := stderr.(scanProgressHeartbeatIntervalProvider)
	if !ok {
		return defaultScanProgressHeartbeatInterval
	}
	interval := provider.ScanProgressHeartbeatInterval()
	if interval <= 0 {
		return defaultScanProgressHeartbeatInterval
	}
	return interval
}
