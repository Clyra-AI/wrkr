package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type scanProgressReporter struct {
	enabled      bool
	stderr       io.Writer
	mu           sync.Mutex
	phaseStarted map[string]time.Time
	repoTotal    int
	completed    int
	failed       int
}

func newScanProgressReporter(enabled bool, stderr io.Writer) *scanProgressReporter {
	return &scanProgressReporter{
		enabled:      enabled,
		stderr:       stderr,
		phaseStarted: map[string]time.Time{},
	}
}

func (r *scanProgressReporter) RepoDiscovery(org string, total int) {
	r.setRepoCounts(total, 0, 0)
	r.add("progress target=org org=%s event=repo_discovery repo_total=%d", strings.TrimSpace(org), total)
}

func (r *scanProgressReporter) PathDiscovery(root string, total int) {
	r.setRepoCounts(total, 0, 0)
	r.add("progress target=path path=%s event=repo_discovery repo_total=%d", strings.TrimSpace(root), total)
}

func (r *scanProgressReporter) PathRepo(root string, index, total int, repo string) {
	r.setRepoCounts(total, index, 0)
	r.add(
		"progress target=path path=%s event=repo_discovered repo_index=%d repo_total=%d repo=%s",
		strings.TrimSpace(root),
		index,
		total,
		strings.TrimSpace(repo),
	)
}

func (r *scanProgressReporter) RepoMaterialize(org string, index, total int, repo string) {
	r.add(
		"progress target=org org=%s event=repo_materialize repo_index=%d repo_total=%d repo=%s",
		strings.TrimSpace(org),
		index,
		total,
		strings.TrimSpace(repo),
	)
}

func (r *scanProgressReporter) RepoMaterializeDone(org string, completed, total int, repo, status string) {
	r.updateMaterializeDone(total, completed, status)
	r.add(
		"progress target=org org=%s event=repo_materialize_done completed=%d repo_total=%d repo=%s status=%s",
		strings.TrimSpace(org),
		completed,
		total,
		strings.TrimSpace(repo),
		strings.TrimSpace(status),
	)
}

func (r *scanProgressReporter) ScanPhase(targetMode, targetValue, phase string) {
	targetMode = strings.TrimSpace(targetMode)
	targetValue = strings.TrimSpace(targetValue)
	if targetMode == "" {
		return
	}
	targetKey := targetMode
	if targetMode == "multi" {
		targetKey = "target_set"
	}
	durationMillis, repoTotal, completed, failed := r.recordPhaseTiming(phase)
	r.add(
		"progress target=%s %s=%s event=scan_phase phase=%s duration_ms=%d repo_total=%d completed=%d failed=%d",
		targetMode,
		targetKey,
		targetValue,
		strings.TrimSpace(phase),
		durationMillis,
		repoTotal,
		completed,
		failed,
	)
}

func (r *scanProgressReporter) Retry(org string, attempt int, delay time.Duration, statusCode int) {
	r.add(
		"progress target=org org=%s event=retry attempt=%d delay_ms=%d status=%d",
		strings.TrimSpace(org),
		attempt,
		delay.Milliseconds(),
		statusCode,
	)
}

func (r *scanProgressReporter) Cooldown(org string, delay time.Duration, until time.Time) {
	if until.IsZero() {
		r.add("progress target=org org=%s event=cooldown wait_ms=%d", strings.TrimSpace(org), delay.Milliseconds())
		return
	}
	r.add(
		"progress target=org org=%s event=cooldown wait_ms=%d until=%s",
		strings.TrimSpace(org),
		delay.Milliseconds(),
		until.UTC().Format(time.RFC3339),
	)
}

func (r *scanProgressReporter) Resume(org string, total, completed, pending int) {
	r.add(
		"progress target=org org=%s event=resume repo_total=%d completed=%d pending=%d",
		strings.TrimSpace(org),
		total,
		completed,
		pending,
	)
}

func (r *scanProgressReporter) Complete(org string, total, completed, failed int) {
	r.setRepoCounts(total, completed, failed)
	r.add(
		"progress target=org org=%s event=complete repo_total=%d completed=%d failed=%d",
		strings.TrimSpace(org),
		total,
		completed,
		failed,
	)
}

func (r *scanProgressReporter) Flush() {
	// Progress now streams as events happen; Flush remains as a no-op for callers.
}

func (r *scanProgressReporter) add(format string, args ...any) {
	if r == nil || !r.enabled || r.stderr == nil {
		return
	}
	line := fmt.Sprintf(format, args...)
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = fmt.Fprintln(r.stderr, line)
}

func (r *scanProgressReporter) setRepoCounts(total, completed, failed int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repoTotal = total
	r.completed = completed
	r.failed = failed
}

func (r *scanProgressReporter) updateMaterializeDone(total, completed int, status string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repoTotal = total
	r.completed = completed
	if strings.TrimSpace(status) == "failed" {
		r.failed++
	}
}

func (r *scanProgressReporter) recordPhaseTiming(rawPhase string) (int64, int, int, int) {
	if r == nil {
		return 0, 0, 0, 0
	}
	phase := strings.TrimSpace(rawPhase)
	base := strings.TrimSuffix(strings.TrimSuffix(phase, "_start"), "_complete")
	if base == "" {
		return 0, 0, 0, 0
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.HasSuffix(phase, "_start") {
		r.phaseStarted[base] = now
		return 0, r.repoTotal, r.completed, r.failed
	}
	started := r.phaseStarted[base]
	if started.IsZero() {
		return 0, r.repoTotal, r.completed, r.failed
	}
	return now.Sub(started).Milliseconds(), r.repoTotal, r.completed, r.failed
}
