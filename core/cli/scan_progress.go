package cli

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type scanProgressReporter struct {
	enabled bool
	stderr  io.Writer
	mu      sync.Mutex
}

func newScanProgressReporter(enabled bool, stderr io.Writer) *scanProgressReporter {
	return &scanProgressReporter{
		enabled: enabled,
		stderr:  stderr,
	}
}

func (r *scanProgressReporter) RepoDiscovery(org string, total int) {
	r.add("progress target=org org=%s event=repo_discovery repo_total=%d", strings.TrimSpace(org), total)
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
