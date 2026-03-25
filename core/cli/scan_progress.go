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
	lines   []string
	mu      sync.Mutex
}

func newScanProgressReporter(enabled bool, stderr io.Writer) *scanProgressReporter {
	return &scanProgressReporter{
		enabled: enabled,
		stderr:  stderr,
		lines:   []string{},
	}
}

func (r *scanProgressReporter) RepoDiscovery(total int) {
	r.add("progress target=org event=repo_discovery repo_total=%d", total)
}

func (r *scanProgressReporter) RepoMaterialize(index, total int, repo string) {
	r.add(
		"progress target=org event=repo_materialize repo_index=%d repo_total=%d repo=%s",
		index,
		total,
		strings.TrimSpace(repo),
	)
}

func (r *scanProgressReporter) Retry(attempt int, delay time.Duration, statusCode int) {
	r.add(
		"progress target=org event=retry attempt=%d delay_ms=%d status=%d",
		attempt,
		delay.Milliseconds(),
		statusCode,
	)
}

func (r *scanProgressReporter) Cooldown(delay time.Duration, until time.Time) {
	if until.IsZero() {
		r.add("progress target=org event=cooldown wait_ms=%d", delay.Milliseconds())
		return
	}
	r.add(
		"progress target=org event=cooldown wait_ms=%d until=%s",
		delay.Milliseconds(),
		until.UTC().Format(time.RFC3339),
	)
}

func (r *scanProgressReporter) Resume(total, completed, pending int) {
	r.add(
		"progress target=org event=resume repo_total=%d completed=%d pending=%d",
		total,
		completed,
		pending,
	)
}

func (r *scanProgressReporter) Complete(total, completed, failed int) {
	r.add(
		"progress target=org event=complete repo_total=%d completed=%d failed=%d",
		total,
		completed,
		failed,
	)
}

func (r *scanProgressReporter) Flush() {
	if r == nil || !r.enabled || r.stderr == nil {
		return
	}
	r.mu.Lock()
	lines := append([]string(nil), r.lines...)
	r.lines = nil
	r.mu.Unlock()
	for _, line := range lines {
		_, _ = fmt.Fprintln(r.stderr, line)
	}
}

func (r *scanProgressReporter) add(format string, args ...any) {
	if r == nil || !r.enabled {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}
