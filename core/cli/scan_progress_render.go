package cli

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

type scanProgressCapabilities struct {
	Interactive bool
	SupportsBar bool
}

type scanProgressCapabilityProvider interface {
	ScanProgressCapabilities() scanProgressCapabilities
}

type scanProgressRenderer interface {
	Render(snapshot scanProgressSnapshot, update scanProgressUpdate)
	Flush()
}

func newScanProgressRenderer(mode scanProgressMode, stderr io.Writer) scanProgressRenderer {
	if stderr == nil {
		return nil
	}
	switch mode {
	case scanProgressModeBar:
		return &scanProgressBarRenderer{stderr: stderr}
	case scanProgressModePlain:
		return &scanProgressPlainRenderer{stderr: stderr}
	case scanProgressModeEvents:
		return &scanProgressEventRenderer{stderr: stderr}
	default:
		return nil
	}
}

func detectScanProgressCapabilities(stderr io.Writer) scanProgressCapabilities {
	if provider, ok := stderr.(scanProgressCapabilityProvider); ok {
		capabilities := provider.ScanProgressCapabilities()
		if !capabilities.Interactive {
			capabilities.SupportsBar = false
			return capabilities
		}
		if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") || strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
			capabilities.SupportsBar = false
		}
		return capabilities
	}
	file, ok := stderr.(*os.File)
	if !ok {
		return scanProgressCapabilities{}
	}
	info, err := file.Stat()
	if err != nil {
		return scanProgressCapabilities{}
	}
	interactive := info.Mode()&os.ModeCharDevice != 0
	if !interactive {
		return scanProgressCapabilities{}
	}
	if runtime.GOOS == "windows" {
		return scanProgressCapabilities{Interactive: true, SupportsBar: false}
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("TERM")), "dumb") {
		return scanProgressCapabilities{Interactive: true, SupportsBar: false}
	}
	if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
		return scanProgressCapabilities{Interactive: true, SupportsBar: false}
	}
	return scanProgressCapabilities{Interactive: true, SupportsBar: true}
}

type scanProgressBarRenderer struct {
	stderr  io.Writer
	lastLen int
	dirty   bool
}

func (r *scanProgressBarRenderer) Render(snapshot scanProgressSnapshot, update scanProgressUpdate) {
	if r == nil || r.stderr == nil {
		return
	}
	switch update.Kind {
	case "notice":
		_, _ = fmt.Fprintln(r.stderr, update.Message)
		return
	case "footer":
		r.Flush()
		_, _ = fmt.Fprintln(r.stderr, formatScanProgressFooter(update.Footer))
		return
	}
	line := formatScanProgressBarLine(snapshot)
	padding := ""
	if len(line) < r.lastLen {
		padding = strings.Repeat(" ", r.lastLen-len(line))
	}
	_, _ = fmt.Fprintf(r.stderr, "\r%s%s", line, padding)
	r.lastLen = len(line)
	r.dirty = true
}

func (r *scanProgressBarRenderer) Flush() {
	if r == nil || r.stderr == nil || !r.dirty {
		return
	}
	_, _ = fmt.Fprintln(r.stderr)
	r.dirty = false
	r.lastLen = 0
}

type scanProgressPlainRenderer struct {
	stderr io.Writer
}

func (r *scanProgressPlainRenderer) Render(snapshot scanProgressSnapshot, update scanProgressUpdate) {
	if r == nil || r.stderr == nil {
		return
	}
	switch update.Kind {
	case "notice":
		_, _ = fmt.Fprintln(r.stderr, update.Message)
	case "footer":
		_, _ = fmt.Fprintln(r.stderr, formatScanProgressFooter(update.Footer))
	default:
		_, _ = fmt.Fprintln(r.stderr, formatScanProgressPlainLine(snapshot))
	}
}

func (r *scanProgressPlainRenderer) Flush() {}

type scanProgressEventRenderer struct {
	stderr io.Writer
}

func (r *scanProgressEventRenderer) Render(snapshot scanProgressSnapshot, update scanProgressUpdate) {
	if r == nil || r.stderr == nil {
		return
	}
	line := formatScanProgressEventLine(snapshot, update)
	if strings.TrimSpace(line) == "" {
		return
	}
	_, _ = fmt.Fprintln(r.stderr, line)
}

func (r *scanProgressEventRenderer) Flush() {}

func formatScanProgressBarLine(snapshot scanProgressSnapshot) string {
	const barWidth = 20
	filled := snapshot.ProgressPercent * barWidth / 100
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("#", filled) + strings.Repeat(".", barWidth-filled)
	parts := []string{
		fmt.Sprintf("scan [%s] %3d%%", bar, snapshot.ProgressPercent),
		"phase=" + fallbackForExplain(snapshot.PhaseProgress.Phase, "unknown"),
	}
	if snapshot.RepoProgress.Total > 0 {
		parts = append(parts, fmt.Sprintf("repos=%d/%d", snapshot.RepoProgress.Completed, snapshot.RepoProgress.Total))
	}
	if snapshot.RepoProgress.Failed > 0 {
		parts = append(parts, fmt.Sprintf("failed=%d", snapshot.RepoProgress.Failed))
	}
	if snapshot.DetectorProgress.Total > 0 {
		parts = append(parts, fmt.Sprintf("detectors=%d/%d", snapshot.DetectorProgress.Completed, snapshot.DetectorProgress.Total))
	}
	if strings.TrimSpace(snapshot.DetectorProgress.ActiveDetector) != "" {
		parts = append(parts, "detector="+snapshot.DetectorProgress.ActiveDetector)
	}
	parts = append(parts, fmt.Sprintf("elapsed=%ds", snapshot.ElapsedSeconds))
	return strings.Join(parts, " ")
}

func formatScanProgressPlainLine(snapshot scanProgressSnapshot) string {
	parts := []string{
		"scan",
		"progress",
		fmt.Sprintf("progress=%d%%", snapshot.ProgressPercent),
		"phase=" + fallbackForExplain(snapshot.PhaseProgress.Phase, "unknown"),
	}
	if snapshot.RepoProgress.Total > 0 {
		parts = append(parts, fmt.Sprintf("repos=%d/%d", snapshot.RepoProgress.Completed, snapshot.RepoProgress.Total))
	}
	if snapshot.RepoProgress.Failed > 0 {
		parts = append(parts, fmt.Sprintf("failed=%d", snapshot.RepoProgress.Failed))
	}
	if snapshot.DetectorProgress.Total > 0 {
		parts = append(parts, fmt.Sprintf("detectors=%d/%d", snapshot.DetectorProgress.Completed, snapshot.DetectorProgress.Total))
	}
	if strings.TrimSpace(snapshot.DetectorProgress.ActiveDetector) != "" {
		parts = append(parts, "detector="+snapshot.DetectorProgress.ActiveDetector)
	}
	parts = append(parts, fmt.Sprintf("elapsed=%ds", snapshot.ElapsedSeconds))
	if strings.TrimSpace(snapshot.ProgressMessage) != "" {
		parts = append(parts, fmt.Sprintf("message=%q", snapshot.ProgressMessage))
	}
	return strings.Join(parts, " ")
}

func formatScanProgressEventLine(snapshot scanProgressSnapshot, update scanProgressUpdate) string {
	targetMode, targetKey, targetValue := scanProgressLabelParts(update.TargetMode, update.TargetValue)
	if targetMode == "" {
		targetMode = fallbackForExplain(snapshot.TargetMode, "")
		targetKey, targetValue = scanProgressTargetKey(targetMode), snapshot.TargetValue
	}
	if targetMode == "" {
		return ""
	}
	base := []string{
		"progress",
		"target=" + targetMode,
		targetKey + "=" + targetValue,
	}
	switch update.Kind {
	case "repo_discovery":
		return strings.Join(append(base,
			"event=repo_discovery",
			fmt.Sprintf("repo_total=%d", update.RepoTotal),
		), " ")
	case "repo_discovered":
		return strings.Join(append(base,
			"event=repo_discovered",
			fmt.Sprintf("repo_index=%d", update.RepoIndex),
			fmt.Sprintf("repo_total=%d", update.RepoTotal),
			"repo="+update.Repo,
		), " ")
	case "repo_materialize":
		return strings.Join(append(base,
			"event=repo_materialize",
			fmt.Sprintf("repo_index=%d", update.RepoIndex),
			fmt.Sprintf("repo_total=%d", update.RepoTotal),
			"repo="+update.Repo,
		), " ")
	case "repo_materialize_done":
		return strings.Join(append(base,
			"event=repo_materialize_done",
			fmt.Sprintf("completed=%d", update.Completed),
			fmt.Sprintf("repo_total=%d", update.RepoTotal),
			"repo="+update.Repo,
			"status="+fallbackForExplain(update.Status, "ok"),
		), " ")
	case "scan_phase":
		return strings.Join(append(base,
			"event=scan_phase",
			"phase="+update.Phase,
			fmt.Sprintf("duration_ms=%d", update.DurationMillis),
			fmt.Sprintf("repo_total=%d", snapshot.RepoProgress.Total),
			fmt.Sprintf("completed=%d", snapshot.RepoProgress.Completed),
			fmt.Sprintf("failed=%d", snapshot.RepoProgress.Failed),
		), " ")
	case "retry":
		return strings.Join(append(base,
			"event=retry",
			fmt.Sprintf("attempt=%d", update.Attempt),
			fmt.Sprintf("delay_ms=%d", update.Delay.Milliseconds()),
			fmt.Sprintf("status=%d", update.StatusCode),
		), " ")
	case "cooldown":
		fields := append(base,
			"event=cooldown",
			fmt.Sprintf("wait_ms=%d", update.Delay.Milliseconds()),
		)
		if !update.Until.IsZero() {
			fields = append(fields, "until="+update.Until.UTC().Format(timeRFC3339()))
		}
		return strings.Join(fields, " ")
	case "resume":
		return strings.Join(append(base,
			"event=resume",
			fmt.Sprintf("repo_total=%d", update.RepoTotal),
			fmt.Sprintf("completed=%d", update.Completed),
			fmt.Sprintf("pending=%d", update.Pending),
		), " ")
	case "complete":
		return strings.Join(append(base,
			"event=complete",
			fmt.Sprintf("repo_total=%d", update.RepoTotal),
			fmt.Sprintf("completed=%d", update.Completed),
			fmt.Sprintf("failed=%d", update.Failed),
		), " ")
	case "detector_start":
		return strings.Join(append(base,
			"event=detector_start",
			"detector="+update.Detector,
			fmt.Sprintf("detector_index=%d", update.DetectorIndex),
			fmt.Sprintf("detector_total=%d", update.DetectorTotal),
			"repo="+fallbackForExplain(update.Repo, "unknown"),
		), " ")
	case "detector_complete":
		return strings.Join(append(base,
			"event=detector_complete",
			"detector="+update.Detector,
			fmt.Sprintf("completed=%d", update.DetectorIndex),
			fmt.Sprintf("detector_total=%d", update.DetectorTotal),
			"repo="+fallbackForExplain(update.Repo, "unknown"),
			"status="+fallbackForExplain(update.Status, "ok"),
		), " ")
	case "heartbeat":
		fields := append(base,
			"event=heartbeat",
			"phase="+fallbackForExplain(snapshot.PhaseProgress.Phase, "unknown"),
			fmt.Sprintf("progress_percent=%d", snapshot.ProgressPercent),
			fmt.Sprintf("repo_total=%d", snapshot.RepoProgress.Total),
			fmt.Sprintf("completed=%d", snapshot.RepoProgress.Completed),
			fmt.Sprintf("failed=%d", snapshot.RepoProgress.Failed),
			fmt.Sprintf("elapsed_seconds=%d", snapshot.ElapsedSeconds),
		)
		if snapshot.DetectorProgress.Total > 0 {
			fields = append(fields,
				fmt.Sprintf("detector_total=%d", snapshot.DetectorProgress.Total),
				fmt.Sprintf("detector_completed=%d", snapshot.DetectorProgress.Completed),
				fmt.Sprintf("detector_failed=%d", snapshot.DetectorProgress.Failed),
			)
		}
		if strings.TrimSpace(snapshot.DetectorProgress.ActiveDetector) != "" {
			fields = append(fields, "active_detector="+snapshot.DetectorProgress.ActiveDetector)
		}
		return strings.Join(fields, " ")
	case "footer":
		fields := append(base,
			"event=footer",
			"status="+fallbackForExplain(update.Footer.Status, "unknown"),
			"current_phase="+fallbackForExplain(update.Footer.CurrentPhase, "unknown"),
			"last_successful_phase="+fallbackForExplain(update.Footer.LastSuccessfulPhase, "unknown"),
			fmt.Sprintf("partial_result=%t", update.Footer.PartialResult),
			fmt.Sprintf("repo_total=%d", update.Footer.RepoTotal),
			fmt.Sprintf("completed=%d", update.Footer.ReposCompleted),
			fmt.Sprintf("failed=%d", update.Footer.ReposFailed),
			fmt.Sprintf("progress_percent=%d", update.Footer.ProgressPercent),
			fmt.Sprintf("elapsed_seconds=%d", update.Footer.ElapsedSeconds),
		)
		if strings.TrimSpace(update.Footer.ResumeHint) != "" {
			fields = append(fields, "resume_hint=true")
		}
		if len(update.Footer.ArtifactPaths) > 0 {
			fields = append(fields, "artifacts="+strings.Join(update.Footer.ArtifactPaths, ","))
		}
		return strings.Join(fields, " ")
	default:
		return ""
	}
}

func scanProgressLabelParts(targetMode, targetValue string) (string, string, string) {
	mode := strings.TrimSpace(targetMode)
	value := strings.TrimSpace(targetValue)
	if mode == "" {
		return "", "", ""
	}
	return mode, scanProgressTargetKey(mode), fallbackForExplain(value, mode)
}

func scanProgressTargetKey(mode string) string {
	switch strings.TrimSpace(mode) {
	case "org":
		return "org"
	case "path":
		return "path"
	case "repo":
		return "repo"
	case "my_setup":
		return "target"
	case "multi":
		return "target_set"
	default:
		return "target"
	}
}

func timeRFC3339() string {
	return "2006-01-02T15:04:05Z07:00"
}
