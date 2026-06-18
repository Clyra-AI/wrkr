package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScanProgressModeRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	reposPath := filepath.Join(t.TempDir(), "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--json",
		"--progress", "nonsense",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected invalid input exit, got %d stderr=%q", code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
	if out.Len() != 0 {
		t.Fatalf("expected clean stdout on invalid progress mode, got %q", out.String())
	}
}

func TestScanProgressHelpIncludesFlag(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--help"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected help exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "-progress") {
		t.Fatalf("expected scan help to mention --progress, got %q", errOut.String())
	}
}

func TestScanProgressAutoKeepsJSONStdoutClean(t *testing.T) {
	t.Parallel()

	reposPath := filepath.Join(t.TempDir(), "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--json",
		"--progress", "auto",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
	}
	if strings.Contains(out.String(), "progress target=") {
		t.Fatalf("expected JSON stdout to remain clean, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "progress target=path") {
		t.Fatalf("expected auto JSON mode to preserve structured progress on stderr, got %q", errOut.String())
	}
}

func TestScanQuietSuppressesAllProgressModes(t *testing.T) {
	t.Parallel()

	reposPath := filepath.Join(t.TempDir(), "repos")
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}

	for _, mode := range []string{"auto", "bar", "plain", "events", "none"} {
		t.Run(mode, func(t *testing.T) {
			statePath := filepath.Join(tmp, mode+".json")
			var out bytes.Buffer
			var errOut bytes.Buffer
			code := Run([]string{
				"scan",
				"--path", reposPath,
				"--state", statePath,
				"--json",
				"--quiet",
				"--progress", mode,
			}, &out, &errOut)
			if code != exitSuccess {
				t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "progress ") || strings.Contains(errOut.String(), "scan status=") {
				t.Fatalf("expected --quiet to suppress progress output for mode %s, got %q", mode, errOut.String())
			}
		})
	}
}

func TestScanStatusIncludesProgressFieldsDuringRun(t *testing.T) {
	t.Parallel()

	releaseRepo := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseRepo)
		})
	}
	repoDetailRequested := make(chan struct{})
	var repoDetailOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			repoDetailOnce.Do(func() {
				close(repoDetailRequested)
			})
			<-releaseRepo
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	errOut := newLiveBuffer()
	done := make(chan int, 1)
	go func() {
		done <- Run([]string{
			"scan",
			"--org", "acme",
			"--github-api", server.URL,
			"--state", statePath,
			"--json",
			"--progress", "events",
		}, &out, errOut)
	}()

	doneConsumed := false
	defer func() {
		release()
		if doneConsumed {
			return
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("scan did not exit after test cleanup; stderr=%q", errOut.String())
		}
	}()

	select {
	case <-repoDetailRequested:
	case code := <-done:
		doneConsumed = true
		t.Fatalf("scan exited before status inspection: %d stderr=%q", code, errOut.String())
	case <-time.After(10 * time.Second):
		t.Fatalf("expected repo materialize request before status inspection, got %q", errOut.String())
	}

	status := waitForActiveScanStatus(t, statePath, 10*time.Second)
	if status["status"] != "running" {
		t.Fatalf("expected running status during active scan, got %v", status)
	}
	if status["current_phase"] != "source_acquire" {
		t.Fatalf("expected source_acquire current phase during active scan, got %v", status)
	}
	if status["repo_total"] != float64(1) {
		t.Fatalf("expected repo total during active scan, got %v", status)
	}
	if status["progress_percent"] == nil {
		t.Fatalf("expected progress_percent during active scan, got %v", status)
	}
	if _, ok := status["progress_message"].(string); !ok {
		t.Fatalf("expected progress_message during active scan, got %v", status)
	}
	if _, ok := status["last_progress_at"].(string); !ok {
		t.Fatalf("expected last_progress_at during active scan, got %v", status)
	}
	phaseProgress, ok := status["phase_progress"].(map[string]any)
	if !ok || phaseProgress["phase"] != "source_acquire" {
		t.Fatalf("expected source_acquire phase progress, got %v", status)
	}
	repoProgress, ok := status["repo_progress"].(map[string]any)
	if !ok || repoProgress["total"] != float64(1) {
		t.Fatalf("expected repo progress totals during active scan, got %v", status)
	}

	release()
	if code := <-done; code != exitSuccess {
		doneConsumed = true
		t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
	}
	doneConsumed = true
}

func waitForActiveScanStatus(t *testing.T, statePath string, timeout time.Duration) map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastStatus map[string]any
	var lastStatusErr string
	for time.Now().Before(deadline) {
		var statusOut bytes.Buffer
		var statusErr bytes.Buffer
		statusCode := Run([]string{"scan", "status", "--state", statePath, "--json"}, &statusOut, &statusErr)
		if statusCode == exitSuccess {
			var status map[string]any
			if err := json.Unmarshal(statusOut.Bytes(), &status); err != nil {
				t.Fatalf("parse status: %v", err)
			}
			lastStatus = status
			if status["status"] == "running" &&
				status["current_phase"] == "source_acquire" &&
				status["progress_percent"] != nil &&
				status["progress_message"] != nil &&
				status["last_progress_at"] != nil &&
				status["phase_progress"] != nil &&
				status["repo_progress"] != nil {
				return status
			}
		} else {
			lastStatusErr = statusErr.String()
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected active scan status before timeout; last_status=%v last_stderr=%q", lastStatus, lastStatusErr)
	return nil
}

func TestScanProgressBarRendersOnTTYStderr(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	errOut := newLiveBuffer()
	errOut.capabilities = scanProgressCapabilities{Interactive: true, SupportsBar: true}
	progress := newScanProgressReporter(scanProgressReporterOptions{
		RequestedMode: scanProgressModeBar,
		Stderr:        errOut,
		StartedAt:     time.Unix(0, 0).UTC(),
		TargetMode:    "path",
		TargetValue:   "/tmp/repos",
	})
	progress.ScanPhase("path", "/tmp/repos", "source_acquire_start")
	progress.PathDiscovery("/tmp/repos", 1)
	progress.PathRepo("/tmp/repos", 1, 1, "alpha")
	progress.Flush()
	if !strings.Contains(errOut.String(), "\rscan [") {
		t.Fatalf("expected bar renderer output on tty stderr, got %q", errOut.String())
	}
}

func TestScanProgressPlainRendererForNonTTY(t *testing.T) {
	var errOut bytes.Buffer
	progress := newScanProgressReporter(scanProgressReporterOptions{
		RequestedMode: scanProgressModeBar,
		Stderr:        &errOut,
		StartedAt:     time.Unix(0, 0).UTC(),
		TargetMode:    "path",
		TargetValue:   "/tmp/repos",
	})
	progress.ScanPhase("path", "/tmp/repos", "source_acquire_start")
	progress.PathDiscovery("/tmp/repos", 1)
	progress.PathRepo("/tmp/repos", 1, 1, "alpha")
	if !strings.Contains(errOut.String(), "requested --progress bar") {
		t.Fatalf("expected plain fallback notice for non-tty stderr, got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "scan progress progress=") {
		t.Fatalf("expected plain progress output for non-tty stderr, got %q", errOut.String())
	}
}

func TestScanProgressNoColorAndTermDumbUsePlainFallback(t *testing.T) {
	for name, env := range map[string]string{
		"no_color":  "1",
		"term_dumb": "",
	} {
		t.Run(name, func(t *testing.T) {
			errOut := newLiveBuffer()
			errOut.capabilities = scanProgressCapabilities{Interactive: true, SupportsBar: true}
			if name == "no_color" {
				t.Setenv("NO_COLOR", env)
				t.Setenv("TERM", "")
			} else {
				t.Setenv("NO_COLOR", "")
				t.Setenv("TERM", "dumb")
			}
			progress := newScanProgressReporter(scanProgressReporterOptions{
				RequestedMode: scanProgressModeAuto,
				Stderr:        errOut,
				StartedAt:     time.Unix(0, 0).UTC(),
				TargetMode:    "path",
				TargetValue:   "/tmp/repos",
			})
			progress.ScanPhase("path", "/tmp/repos", "source_acquire_start")
			if strings.Contains(errOut.String(), "\rscan [") {
				t.Fatalf("expected plain fallback when %s disables bar rendering, got %q", name, errOut.String())
			}
			if !strings.Contains(errOut.String(), "scan progress progress=") {
				t.Fatalf("expected plain progress output when %s disables bar rendering, got %q", name, errOut.String())
			}
		})
	}
}

func TestScanProgressFlushesNewlineBeforeExplain(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	errOut := newLiveBuffer()
	errOut.capabilities = scanProgressCapabilities{Interactive: true, SupportsBar: true}
	progress := newScanProgressReporter(scanProgressReporterOptions{
		RequestedMode: scanProgressModeBar,
		Stderr:        errOut,
		StartedAt:     time.Unix(0, 0).UTC(),
		TargetMode:    "path",
		TargetValue:   "/tmp/repos",
	})
	progress.ScanPhase("path", "/tmp/repos", "source_acquire_start")
	progress.PathDiscovery("/tmp/repos", 1)
	progress.PathRepo("/tmp/repos", 1, 1, "alpha")
	progress.Finish(scanProgressFooter{
		Status:              "completed",
		CurrentPhase:        "artifact_commit",
		LastSuccessfulPhase: "artifact_commit",
		ProgressPercent:     100,
		RepoTotal:           1,
		ReposCompleted:      1,
		ArtifactPaths:       []string{"state=.wrkr/last-scan.json"},
	})
	if !strings.Contains(errOut.String(), "\nscan status=") {
		t.Fatalf("expected bar renderer to flush a newline before the final footer, got %q", errOut.String())
	}
}

func TestScanProgressHeartbeatVisibleBeforeLongSourceCompletion(t *testing.T) {
	t.Parallel()

	releaseRepo := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			<-releaseRepo
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	errOut := newLiveBuffer()
	errOut.heartbeatInterval = 20 * time.Millisecond
	done := make(chan int, 1)
	go func() {
		done <- Run([]string{
			"scan",
			"--org", "acme",
			"--github-api", server.URL,
			"--state", statePath,
			"--json",
			"--progress", "events",
		}, &out, errOut)
	}()

	if !errOut.waitFor("event=heartbeat", 2*time.Second) {
		t.Fatalf("expected heartbeat progress before command completion, got %q", errOut.String())
	}
	select {
	case code := <-done:
		t.Fatalf("expected scan to remain in flight while heartbeat was visible, got code=%d stderr=%q", code, errOut.String())
	default:
	}

	close(releaseRepo)
	if code := <-done; code != exitSuccess {
		t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
	}
}

func TestScanProgressHeartbeatStopsAfterCancellation(t *testing.T) {
	t.Parallel()

	releaseRepo := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			select {
			case <-r.Context().Done():
				return
			case <-releaseRepo:
				_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	errOut := newLiveBuffer()
	errOut.heartbeatInterval = 20 * time.Millisecond
	done := make(chan int, 1)
	go func() {
		done <- runScanWithContext(ctx, []string{
			"--org", "acme",
			"--github-api", server.URL,
			"--state", statePath,
			"--json",
			"--progress", "events",
		}, &out, errOut)
	}()

	if !errOut.waitFor("event=heartbeat", 2*time.Second) {
		t.Fatalf("expected heartbeat before cancellation, got %q", errOut.String())
	}
	cancel()
	if code := <-done; code != exitRuntime {
		t.Fatalf("expected runtime exit after cancellation, got %d stderr=%q", code, errOut.String())
	}
	before := errOut.String()
	time.Sleep(80 * time.Millisecond)
	if errOut.String() != before {
		t.Fatalf("expected heartbeat goroutine to stop after cancellation, before=%q after=%q", before, errOut.String())
	}

	close(releaseRepo)
}

func TestScanProgressFooterIncludesResumeHintForInterruptedOrgScan(t *testing.T) {
	t.Parallel()

	releaseRepo := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			select {
			case <-r.Context().Done():
				return
			case <-releaseRepo:
				_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	errOut := newLiveBuffer()
	done := make(chan int, 1)
	go func() {
		done <- runScanWithContext(ctx, []string{
			"--org", "acme",
			"--github-api", server.URL,
			"--state", statePath,
			"--progress", "plain",
		}, &out, errOut)
	}()

	if !errOut.waitFor("materializing acme/a", 2*time.Second) {
		t.Fatalf("expected source progress before interruption, got %q", errOut.String())
	}
	cancel()
	if code := <-done; code != exitRuntime {
		t.Fatalf("expected runtime exit after cancellation, got %d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "resume_hint=") {
		t.Fatalf("expected interrupted org footer to include resume hint, got %q", errOut.String())
	}

	close(releaseRepo)
}

func TestScanProgressShowsDetectorPhaseDetail(t *testing.T) {
	t.Parallel()

	reposPath := filepath.Join(t.TempDir(), "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reposPath, "alpha", ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", reposPath,
		"--state", statePath,
		"--mode", "quick",
		"--json",
		"--progress", "events",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "event=detector_start") {
		t.Fatalf("expected detector start progress detail, got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "event=detector_complete") {
		t.Fatalf("expected detector completion progress detail, got %q", errOut.String())
	}
}
