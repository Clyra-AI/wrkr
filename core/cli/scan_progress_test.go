package cli

import (
	"bytes"
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

func TestScanJSONOrgProgressEmitsToStderrOnly(t *testing.T) {
	t.Parallel()

	var repoRetryAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"},{"full_name":"acme/b"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/b":
			repoRetryAttempts++
			if repoRetryAttempts == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = fmt.Fprint(w, `{"message":"retry later"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"full_name":"acme/b","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		case "/repos/acme/b/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse stdout payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %v", payload)
	}
	if strings.Contains(out.String(), "progress target=org") {
		t.Fatalf("expected progress lines to stay off stdout, got %q", out.String())
	}

	stderrText := errOut.String()
	for _, want := range []string{
		"progress target=org org=acme event=repo_discovery repo_total=2",
		"progress target=org org=acme event=repo_materialize repo_index=1 repo_total=2 repo=acme/a",
		"progress target=org org=acme event=retry attempt=1 delay_ms=0 status=429",
		"progress target=org org=acme event=complete repo_total=2 completed=2 failed=0",
	} {
		if !strings.Contains(stderrText, want) {
			t.Fatalf("expected stderr progress to contain %q, got %q", want, stderrText)
		}
	}
}

func TestScanJSONOrgProgressEmitsRecognized403RateLimitRetries(t *testing.T) {
	t.Parallel()

	var repoRetryAttempts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			repoRetryAttempts++
			if repoRetryAttempts == 1 {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
				return
			}
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
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "progress target=org org=acme event=retry attempt=1 delay_ms=0 status=403") {
		t.Fatalf("expected 403 retry progress line, got %q", errOut.String())
	}
}

func TestScanJSONQuietSuppressesProgressLines(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
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
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
		"--quiet",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(errOut.String(), "progress target=org") {
		t.Fatalf("expected quiet json scan to suppress progress lines, got %q", errOut.String())
	}
}

func TestScanJSONOrgProgressIsVisibleBeforeCommandCompletion(t *testing.T) {
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
	done := make(chan int, 1)
	go func() {
		done <- Run([]string{
			"scan",
			"--org", "acme",
			"--github-api", server.URL,
			"--state", statePath,
			"--json",
		}, &out, errOut)
	}()

	const want = "progress target=org org=acme event=repo_materialize repo_index=1 repo_total=1 repo=acme/a"
	if !errOut.waitFor(want, 2*time.Second) {
		t.Fatalf("expected live stderr progress before completion, got %q", errOut.String())
	}
	select {
	case code := <-done:
		t.Fatalf("expected scan to remain in flight while progress was visible, got code=%d stderr=%q", code, errOut.String())
	default:
	}

	close(releaseRepo)
	code := <-done
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanJSONPathAndProgressRemainCompatible(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	jsonPath := filepath.Join(tmp, "scan.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
		"--json-path", jsonPath,
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}

	filePayload, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read json payload: %v", err)
	}
	if !bytes.Equal(out.Bytes(), filePayload) {
		t.Fatalf("expected stdout and file payloads to match")
	}
	if !strings.Contains(errOut.String(), "progress target=org org=acme event=complete repo_total=1 completed=1 failed=0") {
		t.Fatalf("expected completion progress line, got %q", errOut.String())
	}
}

func TestScanJSONProgressFlushesOnErrorExit(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	approvedToolsPath := filepath.Join(tmp, "missing-approved-tools.yaml")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
		"--approved-tools", approvedToolsPath,
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected invalid input exit, got %d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "progress target=org org=acme event=complete repo_total=1 completed=1 failed=0") {
		t.Fatalf("expected completion progress line on error exit, got %q", errOut.String())
	}
}

type liveBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes chan struct{}
}

func newLiveBuffer() *liveBuffer {
	return &liveBuffer{writes: make(chan struct{}, 32)}
}

func (b *liveBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	select {
	case b.writes <- struct{}{}:
	default:
	}
	return n, err
}

func (b *liveBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *liveBuffer) waitFor(substring string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if strings.Contains(b.String(), substring) {
			return true
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		select {
		case <-b.writes:
		case <-time.After(remaining):
			return strings.Contains(b.String(), substring)
		}
	}
}
