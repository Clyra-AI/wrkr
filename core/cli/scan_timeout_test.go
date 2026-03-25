package cli

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestScanTimeoutDeadlineExceeded(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		_, _ = w.Write([]byte(`{"full_name":"acme/backend","default_branch":"main"}`))
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--state", statePath,
		"--timeout", "20ms",
		"--json",
	}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for timeout, got %d (stderr=%s)", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on timeout, got %q", out.String())
	}
	assertErrorCode(t, errOut.Bytes(), "scan_timeout")
}

func TestScanCancellationStopsAcquisitionAndDetection(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"full_name":"acme/backend","default_branch":"main"}`))
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code := RunWithContext(ctx, []string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for canceled scan, got %d (stderr=%s)", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on canceled scan, got %q", out.String())
	}
	assertErrorCode(t, errOut.Bytes(), "scan_canceled")
}

func TestScanOrgTimeoutDuringAcquireReturnsTimeoutError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			time.Sleep(250 * time.Millisecond)
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--timeout", "20ms",
		"--json",
	}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1 for timeout, got %d (stderr=%s)", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on timeout, got %q", out.String())
	}
	assertErrorCode(t, errOut.Bytes(), "scan_timeout")
}

func assertErrorCode(t *testing.T, payload []byte, expected string) {
	t.Helper()

	envelope := parseTrailingJSONEnvelope(t, payload)
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", envelope)
	}
	if errorPayload["code"] != expected {
		t.Fatalf("expected error code %q, got %v", expected, errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(1) {
		t.Fatalf("expected exit_code=1, got %v", errorPayload["exit_code"])
	}
}
