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
	"testing"
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
		"progress target=org event=repo_discovery repo_total=2",
		"progress target=org event=repo_materialize repo_index=1 repo_total=2 repo=acme/a",
		"progress target=org event=retry attempt=1 delay_ms=0 status=429",
		"progress target=org event=complete repo_total=2 completed=2 failed=0",
	} {
		if !strings.Contains(stderrText, want) {
			t.Fatalf("expected stderr progress to contain %q, got %q", want, stderrText)
		}
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
	if !strings.Contains(errOut.String(), "progress target=org event=complete repo_total=1 completed=1 failed=0") {
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
	if !strings.Contains(errOut.String(), "progress target=org event=complete repo_total=1 completed=1 failed=0") {
		t.Fatalf("expected completion progress line on error exit, got %q", errOut.String())
	}
}
