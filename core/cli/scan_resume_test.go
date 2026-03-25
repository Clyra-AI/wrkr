package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanResumeHelpIncludesFlag(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--help"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "-resume") {
		t.Fatalf("expected scan help to mention --resume, got %q", errOut.String())
	}
}

func TestScanResumeRejectsNonOrgTargets(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", t.TempDir(), "--state", filepath.Join(t.TempDir(), "state.json"), "--resume", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanResumeMissingCheckpointReturnsInvalidInput(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--resume",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanResumeMismatchReturnsInvalidInput(t *testing.T) {
	t.Parallel()

	var repoList string = `[{"full_name":"acme/a"}]`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, repoList)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		case "/orgs/acme/repos?page=2&per_page=100":
			_, _ = fmt.Fprint(w, `[]`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := Run([]string{"scan", "--org", "acme", "--github-api", server.URL, "--state", statePath, "--json"}, &firstOut, &firstErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d (%s)", code, firstErr.String())
	}

	repoList = `[{"full_name":"acme/a"},{"full_name":"acme/b"}]`
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--org", "acme", "--github-api", server.URL, "--state", statePath, "--resume", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanResumeSuccessEmitsResumeProgress(t *testing.T) {
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
	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := Run([]string{"scan", "--org", "acme", "--github-api", server.URL, "--state", statePath, "--json"}, &firstOut, &firstErr); code != exitSuccess {
		t.Fatalf("initial scan failed: %d (%s)", code, firstErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--org", "acme", "--github-api", server.URL, "--state", statePath, "--resume", "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("resume scan failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse resume payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %v", payload)
	}
	if !strings.Contains(errOut.String(), "progress target=org event=resume repo_total=1 completed=1 pending=0") {
		t.Fatalf("expected resume progress line, got %q", errOut.String())
	}
}
