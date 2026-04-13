package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/state"
)

func TestScanTargetAcceptsMixedOrgAndPathTargets(t *testing.T) {
	t.Parallel()

	reposPath := filepath.Join(t.TempDir(), "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "local-alpha"), 0o755); err != nil {
		t.Fatalf("mkdir local fixture: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/api"}]`)
		case "/repos/acme/api":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/api","default_branch":"main"}`)
		case "/repos/acme/api/git/trees/main":
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
		"--target", "org:acme",
		"--target", "path:" + reposPath,
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	target, ok := payload["target"].(map[string]any)
	if !ok {
		t.Fatalf("expected target object, got %T", payload["target"])
	}
	if target["mode"] != "multi" {
		t.Fatalf("expected multi target mode, got %v", target)
	}
	targets, ok := payload["targets"].([]any)
	if !ok || len(targets) != 2 {
		t.Fatalf("expected two additive targets, got %v", payload["targets"])
	}
	sourceManifest, ok := payload["source_manifest"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_manifest object, got %T", payload["source_manifest"])
	}
	manifestTargets, ok := sourceManifest["targets"].([]any)
	if !ok || len(manifestTargets) != 2 {
		t.Fatalf("expected source_manifest.targets, got %v", sourceManifest["targets"])
	}
	repos, ok := sourceManifest["repos"].([]any)
	if !ok || len(repos) != 2 {
		t.Fatalf("expected two repos in source manifest, got %v", sourceManifest["repos"])
	}

	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load saved state: %v", err)
	}
	if snapshot.Target.Mode != "multi" {
		t.Fatalf("expected saved multi target mode, got %+v", snapshot.Target)
	}
	if len(snapshot.Targets) != 2 {
		t.Fatalf("expected saved targets array, got %+v", snapshot.Targets)
	}
}

func TestScanRejectsMixedLegacyAndTargetFlags(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--target", "path:" + t.TempDir(),
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanResumeRejectsMixedTargetSets(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--target", "org:acme",
		"--target", "path:" + t.TempDir(),
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--resume",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanMultiOrgResumeRejectsTargetSetMismatch(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/orgs/beta/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"beta/b"}]`)
		case "/orgs/gamma/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"gamma/c"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/beta/b":
			_, _ = fmt.Fprint(w, `{"full_name":"beta/b","default_branch":"main"}`)
		case "/repos/gamma/c":
			_, _ = fmt.Fprint(w, `{"full_name":"gamma/c","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main", "/repos/beta/b/git/trees/main", "/repos/gamma/c/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := Run([]string{
		"scan",
		"--target", "org:acme",
		"--target", "org:beta",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &firstOut, &firstErr); code != exitSuccess {
		t.Fatalf("initial multi-org scan failed: %d (%s)", code, firstErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--target", "org:acme",
		"--target", "org:gamma",
		"--github-api", server.URL,
		"--state", statePath,
		"--resume",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d (%s)", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestReportIncludesTargetsForMultiTargetSnapshots(t *testing.T) {
	t.Parallel()

	reposPath := filepath.Join(t.TempDir(), "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "local-alpha"), 0o755); err != nil {
		t.Fatalf("mkdir local fixture: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/api"}]`)
		case "/repos/acme/api":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/api","default_branch":"main"}`)
		case "/repos/acme/api/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{
		"scan",
		"--target", "org:acme",
		"--target", "path:" + reposPath,
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &scanOut, &scanErr); code != exitSuccess {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--state", statePath, "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("report failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	targets, ok := payload["targets"].([]any)
	if !ok || len(targets) != 2 {
		t.Fatalf("expected additive targets in report payload, got %v", payload["targets"])
	}
}
