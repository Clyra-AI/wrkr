package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestScanContinuesOnDetectorError(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("permission fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(reposPath, 0o755); err != nil {
		t.Fatalf("mkdir repos: %v", err)
	}

	goodRepo := filepath.Join(reposPath, "alpha")
	if err := os.MkdirAll(filepath.Join(goodRepo, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir good repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goodRepo, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	badRepo := filepath.Join(reposPath, "beta")
	if err := os.MkdirAll(badRepo, 0o755); err != nil {
		t.Fatalf("mkdir bad repo: %v", err)
	}
	if err := os.Chmod(badRepo, 0o000); err != nil {
		t.Skipf("chmod 000 unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(badRepo, 0o755)
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	statePath := filepath.Join(tmp, "state.json")
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings to be preserved, got %v", payload["findings"])
	}
	detectorErrors, ok := payload["detector_errors"].([]any)
	if !ok || len(detectorErrors) == 0 {
		t.Fatalf("expected detector_errors in payload, got %v", payload["detector_errors"])
	}
	firstErr, ok := detectorErrors[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected detector error payload type: %T", detectorErrors[0])
	}
	for _, key := range []string{"detector", "org", "repo", "code", "class", "message"} {
		if _, present := firstErr[key]; !present {
			t.Fatalf("detector error missing key %q: %v", key, firstErr)
		}
	}
}

func TestScanOrgMaterializationFailureReturnsPartialResult(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"},{"full_name":"acme/b"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/b":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/b","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		case "/repos/acme/b/git/trees/main":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"message":"upstream unavailable"}`)
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
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	if partial, ok := payload["partial_result"].(bool); !ok || !partial {
		t.Fatalf("expected partial_result=true, got %v", payload["partial_result"])
	}
	sourceErrors, ok := payload["source_errors"].([]any)
	if !ok || len(sourceErrors) == 0 {
		t.Fatalf("expected source_errors, got %v", payload["source_errors"])
	}
	if degraded, ok := payload["source_degraded"].(bool); !ok || degraded {
		t.Fatalf("expected source_degraded=false for non-degraded failure, got %v", payload["source_degraded"])
	}
}
