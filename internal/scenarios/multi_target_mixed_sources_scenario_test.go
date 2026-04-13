//go:build scenario

package scenarios

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestMultiTargetMixedSourcesScenario(t *testing.T) {
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
	payload := runScenarioCommandJSON(t, []string{
		"scan",
		"--target", "org:acme",
		"--target", "path:" + reposPath,
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	})

	target, ok := payload["target"].(map[string]any)
	if !ok || target["mode"] != "multi" {
		t.Fatalf("expected multi target payload, got %v", payload["target"])
	}
	targets, ok := payload["targets"].([]any)
	if !ok || len(targets) != 2 {
		t.Fatalf("expected additive targets array, got %v", payload["targets"])
	}
	sourceManifest, ok := payload["source_manifest"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_manifest object, got %T", payload["source_manifest"])
	}
	repos, ok := sourceManifest["repos"].([]any)
	if !ok || len(repos) != 2 {
		t.Fatalf("expected two repos in multi-target source_manifest, got %v", sourceManifest["repos"])
	}

	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})
	reportTargets, ok := reportPayload["targets"].([]any)
	if !ok || len(reportTargets) != 2 {
		t.Fatalf("expected additive report targets, got %v", reportPayload["targets"])
	}
}
