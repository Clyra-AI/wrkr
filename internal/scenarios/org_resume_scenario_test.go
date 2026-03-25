//go:build scenario

package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestOrgResumeMatchesCleanRun(t *testing.T) {
	t.Parallel()

	var resumePhase atomic.Bool
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
			if !resumePhase.Load() {
				time.Sleep(250 * time.Millisecond)
			}
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	resumeRoot := t.TempDir()
	resumeState := filepath.Join(resumeRoot, "state.json")
	checkpointPath := filepath.Join(resumeRoot, "org-checkpoints", "acme.json")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var interruptedOut bytes.Buffer
	var interruptedErr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- cli.RunWithContext(ctx, []string{
			"scan",
			"--org", "acme",
			"--github-api", server.URL,
			"--state", resumeState,
			"--json",
		}, &interruptedOut, &interruptedErr)
	}()

	waitForCheckpointCompletion(t, checkpointPath, 1)
	cancel()
	if code := <-done; code != 1 {
		t.Fatalf("expected interrupted scan to return exit 1, got %d (%s)", code, interruptedErr.String())
	}

	resumePhase.Store(true)
	resumedPayload := runScenarioCommandJSON(t, []string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", resumeState,
		"--resume",
		"--json",
	})

	cleanState := filepath.Join(t.TempDir(), "state.json")
	cleanPayload := runScenarioCommandJSON(t, []string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", cleanState,
		"--json",
	})

	if !equalScenarioSignatures(resumedPayload, cleanPayload) {
		t.Fatalf("expected resumed and clean scan signatures to match\nresumed=%v\nclean=%v", scenarioSignature(resumedPayload), scenarioSignature(cleanPayload))
	}
}

func waitForCheckpointCompletion(t *testing.T, checkpointPath string, completed int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		payload, err := os.ReadFile(checkpointPath)
		if err == nil {
			var state struct {
				CompletedRepos []string `json:"completed_repos"`
			}
			if json.Unmarshal(payload, &state) == nil && len(state.CompletedRepos) >= completed {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("checkpoint %s did not reach %d completed repos in time", checkpointPath, completed)
}

func equalScenarioSignatures(left, right map[string]any) bool {
	return reflect.DeepEqual(scenarioSignature(left), scenarioSignature(right))
}

func scenarioSignature(payload map[string]any) map[string]any {
	signature := map[string]any{}
	sourceManifest, _ := payload["source_manifest"].(map[string]any)
	repos, _ := sourceManifest["repos"].([]any)
	repoNames := make([]string, 0, len(repos))
	for _, item := range repos {
		repo, _ := item.(map[string]any)
		if name, _ := repo["repo"].(string); name != "" {
			repoNames = append(repoNames, name)
		}
	}
	sort.Strings(repoNames)
	signature["repos"] = repoNames

	findings, _ := payload["findings"].([]any)
	findingKeys := make([]string, 0, len(findings))
	for _, item := range findings {
		finding, _ := item.(map[string]any)
		location := fmt.Sprint(finding["location"])
		if fmt.Sprint(finding["finding_type"]) == "source_discovery" {
			location = "materialized_root"
		}
		findingKeys = append(findingKeys, fmt.Sprintf("%v|%v|%v|%v", finding["finding_type"], finding["tool_type"], finding["repo"], location))
	}
	sort.Strings(findingKeys)
	signature["findings"] = findingKeys

	topFindings, _ := payload["top_findings"].([]any)
	topKeys := make([]string, 0, len(topFindings))
	for _, item := range topFindings {
		row, _ := item.(map[string]any)
		finding, _ := row["finding"].(map[string]any)
		topKeys = append(topKeys, fmt.Sprintf("%v|%v|%v", row["risk_score"], finding["finding_type"], finding["location"]))
	}
	sort.Strings(topKeys)
	signature["top_findings"] = topKeys
	return signature
}
