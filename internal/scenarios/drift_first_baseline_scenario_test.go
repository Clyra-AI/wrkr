//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestDriftFirstBaseline(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "drift-first-baseline", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "empty-approved-baseline.json")
	if err := os.WriteFile(baselinePath, []byte("{\"version\":\"v1\",\"generated_at\":\"2026-04-22T12:00:00Z\",\"tools\":[]}\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	_ = runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 5 {
		t.Fatalf("expected drift exit 5, got %d stderr=%s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected drift JSON on stdout only, got stderr=%q", errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse regress payload: %v", err)
	}
	reasons, ok := payload["reasons"].([]any)
	if !ok || len(reasons) == 0 {
		t.Fatalf("expected drift reasons, got %v", payload)
	}
	for _, item := range reasons {
		reason, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if reason["code"] == "new_secret_bearing_workflow" {
			return
		}
	}
	t.Fatalf("expected new_secret_bearing_workflow reason, got %v", reasons)
}
