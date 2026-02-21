package regresse2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestE2ERegressInitAndRunDetectsDrift(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha fixture: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("initial scan failed: %d (%s)", code, scanErr.String())
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := cli.Run([]string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"}, &initOut, &initErr); code != 0 {
		t.Fatalf("regress init failed: %d (%s)", code, initErr.String())
	}

	var runOut bytes.Buffer
	var runErr bytes.Buffer
	if code := cli.Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &runOut, &runErr); code != 0 {
		t.Fatalf("expected clean regress run, got %d (%s)", code, runErr.String())
	}
	var runPayload map[string]any
	if err := json.Unmarshal(runOut.Bytes(), &runPayload); err != nil {
		t.Fatalf("parse regress run payload: %v", err)
	}
	if runPayload["drift_detected"] != false {
		t.Fatalf("expected no drift, got %v", runPayload)
	}

	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta fixture: %v", err)
	}
	scanOut.Reset()
	scanErr.Reset()
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("second scan failed: %d (%s)", code, scanErr.String())
	}

	runOut.Reset()
	runErr.Reset()
	if code := cli.Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &runOut, &runErr); code != 5 {
		t.Fatalf("expected drift exit 5, got %d (%s)", code, runErr.String())
	}
	if runErr.Len() != 0 {
		t.Fatalf("expected drift JSON on stdout only, got stderr=%q", runErr.String())
	}
	if err := json.Unmarshal(runOut.Bytes(), &runPayload); err != nil {
		t.Fatalf("parse regress drift payload: %v", err)
	}
	if runPayload["drift_detected"] != true {
		t.Fatalf("expected drift detected payload, got %v", runPayload)
	}
}

func TestE2ERegressRunIgnoresPolicyOnlyStateDelta(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	reposPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("initial scan failed: %d (%s)", code, scanErr.String())
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := cli.Run([]string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"}, &initOut, &initErr); code != 0 {
		t.Fatalf("regress init failed: %d (%s)", code, initErr.String())
	}

	snapshot, loadErr := state.Load(statePath)
	if loadErr != nil {
		t.Fatalf("load state: %v", loadErr)
	}
	removeIndex := -1
	for i, finding := range snapshot.Findings {
		if finding.FindingType == "policy_check" || finding.FindingType == "policy_violation" {
			removeIndex = i
			break
		}
	}
	if removeIndex < 0 {
		t.Fatal("expected policy finding in fixture state")
	}
	snapshot.Findings = append(snapshot.Findings[:removeIndex], snapshot.Findings[removeIndex+1:]...)
	if saveErr := state.Save(statePath, snapshot); saveErr != nil {
		t.Fatalf("save mutated state: %v", saveErr)
	}

	var runOut bytes.Buffer
	var runErr bytes.Buffer
	if code := cli.Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &runOut, &runErr); code != 0 {
		t.Fatalf("expected no drift for policy-only delta, got %d (%s)", code, runErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(runOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse regress run payload: %v", err)
	}
	if payload["drift_detected"] != false {
		t.Fatalf("expected no drift for policy-only delta, got %v", payload)
	}
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	current := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	t.Fatalf("could not locate repository root from %s", wd)
	return ""
}
