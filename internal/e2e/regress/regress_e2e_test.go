package regresse2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
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
