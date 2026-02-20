package diffe2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EDiffNoNoiseOnUnchangedInput(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha: %v", err)
	}

	var out1 bytes.Buffer
	var err1 bytes.Buffer
	code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out1, &err1)
	if code != 0 {
		t.Fatalf("initial scan failed: %d (%s)", code, err1.String())
	}

	var out2 bytes.Buffer
	var err2 bytes.Buffer
	code = cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--diff", "--json"}, &out2, &err2)
	if code != 0 {
		t.Fatalf("diff scan failed: %d (%s)", code, err2.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out2.Bytes(), &payload); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if payload["diff_empty"] != true {
		t.Fatalf("expected diff_empty=true, got %v", payload["diff_empty"])
	}

	var out3 bytes.Buffer
	var err3 bytes.Buffer
	code = cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--diff", "--json"}, &out3, &err3)
	if code != 0 {
		t.Fatalf("repeat diff failed: %d (%s)", code, err3.String())
	}
	if out2.String() != out3.String() {
		t.Fatalf("expected byte-stable diff output\nfirst: %s\nsecond: %s", out2.String(), out3.String())
	}
}

func TestE2EDiffUsesBaselineWhenStateMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	baselinePath := filepath.Join(tmp, "baseline.json")
	statePath := filepath.Join(tmp, "state.json")

	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha: %v", err)
	}

	// Build baseline from the same target path with one repo.
	var baselineOut bytes.Buffer
	var baselineErr bytes.Buffer
	code := cli.Run([]string{"scan", "--path", reposPath, "--state", baselinePath, "--json"}, &baselineOut, &baselineErr)
	if code != 0 {
		t.Fatalf("build baseline failed: %d (%s)", code, baselineErr.String())
	}
	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta: %v", err)
	}

	var diffOut bytes.Buffer
	var diffErr bytes.Buffer
	code = cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--baseline", baselinePath, "--diff", "--json"}, &diffOut, &diffErr)
	if code != 0 {
		t.Fatalf("diff with baseline failed: %d (%s)", code, diffErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(diffOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse diff payload: %v", err)
	}
	diffPayload := payload["diff"].(map[string]any)
	added := diffPayload["added"].([]any)
	if len(added) == 0 {
		t.Fatalf("expected added findings from baseline comparison, got %d", len(added))
	}
	foundBetaRepo := false
	for _, item := range added {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["tool_type"] == "source_repo" && finding["repo"] == "beta" {
			foundBetaRepo = true
			break
		}
	}
	if !foundBetaRepo {
		t.Fatalf("expected diff added list to include beta source discovery, payload=%v", diffPayload)
	}
}
