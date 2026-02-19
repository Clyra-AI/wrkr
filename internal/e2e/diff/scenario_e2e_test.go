package diffe2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EScenarioUnchangedReposProduceZeroDiffNoise(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	fixtureRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-diff-no-noise")
	inputPath := filepath.Join(fixtureRoot, "input", "local-repos")
	expectedPath := filepath.Join(fixtureRoot, "expected", "diff.json")

	statePath := filepath.Join(t.TempDir(), "state.json")

	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", inputPath, "--state", statePath, "--json"}, &firstOut, &firstErr); code != 0 {
		t.Fatalf("initial scan failed: %d (%s)", code, firstErr.String())
	}

	var diffOut bytes.Buffer
	var diffErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", inputPath, "--state", statePath, "--diff", "--json"}, &diffOut, &diffErr); code != 0 {
		t.Fatalf("diff scan failed: %d (%s)", code, diffErr.String())
	}

	payload := mustJSONMap(t, diffOut.Bytes())
	diffPayload := payload["diff"].(map[string]any)

	expectedBytes, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected diff fixture: %v", err)
	}
	expected := mustJSONMap(t, expectedBytes)

	if !reflect.DeepEqual(diffPayload, expected) {
		t.Fatalf("unexpected diff payload\nactual=%v\nexpected=%v", diffPayload, expected)
	}
}

func mustJSONMap(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse json payload: %v", err)
	}
	return out
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatalf("could not locate repo root from %s", wd)
		}
		current = parent
	}
}
