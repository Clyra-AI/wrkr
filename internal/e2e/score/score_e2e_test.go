package scoree2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EScoreJSONAndExplainContracts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := cli.Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score --json failed: %d (%s)", code, scoreErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(scoreOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	for _, key := range []string{"score", "grade", "breakdown", "weighted_breakdown", "weights", "trend_delta"} {
		if _, present := payload[key]; !present {
			t.Fatalf("missing score key %q in %v", key, payload)
		}
	}

	scoreOut.Reset()
	scoreErr.Reset()
	if code := cli.Run([]string{"score", "--state", statePath, "--explain"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score --explain failed: %d (%s)", code, scoreErr.String())
	}
	if !strings.Contains(scoreOut.String(), "wrkr score") {
		t.Fatalf("expected explain output, got %q", scoreOut.String())
	}
}
