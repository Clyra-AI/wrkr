package inite2e

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EInitThenScanWithRepoTarget(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	statePath := filepath.Join(tmp, "state.json")

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	code := cli.Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &initOut, &initErr)
	if code != 0 {
		t.Fatalf("init failed exit=%d stderr=%s", code, initErr.String())
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	code = cli.Run([]string{"scan", "--config", configPath, "--state", statePath, "--json"}, &scanOut, &scanErr)
	if code != 0 {
		t.Fatalf("scan failed exit=%d stderr=%s", code, scanErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestE2EInitRejectsInvalidTargetCombo(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--org", "acme", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
}
