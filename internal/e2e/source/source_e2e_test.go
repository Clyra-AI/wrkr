package sourcee2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EScanModesRepoOrgPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	state := filepath.Join(tmp, "state.json")

	var repoOut bytes.Buffer
	var repoErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--repo", "acme/backend", "--state", state, "--json"}, &repoOut, &repoErr); code != 0 {
		t.Fatalf("repo scan failed: %d (%s)", code, repoErr.String())
	}

	var orgOut bytes.Buffer
	var orgErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--org", "acme", "--state", state, "--json"}, &orgOut, &orgErr); code != 0 {
		t.Fatalf("org scan failed: %d (%s)", code, orgErr.String())
	}

	pathTarget := filepath.Join(tmp, "local-repos")
	if err := os.MkdirAll(filepath.Join(pathTarget, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir local repo: %v", err)
	}
	var pathOut bytes.Buffer
	var pathErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", pathTarget, "--state", state, "--json"}, &pathOut, &pathErr); code != 0 {
		t.Fatalf("path scan failed: %d (%s)", code, pathErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(pathOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	manifest := payload["source_manifest"].(map[string]any)
	repos := manifest["repos"].([]any)
	if len(repos) != 1 {
		t.Fatalf("expected one local repo, got %d", len(repos))
	}
}

func TestE2EAirGappedPathScan(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pathTarget := filepath.Join(tmp, "air-gapped")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(pathTarget, "repo1"), 0o755); err != nil {
		t.Fatalf("mkdir repo1: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", pathTarget, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("air-gapped path scan should succeed offline: %d (%s)", code, errOut.String())
	}
}
