package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanPathRepoRootProducesSingleRepoManifestAndRootFinding(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "demo-repo")
	if err := os.MkdirAll(repoRoot, 0o755); err != nil {
		t.Fatalf("mkdir repo root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "AGENTS.md"), []byte("agent instructions\n"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", repoRoot, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	sourceManifest, ok := payload["source_manifest"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_manifest object, got %T", payload["source_manifest"])
	}
	repos, ok := sourceManifest["repos"].([]any)
	if !ok || len(repos) != 1 {
		t.Fatalf("expected one repo manifest entry, got %v", sourceManifest["repos"])
	}
	firstRepo, ok := repos[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected repo manifest shape: %T", repos[0])
	}
	if firstRepo["repo"] != "demo-repo" {
		t.Fatalf("expected repo name demo-repo, got %v", firstRepo["repo"])
	}

	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	foundRootSignal := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["location"] == "AGENTS.md" && finding["repo"] == "demo-repo" {
			foundRootSignal = true
			break
		}
	}
	if !foundRootSignal {
		t.Fatalf("expected a root-level AGENTS.md finding in payload: %v", findings)
	}
}

func TestScanPathRepoSetPreservesDeterministicChildOrdering(t *testing.T) {
	t.Parallel()

	reposRoot := filepath.Join(t.TempDir(), "repos")
	for _, name := range []string{"zeta", "alpha"} {
		repoRoot := filepath.Join(reposRoot, name)
		if err := os.MkdirAll(filepath.Join(repoRoot, ".codex"), 0o755); err != nil {
			t.Fatalf("mkdir repo %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(repoRoot, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
			t.Fatalf("write codex config for %s: %v", name, err)
		}
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposRoot, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: %d stderr=%q", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	sourceManifest, ok := payload["source_manifest"].(map[string]any)
	if !ok {
		t.Fatalf("expected source_manifest object, got %T", payload["source_manifest"])
	}
	repos, ok := sourceManifest["repos"].([]any)
	if !ok || len(repos) != 2 {
		t.Fatalf("expected two repo manifest entries, got %v", sourceManifest["repos"])
	}
	firstRepo, ok := repos[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected first repo manifest shape: %T", repos[0])
	}
	secondRepo, ok := repos[1].(map[string]any)
	if !ok {
		t.Fatalf("unexpected second repo manifest shape: %T", repos[1])
	}
	if firstRepo["repo"] != "alpha" || secondRepo["repo"] != "zeta" {
		t.Fatalf("expected deterministic alpha/zeta ordering, got %v", repos)
	}
}
