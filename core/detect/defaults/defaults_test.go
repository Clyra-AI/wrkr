package defaults

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestRegistryRunsCrossDetectorCoverage(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	repoEntries, err := os.ReadDir(scanRoot)
	if err != nil {
		t.Fatalf("read scenario repos: %v", err)
	}

	scopes := make([]detect.Scope, 0)
	for _, entry := range repoEntries {
		if !entry.IsDir() {
			continue
		}
		scopes = append(scopes, detect.Scope{Org: "local", Repo: entry.Name(), Root: filepath.Join(scanRoot, entry.Name())})
	}

	registry, err := Registry()
	if err != nil {
		t.Fatalf("create detector registry: %v", err)
	}
	findings, err := registry.Run(context.Background(), scopes, detect.Options{})
	if err != nil {
		t.Fatalf("run detector registry: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected detector findings from mixed-org fixtures")
	}

	required := map[string]bool{
		"claude":         false,
		"cursor":         false,
		"codex":          false,
		"copilot":        false,
		"mcp":            false,
		"skills":         false,
		"gaitpolicy":     false,
		"dependency":     false,
		"secrets":        false,
		"compiledaction": false,
		"ciagent":        false,
	}
	for _, finding := range findings {
		if _, ok := required[finding.Detector]; ok {
			required[finding.Detector] = true
		}
	}
	for detectorID, seen := range required {
		if !seen {
			t.Fatalf("expected detector %s to produce at least one finding", detectorID)
		}
	}
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not find repo root")
		}
		wd = next
	}
}
