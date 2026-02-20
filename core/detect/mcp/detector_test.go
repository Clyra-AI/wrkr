package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectMCPServersAndTrustSignals(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scope := detect.Scope{Org: "local", Repo: "backend", Root: filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos", "backend")}
	findings, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect mcp: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected mcp findings")
	}
	foundTrust := false
	for _, finding := range findings {
		for _, ev := range finding.Evidence {
			if ev.Key == "trust_score" {
				foundTrust = true
			}
		}
	}
	if !foundTrust {
		t.Fatal("expected trust_score evidence in mcp findings")
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
