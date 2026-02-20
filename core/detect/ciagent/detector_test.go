package ciagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectCIAutonomyCriticalFinding(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scope := detect.Scope{Org: "local", Repo: "infra", Root: filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos", "infra")}
	findings, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect ciagent: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected ciagent findings")
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity finding first, got %s", findings[0].Severity)
	}
	if findings[0].Autonomy != "headless_auto" {
		t.Fatalf("expected headless_auto autonomy, got %s", findings[0].Autonomy)
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
