package skills

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectSkillMetricsAndPolicyConflict(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scope := detect.Scope{Org: "local", Repo: "frontend", Root: filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos", "frontend")}
	findings, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect skills: %v", err)
	}

	foundMetrics := false
	foundConflict := false
	for _, finding := range findings {
		if finding.FindingType == "skill_metrics" {
			foundMetrics = true
		}
		if finding.FindingType == "skill_policy_conflict" {
			foundConflict = true
		}
	}
	if !foundMetrics {
		t.Fatal("expected skill_metrics finding")
	}
	if !foundConflict {
		t.Fatal("expected skill_policy_conflict finding")
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
