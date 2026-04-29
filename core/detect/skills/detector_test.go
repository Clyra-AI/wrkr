package skills

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestSkillDetectorRejectsExternalSymlinkedSkillFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	writeSkillFile(t, outside, "SKILL.md", strings.Join([]string{
		"---",
		"allowed-tools:",
		"  - proc.exec",
		"---",
		"",
		"# Deploy",
	}, "\n"))
	mustSymlinkOrSkipSkill(t, filepath.Join(outside, "SKILL.md"), filepath.Join(root, ".agents", "skills", "deploy", "SKILL.md"))

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect skills: %v", err)
	}

	parseErrors := 0
	for _, finding := range findings {
		if finding.Location != ".agents/skills/deploy/SKILL.md" {
			continue
		}
		if finding.FindingType == "parse_error" && finding.ParseError != nil && finding.ParseError.Kind == "unsafe_path" {
			parseErrors++
			continue
		}
		t.Fatalf("expected only unsafe_path parse_error for symlinked skill, got %#v", finding)
	}
	if parseErrors != 1 {
		t.Fatalf("expected one unsafe_path parse error, got %#v", findings)
	}
}

func TestSkillDetectorIgnoresUnsafeGaitPolicyContents(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeSkillFile(t, root, ".agents/skills/release/SKILL.md", strings.Join([]string{
		"---",
		"allowed-tools:",
		"  - proc.exec",
		"---",
		"",
		"# Release",
	}, "\n"))

	outside := t.TempDir()
	writeSkillFile(t, outside, "external.yaml", strings.Join([]string{
		"rules:",
		"  - id: outside-only",
		"    block_tools:",
		"      - proc.exec",
	}, "\n"))
	mustSymlinkOrSkipSkill(t, filepath.Join(outside, "external.yaml"), filepath.Join(root, ".gait", "external.yaml"))

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect skills: %v", err)
	}

	foundSkill := false
	for _, finding := range findings {
		if finding.FindingType == "skill" && finding.Location == ".agents/skills/release/SKILL.md" {
			foundSkill = true
		}
		if finding.FindingType == "skill_policy_conflict" {
			t.Fatalf("expected unsafe gait policy contents to be ignored, got %#v", finding)
		}
	}
	if !foundSkill {
		t.Fatalf("expected skill finding to remain, got %#v", findings)
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

func writeSkillFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func mustSymlinkOrSkipSkill(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink parent: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}
}
