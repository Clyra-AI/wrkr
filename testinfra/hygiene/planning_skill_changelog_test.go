package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanningSkillsRequireExplicitStoryChangelogFields(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	cases := []struct {
		name string
		path string
	}{
		{name: "adhoc-plan", path: filepath.Join(repoRoot, "factory/skills/adhoc-plan/SKILL.md")},
		{name: "backlog-plan", path: filepath.Join(repoRoot, "factory/skills/backlog-plan/SKILL.md")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := readFactorySkillOrSkip(t, tc.path)
			for _, needle := range []string{
				"Changelog impact:",
				"required",
				"not required",
				"Changelog section:",
				"Draft changelog entry:",
				"Semver marker override:",
				"[semver:patch]",
				"[semver:minor]",
				"[semver:major]",
				"Generated plans must leave explicit story-level changelog",
			} {
				if !strings.Contains(skill, needle) {
					t.Fatalf("%s missing changelog planning contract %q", tc.name, needle)
				}
			}
		})
	}
}

func TestImplementationSkillsConsumeStoryChangelogFields(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	cases := []struct {
		name string
		path string
	}{
		{name: "plan-implement", path: filepath.Join(repoRoot, "factory/skills/plan-implement/SKILL.md")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := readFactorySkillOrSkip(t, tc.path)
			for _, needle := range []string{
				"Changelog impact",
				"Changelog section",
				"Draft changelog entry",
				"update profile `changelog.path` under profile `changelog.unreleased_heading`",
				"do not finalize versioned release sections during implementation",
				"Do not invent changelog policy during implementation",
			} {
				if !strings.Contains(skill, needle) {
					t.Fatalf("%s missing changelog implementation contract %q", tc.name, needle)
				}
			}
		})
	}
}

func readFactorySkillOrSkip(t *testing.T, path string) string {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			t.Skipf("factory submodule is not initialized; skipping shared skill contract for %s", path)
		}
		t.Fatalf("stat factory skill %s: %v", path, err)
	}
	return mustReadFile(t, path)
}
