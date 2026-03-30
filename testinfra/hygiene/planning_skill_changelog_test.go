package hygiene

import (
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
		{name: "adhoc-plan", path: filepath.Join(repoRoot, ".agents/skills/adhoc-plan/SKILL.md")},
		{name: "backlog-plan", path: filepath.Join(repoRoot, ".agents/skills/backlog-plan/SKILL.md")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := mustReadFile(t, tc.path)
			for _, needle := range []string{
				"Changelog impact: required|not required",
				"Changelog section: Added|Changed|Deprecated|Removed|Fixed|Security|none",
				"Draft changelog entry:",
				"Semver marker override: none|[semver:patch]|[semver:minor]|[semver:major]",
				"Generated plans must leave explicit story-level changelog fields",
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
		{name: "adhoc-implement", path: filepath.Join(repoRoot, ".agents/skills/adhoc-implement/SKILL.md")},
		{name: "backlog-implement", path: filepath.Join(repoRoot, ".agents/skills/backlog-implement/SKILL.md")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := mustReadFile(t, tc.path)
			for _, needle := range []string{
				"Changelog impact",
				"Changelog section",
				"Draft changelog entry",
				"update `CHANGELOG.md` `## [Unreleased]` in the same story",
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
