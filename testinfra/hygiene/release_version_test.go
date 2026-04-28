package hygiene

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type changelogReleaseResult struct {
	BaseTag     string `json:"base_tag"`
	Bump        string `json:"bump"`
	Reason      string `json:"reason"`
	ReleaseDate string `json:"release_date"`
	Source      string `json:"source"`
	Status      string `json:"status"`
	Version     string `json:"version"`
}

func TestResolveReleaseVersionBootstrapsWithoutTags(t *testing.T) {
	t.Parallel()

	repoRoot := initReleaseFixtureRepo(t)
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Added": {"first stable release packaging"},
		},
	))
	commitAll(t, repoRoot, "docs: seed changelog")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.0.0" {
		t.Fatalf("expected bootstrap version v1.0.0, got %s", result.Version)
	}
	if result.Bump != "bootstrap" {
		t.Fatalf("expected bootstrap bump, got %s", result.Bump)
	}
}

func TestResolveReleaseVersionUsesPatchForFixes(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "patch change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"tightened proof-chain verification failure handling"},
		},
	))
	commitAll(t, repoRoot, "fix: tighten proof-chain verification")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.2.4" {
		t.Fatalf("expected patch version v1.2.4, got %s", result.Version)
	}
	if result.Bump != "patch" {
		t.Fatalf("expected patch bump, got %s", result.Bump)
	}
	if result.BaseTag != "v1.2.3" {
		t.Fatalf("expected base tag v1.2.3, got %s", result.BaseTag)
	}
}

func TestResolveReleaseVersionUsesMinorForAddedEntries(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "minor change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Added": {"new inventory export summary for machine-readable posture diffs"},
		},
	))
	commitAll(t, repoRoot, "feat: add inventory export summary")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.3.0" {
		t.Fatalf("expected minor version v1.3.0, got %s", result.Version)
	}
	if result.Bump != "minor" {
		t.Fatalf("expected minor bump, got %s", result.Bump)
	}
}

func TestResolveReleaseVersionUsesMajorForBreakingMarkers(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "major change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Changed": {"BREAKING: rename the baseline schema contract and require explicit migration"},
		},
	))
	commitAll(t, repoRoot, "feat!: rename baseline schema contract")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v2.0.0" {
		t.Fatalf("expected major version v2.0.0, got %s", result.Version)
	}
	if result.Bump != "major" {
		t.Fatalf("expected major bump, got %s", result.Bump)
	}
}

func TestResolveReleaseVersionHonorsExplicitMarkerOverrides(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "override change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Added": {"[semver:patch] add operator-facing wording cleanup only"},
		},
	))
	commitAll(t, repoRoot, "docs: clarify operator wording")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.2.4" {
		t.Fatalf("expected explicit patch override to yield v1.2.4, got %s", result.Version)
	}
	if result.Bump != "patch" {
		t.Fatalf("expected explicit patch bump, got %s", result.Bump)
	}
}

func TestResolveReleaseVersionRejectsExplicitMismatch(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "patch change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"tightened proof-chain verification failure handling"},
		},
	))
	commitAll(t, repoRoot, "fix: tighten proof-chain verification")

	_, stderr, err := runReleaseVersionResolverRaw(t, repoRoot, "--release-version", "v1.3.0")
	if err == nil {
		t.Fatal("expected explicit version mismatch to fail")
	}
	if !strings.Contains(stderr, "does not match changelog-derived v1.2.4") {
		t.Fatalf("expected mismatch stderr, got %q", stderr)
	}
}

func TestResolveReleaseVersionIgnoresPrereleaseTags(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	runCommand(t, repoRoot, "git", "tag", "v2.0.0-rc1")
	writeFixtureFile(t, repoRoot, "README.md", "stable tag change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"stabilize release resolver tag selection"},
		},
	))
	commitAll(t, repoRoot, "fix: stabilize release resolver tag selection")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.2.4" {
		t.Fatalf("expected prerelease tags to be ignored in favor of v1.2.4, got %s", result.Version)
	}
	if result.BaseTag != "v1.2.3" {
		t.Fatalf("expected stable base tag v1.2.3, got %s", result.BaseTag)
	}
}

func TestResolveReleaseVersionIgnoresUnmergedTags(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")

	runCommand(t, repoRoot, "git", "checkout", "-b", "release-preview")
	writeFixtureFile(t, repoRoot, "preview.txt", "preview branch only\n")
	commitAll(t, repoRoot, "chore: preview-only commit")
	runCommand(t, repoRoot, "git", "tag", "v9.9.9")

	runCommand(t, repoRoot, "git", "checkout", "main")
	writeFixtureFile(t, repoRoot, "README.md", "mainline change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"keep release numbering on the mainline tag lineage"},
		},
	))
	commitAll(t, repoRoot, "fix: keep release numbering on mainline")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.2.4" {
		t.Fatalf("expected unmerged tags to be ignored in favor of v1.2.4, got %s", result.Version)
	}
	if result.BaseTag != "v1.2.3" {
		t.Fatalf("expected reachable base tag v1.2.3, got %s", result.BaseTag)
	}
}

func TestResolveReleaseVersionFallsBackToExistingTagsWithoutMergedTags(t *testing.T) {
	t.Parallel()

	repoRoot := initReleaseFixtureRepo(t)

	runCommand(t, repoRoot, "git", "checkout", "--orphan", "release-history")
	writeFixtureFile(t, repoRoot, "README.md", "prior release history\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(nil))
	commitAll(t, repoRoot, "chore: prior release history")
	runCommand(t, repoRoot, "git", "tag", "v1.1.1")

	runCommand(t, repoRoot, "git", "checkout", "main")
	writeFixtureFile(t, repoRoot, "README.md", "mainline release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelogWithRelease(
		map[string][]string{
			"Fixed": {"keep release numbering when historic tags are not merged into main"},
		},
		"v1.1.1",
	))
	commitAll(t, repoRoot, "fix: keep release numbering after lineage reset")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.1.2" {
		t.Fatalf("expected fallback tag to yield v1.1.2, got %s", result.Version)
	}
	if result.BaseTag != "v1.1.1" {
		t.Fatalf("expected fallback base tag v1.1.1, got %s", result.BaseTag)
	}
}

func TestResolveReleaseVersionFallbackIgnoresTagsOutsideChangelogLineage(t *testing.T) {
	t.Parallel()

	repoRoot := initReleaseFixtureRepo(t)

	runCommand(t, repoRoot, "git", "checkout", "--orphan", "release-history")
	writeFixtureFile(t, repoRoot, "README.md", "prior release history\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(nil))
	commitAll(t, repoRoot, "chore: prior release history")
	runCommand(t, repoRoot, "git", "tag", "v1.1.1")

	runCommand(t, repoRoot, "git", "checkout", "main")
	runCommand(t, repoRoot, "git", "checkout", "-b", "release-preview")
	writeFixtureFile(t, repoRoot, "preview.txt", "preview branch only\n")
	commitAll(t, repoRoot, "chore: preview-only release")
	runCommand(t, repoRoot, "git", "tag", "v9.9.9")

	runCommand(t, repoRoot, "git", "checkout", "main")
	writeFixtureFile(t, repoRoot, "README.md", "mainline release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelogWithRelease(
		map[string][]string{
			"Fixed": {"keep release numbering on the documented release lineage"},
		},
		"v1.1.1",
	))
	commitAll(t, repoRoot, "fix: keep release numbering on release lineage")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.1.2" {
		t.Fatalf("expected changelog-lineage fallback to yield v1.1.2, got %s", result.Version)
	}
	if result.BaseTag != "v1.1.1" {
		t.Fatalf("expected changelog-lineage base tag v1.1.1, got %s", result.BaseTag)
	}
}

func TestResolveReleaseVersionFailsClosedForUnreachableTagsOutsideChangelogLineage(t *testing.T) {
	t.Parallel()

	repoRoot := initReleaseFixtureRepo(t)

	runCommand(t, repoRoot, "git", "checkout", "-b", "release-preview")
	writeFixtureFile(t, repoRoot, "preview.txt", "preview branch only\n")
	commitAll(t, repoRoot, "chore: preview-only release")
	runCommand(t, repoRoot, "git", "tag", "v9.9.9")

	runCommand(t, repoRoot, "git", "checkout", "main")
	writeFixtureFile(t, repoRoot, "README.md", "mainline release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"refuse unreachable preview tags outside release lineage"},
		},
	))
	commitAll(t, repoRoot, "fix: refuse preview release tag fallback")

	_, stderr, err := runReleaseVersionResolverRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected resolver to fail closed for unreachable tags outside changelog lineage")
	}
	if !strings.Contains(stderr, "semantic version tags exist but none are reachable from HEAD or documented in CHANGELOG.md release lineage") {
		t.Fatalf("expected release-lineage failure, got %q", stderr)
	}
}

func TestValidateReleaseChangelogFallbackIgnoresTagsOutsideChangelogLineage(t *testing.T) {
	t.Parallel()

	repoRoot := initReleaseFixtureRepo(t)

	runCommand(t, repoRoot, "git", "checkout", "--orphan", "release-history")
	writeFixtureFile(t, repoRoot, "README.md", "prior release history\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(nil))
	commitAll(t, repoRoot, "chore: prior release history")
	runCommand(t, repoRoot, "git", "tag", "v1.1.1")

	runCommand(t, repoRoot, "git", "checkout", "main")
	runCommand(t, repoRoot, "git", "checkout", "-b", "release-preview")
	writeFixtureFile(t, repoRoot, "preview.txt", "preview branch only\n")
	commitAll(t, repoRoot, "chore: preview-only release")
	runCommand(t, repoRoot, "git", "tag", "v9.9.9")

	runCommand(t, repoRoot, "git", "checkout", "main")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureFinalizedChangelog("v1.1.2", "v1.1.1"))
	commitAll(t, repoRoot, "chore: finalize changelog")
	runCommand(t, repoRoot, "git", "tag", "v1.1.2")

	result := runValidateReleaseChangelog(t, repoRoot, "v1.1.2")
	if result.BaseTag != "v1.1.1" {
		t.Fatalf("expected changelog-lineage validation base tag v1.1.1, got %s", result.BaseTag)
	}
}

func TestResolveReleaseVersionFailsClosedWithoutSignal(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "unsignaled change\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(nil))
	commitAll(t, repoRoot, "chore: internal refactor")

	_, stderr, err := runReleaseVersionResolverRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected resolver to fail without unreleased semver signal")
	}
	expected := "could not infer semver bump from CHANGELOG.md Unreleased"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected stderr to contain %q, got %q", expected, stderr)
	}
}

func TestFinalizeReleaseChangelogPromotesEntriesAndResetsUnreleased(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Added": {"[semver:patch] operator wording cleanup only"},
			"Fixed": {"tightened proof-chain verification failure handling"},
		},
	))
	commitAll(t, repoRoot, "docs: stage release changelog")

	result := runFinalizeReleaseChangelog(t, repoRoot, "--release-date", "2026-03-27")
	if result.Version != "v1.2.4" {
		t.Fatalf("expected finalized version v1.2.4, got %s", result.Version)
	}
	if result.Bump != "patch" {
		t.Fatalf("expected finalized patch bump, got %s", result.Bump)
	}
	if result.ReleaseDate != "2026-03-27" {
		t.Fatalf("expected release date 2026-03-27, got %s", result.ReleaseDate)
	}

	changelog := mustReadFile(t, filepath.Join(repoRoot, "CHANGELOG.md"))
	for _, required := range []string{
		"## [Unreleased]",
		"### Deprecated",
		"### Removed",
		"## [v1.2.4] - 2026-03-27",
		"<!-- release-semver: patch -->",
		"- operator wording cleanup only",
		"- tightened proof-chain verification failure handling",
	} {
		if !strings.Contains(changelog, required) {
			t.Fatalf("expected finalized changelog to contain %q", required)
		}
	}
	if strings.Contains(changelog, "[semver:patch]") {
		t.Fatal("expected semver control marker to be stripped from finalized release notes")
	}
	unreleased := strings.SplitN(strings.SplitN(changelog, "## [v1.2.4] - 2026-03-27", 2)[0], "## Changelog maintenance process", 2)[0]
	if strings.Contains(unreleased, "operator wording cleanup only") {
		t.Fatal("expected promoted release notes to be removed from Unreleased")
	}
}

func TestFinalizeReleaseChangelogFailsClosedOnUnknownUnreleasedSections(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "release prep\n")
	changelog := strings.Replace(
		fixtureChangelog(
			map[string][]string{
				"Fixed": {"tightened proof-chain verification failure handling"},
			},
		),
		"## Changelog maintenance process",
		"### Notes\n\n- this entry sits under an unknown section\n\n## Changelog maintenance process",
		1,
	)
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", changelog)
	commitAll(t, repoRoot, "docs: stage malformed release changelog")

	_, stderr, err := runFinalizeReleaseChangelogRaw(t, repoRoot, "--release-date", "2026-03-27")
	if err == nil {
		t.Fatal("expected finalize to fail on unknown unreleased sections")
	}
	if !strings.Contains(stderr, "releasable entries under unknown sections: Notes") {
		t.Fatalf("expected unknown-section failure, got %q", stderr)
	}
}

func TestValidateReleaseChangelogMatchesVersionedSection(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"tightened proof-chain verification failure handling"},
		},
	))
	commitAll(t, repoRoot, "docs: stage release changelog")

	runFinalizeReleaseChangelog(t, repoRoot, "--release-date", "2026-03-27")
	result := runValidateReleaseChangelog(t, repoRoot, "v1.2.4")
	if result.Status != "ok" {
		t.Fatalf("expected validate status ok, got %s", result.Status)
	}
	if result.Bump != "patch" {
		t.Fatalf("expected validate bump patch, got %s", result.Bump)
	}
	if result.BaseTag != "v1.2.3" {
		t.Fatalf("expected validate base tag v1.2.3, got %s", result.BaseTag)
	}
}

func TestValidateReleaseChangelogFailsWhenUnreleasedStillHasEntries(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"tightened proof-chain verification failure handling"},
		},
	))
	commitAll(t, repoRoot, "docs: stage release changelog")

	runFinalizeReleaseChangelog(t, repoRoot, "--release-date", "2026-03-27")
	addUnreleasedEntry(t, repoRoot, "Changed", "post-finalization drift should fail validation")

	_, stderr, err := runValidateReleaseChangelogRaw(t, repoRoot, "v1.2.4")
	if err == nil {
		t.Fatal("expected validate script to fail when Unreleased is not reset")
	}
	if !strings.Contains(stderr, "Unreleased still contains releasable entries") {
		t.Fatalf("expected unreleased-reset failure, got %q", stderr)
	}
}

func TestResolveReleaseVersionAfterFinalizedReleaseOnlyUsesNewUnreleasedEntries(t *testing.T) {
	t.Parallel()

	repoRoot := initTaggedReleaseFixtureRepo(t, "v1.2.3")
	writeFixtureFile(t, repoRoot, "README.md", "release prep\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(
		map[string][]string{
			"Fixed": {"tightened proof-chain verification failure handling"},
		},
	))
	commitAll(t, repoRoot, "docs: stage release changelog")

	runFinalizeReleaseChangelog(t, repoRoot, "--release-date", "2026-03-27")
	commitAll(t, repoRoot, "docs: finalize v1.2.4 changelog")
	runCommand(t, repoRoot, "git", "tag", "v1.2.4")

	writeFixtureFile(t, repoRoot, "README.md", "next release prep\n")
	addUnreleasedEntry(t, repoRoot, "Added", "new org-wide approval-gap summary")
	commitAll(t, repoRoot, "feat: add org-wide approval-gap summary")

	result := runReleaseVersionResolver(t, repoRoot)
	if result.Version != "v1.3.0" {
		t.Fatalf("expected next release version v1.3.0, got %s", result.Version)
	}
	if result.BaseTag != "v1.2.4" {
		t.Fatalf("expected next base tag v1.2.4, got %s", result.BaseTag)
	}
	if result.Bump != "minor" {
		t.Fatalf("expected next bump minor, got %s", result.Bump)
	}
}

func TestCutReleaseSkillReferencesDeterministicResolver(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	skillPath := filepath.Join(repoRoot, "factory/skills/cut-release/SKILL.md")
	skill := readFactorySkillOrSkip(t, skillPath)

	for _, token := range []string{
		"factory/scripts/resolve_release_version.py --repo-root . --json",
		"factory/scripts/finalize_release_changelog.py --repo-root . --release-version <version> --json",
		"factory/scripts/validate_release_changelog.py --repo-root . --release-version <version> --json",
		"release-prep PR",
		"profile `cut_release.versioning.resolver`",
		"profile `cut_release.release.workflow`",
		"[semver:major]",
		"[semver:minor]",
		"[semver:patch]",
		"changelog",
	} {
		if !strings.Contains(skill, token) {
			t.Fatalf("expected cut-release skill to reference %q", token)
		}
	}
}

func TestReleaseWorkflowValidatesVersionedChangelog(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	workflow := mustReadFile(t, filepath.Join(repoRoot, ".github/workflows/release.yml"))
	if !strings.Contains(workflow, "python3 scripts/validate_release_changelog.py --release-version \"${GITHUB_REF_NAME}\" --json") {
		t.Fatal("release workflow must validate the finalized changelog against the release tag")
	}
}

func initReleaseFixtureRepo(t *testing.T) string {
	t.Helper()

	repoRoot := t.TempDir()
	runCommand(t, repoRoot, "git", "init", "-b", "main")
	runCommand(t, repoRoot, "git", "config", "user.name", "Wrkr Tests")
	runCommand(t, repoRoot, "git", "config", "user.email", "wrkr-tests@example.com")
	writeFixtureFile(t, repoRoot, "README.md", "fixture\n")
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", fixtureChangelog(nil))
	commitAll(t, repoRoot, "chore: initial fixture")
	return repoRoot
}

func initTaggedReleaseFixtureRepo(t *testing.T, tag string) string {
	t.Helper()

	repoRoot := initReleaseFixtureRepo(t)
	runCommand(t, repoRoot, "git", "tag", tag)
	return repoRoot
}

func fixtureChangelog(entries map[string][]string) string {
	sections := []string{"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}
	lines := []string{
		"# Changelog",
		"",
		"## [Unreleased]",
		"",
	}

	for _, section := range sections {
		lines = append(lines, "### "+section, "")
		sectionEntries := entries[section]
		if len(sectionEntries) == 0 {
			lines = append(lines, "- (none yet)", "")
			continue
		}
		for _, entry := range sectionEntries {
			lines = append(lines, "- "+entry)
		}
		lines = append(lines, "")
	}

	lines = append(
		lines,
		"## Changelog maintenance process",
		"",
		"1. Update `## [Unreleased]` in every PR that changes user-visible behavior, contracts, or governance process.",
		"2. Before release tagging, run `python3 scripts/finalize_release_changelog.py --json` to promote releasable `Unreleased` entries into a dated versioned section and land that change through a release-prep PR.",
		"3. Validate the prepared release changelog with `python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json` on merged main before or during the tag workflow.",
	)

	return strings.Join(lines, "\n")
}

func fixtureChangelogWithRelease(entries map[string][]string, releaseVersion string) string {
	return fixtureChangelog(entries) + "\n\n" + fixtureReleaseBlock(releaseVersion)
}

func fixtureFinalizedChangelog(releaseVersion string, previousVersion string) string {
	sections := []string{"Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"}
	lines := []string{
		"# Changelog",
		"",
		"## [Unreleased]",
		"",
	}
	for _, section := range sections {
		lines = append(lines, "### "+section, "", "- (none yet)", "")
	}
	lines = append(lines, "## Changelog maintenance process", "")
	lines = append(lines,
		"1. Update `## [Unreleased]` in every PR that changes user-visible behavior, contracts, or governance process.",
		"2. Before release tagging, run `python3 scripts/finalize_release_changelog.py --json` to promote releasable `Unreleased` entries into a dated versioned section and land that change through a release-prep PR.",
		"3. Validate the prepared release changelog with `python3 scripts/validate_release_changelog.py --release-version vX.Y.Z --json` on merged main before or during the tag workflow.",
		"",
	)
	lines = append(lines, strings.Split(fixtureReleaseBlock(releaseVersion), "\n")...)
	lines = append(lines, strings.Split(fixtureReleaseBlock(previousVersion), "\n")...)
	return strings.Join(lines, "\n")
}

func fixtureReleaseBlock(version string) string {
	return strings.Join([]string{
		"## [" + version + "] - 2026-04-01",
		"<!-- release-semver: patch -->",
		"",
		"### Fixed",
		"",
		"- keep release numbering on the documented release lineage",
	}, "\n")
}

func TestReleaseDocsReferenceReleasePrepPRFlow(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	for _, relPath := range []string{
		"CHANGELOG.md",
		"CONTRIBUTING.md",
		"docs/map.md",
		"docs/trust/changelog-and-release-versioning.md",
		"docs/trust/release-integrity.md",
	} {
		content := mustReadFile(t, filepath.Join(repoRoot, relPath))
		if !strings.Contains(content, "release-prep PR") {
			t.Fatalf("expected %s to mention release-prep PR flow", relPath)
		}
	}
}

func TestReleaseIntegrityDocsDescribeVerifyThenPublishSequence(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content := mustReadFile(t, filepath.Join(repoRoot, "docs/trust/release-integrity.md"))

	required := []string{
		"build candidate artifacts without publishing them",
		"verify checksums",
		"generate an sbom",
		"run grype",
		"sign the checksum manifest",
		"generate and verify provenance attestations",
		"publish github release assets and homebrew tap updates",
	}
	for _, fragment := range required {
		if !strings.Contains(strings.ToLower(content), fragment) {
			t.Fatalf("expected release-integrity docs to mention %q", fragment)
		}
	}
}

func addUnreleasedEntry(t *testing.T, repoRoot string, section string, entry string) {
	t.Helper()

	path := filepath.Join(repoRoot, "CHANGELOG.md")
	normalized := strings.ReplaceAll(mustReadFile(t, path), "\r\n", "\n")
	marker := "### " + section + "\n\n- (none yet)"
	replacement := "### " + section + "\n\n- " + entry
	updated := strings.Replace(normalized, marker, replacement, 1)
	if updated == normalized {
		t.Fatalf("could not add unreleased entry for section %s", section)
	}
	writeFixtureFile(t, repoRoot, "CHANGELOG.md", updated)
}

func commitAll(t *testing.T, repoRoot string, message string) {
	t.Helper()

	runCommand(t, repoRoot, "git", "add", "-A")
	runCommand(t, repoRoot, "git", "commit", "-m", message)
}

func writeFixtureFile(t *testing.T, repoRoot string, relPath string, content string) {
	t.Helper()

	path := filepath.Join(repoRoot, filepath.Clean(relPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func runReleaseVersionResolver(t *testing.T, repoRoot string) changelogReleaseResult {
	t.Helper()

	stdout, stderr, err := runReleaseVersionResolverRaw(t, repoRoot)
	if err != nil {
		t.Fatalf("run release version resolver: %v\nstderr=%s", err, stderr)
	}

	var result changelogReleaseResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse resolver json: %v\nstdout=%s", err, stdout)
	}
	return result
}

func runReleaseVersionResolverRaw(t *testing.T, repoRoot string, args ...string) (string, string, error) {
	t.Helper()

	return runPythonScript(t, repoRoot, "resolve_release_version.py", args...)
}

func runFinalizeReleaseChangelog(t *testing.T, repoRoot string, args ...string) changelogReleaseResult {
	t.Helper()

	stdout, stderr, err := runFinalizeReleaseChangelogRaw(t, repoRoot, args...)
	if err != nil {
		t.Fatalf("run finalize release changelog: %v\nstderr=%s", err, stderr)
	}

	var result changelogReleaseResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse finalize json: %v\nstdout=%s", err, stdout)
	}
	return result
}

func runFinalizeReleaseChangelogRaw(t *testing.T, repoRoot string, args ...string) (string, string, error) {
	t.Helper()

	return runPythonScript(t, repoRoot, "finalize_release_changelog.py", args...)
}

func runValidateReleaseChangelog(t *testing.T, repoRoot string, releaseVersion string) changelogReleaseResult {
	t.Helper()

	stdout, stderr, err := runValidateReleaseChangelogRaw(t, repoRoot, releaseVersion)
	if err != nil {
		t.Fatalf("run validate release changelog: %v\nstderr=%s", err, stderr)
	}

	var result changelogReleaseResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse validate json: %v\nstdout=%s", err, stdout)
	}
	return result
}

func runValidateReleaseChangelogRaw(t *testing.T, repoRoot string, releaseVersion string) (string, string, error) {
	t.Helper()

	return runPythonScript(t, repoRoot, "validate_release_changelog.py", "--release-version", releaseVersion)
}

func runPythonScript(t *testing.T, repoRoot string, scriptName string, args ...string) (string, string, error) {
	t.Helper()

	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available in test environment")
	}

	scriptPath := filepath.Join(mustFindRepoRoot(t), "scripts", scriptName)
	cmdArgs := append([]string{scriptPath, "--repo-root", repoRoot, "--json"}, args...)
	cmd := exec.Command(pythonPath, cmdArgs...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		return "", text, err
	}
	return text, "", nil
}

func runCommand(t *testing.T, dir string, name string, args ...string) {
	t.Helper()

	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run %s %s: %v\noutput=%s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}
