package hygiene

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type releaseVersionResult struct {
	BaseTag string `json:"base_tag"`
	Bump    string `json:"bump"`
	Reason  string `json:"reason"`
	Source  string `json:"source"`
	Version string `json:"version"`
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

func TestCutReleaseSkillReferencesDeterministicResolver(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	skillPath := filepath.Join(repoRoot, ".agents/skills/cut-release/SKILL.md")
	skill := mustReadFile(t, skillPath)

	for _, token := range []string{
		"python3 scripts/resolve_release_version.py --json",
		"[semver:major]",
		"[semver:minor]",
		"[semver:patch]",
		"CHANGELOG.md",
	} {
		if !strings.Contains(skill, token) {
			t.Fatalf("expected cut-release skill to reference %q", token)
		}
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

	return strings.Join(lines, "\n")
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

func runReleaseVersionResolver(t *testing.T, repoRoot string) releaseVersionResult {
	t.Helper()

	stdout, stderr, err := runReleaseVersionResolverRaw(t, repoRoot)
	if err != nil {
		t.Fatalf("run release version resolver: %v\nstderr=%s", err, stderr)
	}

	var result releaseVersionResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse resolver json: %v\nstdout=%s", err, stdout)
	}
	return result
}

func runReleaseVersionResolverRaw(t *testing.T, repoRoot string) (string, string, error) {
	t.Helper()

	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available in test environment")
	}

	scriptPath := filepath.Join(mustFindRepoRoot(t), "scripts/resolve_release_version.py")
	cmd := exec.Command(pythonPath, scriptPath, "--repo-root", repoRoot, "--json")
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
