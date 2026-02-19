package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestToolchainPinsAreExact(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content, err := os.ReadFile(filepath.Join(repoRoot, ".tool-versions"))
	if err != nil {
		t.Fatalf("read .tool-versions: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(content)), "\n")
	want := []string{"golang 1.25.7", "python 3.13.1", "nodejs 22.14.0"}
	for _, line := range want {
		if !containsLine(got, line) {
			t.Fatalf("missing pinned version %q in .tool-versions", line)
		}
	}
}

func TestMakeTargetsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	text := string(content)
	for _, target := range []string{
		"fmt:", "lint:", "lint-fast:", "test:", "test-fast:", "test-integration:",
		"test-e2e:", "build:", "hooks:", "prepush:", "prepush-full:",
	} {
		if !strings.Contains(text, "\n"+target) && !strings.HasPrefix(text, target) {
			t.Fatalf("required make target missing: %s", strings.TrimSuffix(target, ":"))
		}
	}
}

func TestNoFloatingLatestInBuildConfigs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	files := []string{
		"Makefile",
		".pre-commit-config.yaml",
		".github/workflows/pr.yml",
		".github/workflows/main.yml",
		".github/workflows/nightly.yml",
		".github/workflows/release.yml",
	}
	for _, rel := range files {
		content, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(content), "@latest") {
			t.Fatalf("floating @latest found in %s", rel)
		}
	}
}

func TestRequiredChecksContractTargetsPROnlyJobs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	requiredChecks := loadRequiredChecks(t, repoRoot)
	if len(requiredChecks) == 0 {
		t.Fatal("required checks contract must include at least one check")
	}

	dupes := duplicateEntries(requiredChecks)
	if len(dupes) > 0 {
		t.Fatalf("required checks contract contains duplicates: %v", dupes)
	}
	if !sort.StringsAreSorted(append([]string(nil), requiredChecks...)) {
		t.Fatalf("required checks contract must be sorted for deterministic diffs: %v", requiredChecks)
	}

	prChecks := map[string]struct{}{}
	workflowPaths := listWorkflowFiles(t, repoRoot)
	prWorkflowCount := 0
	for _, path := range workflowPaths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read workflow %s: %v", path, err)
		}
		text := string(content)
		if !hasPullRequestTrigger(text) {
			continue
		}
		prWorkflowCount++
		for check := range parseWorkflowStatusChecks(text) {
			prChecks[check] = struct{}{}
		}
	}

	if prWorkflowCount == 0 {
		t.Fatal("expected at least one pull_request workflow")
	}

	for _, required := range requiredChecks {
		if _, ok := prChecks[required]; !ok {
			keys := make([]string, 0, len(prChecks))
			for key := range prChecks {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			t.Fatalf(
				"required check %q does not map to any pull_request workflow status; available PR checks: %v",
				required,
				keys,
			)
		}
	}
}

func TestWorkflowConcurrencyConfigured(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	required := []string{
		".github/workflows/pr.yml",
		".github/workflows/main.yml",
		".github/workflows/nightly.yml",
		".github/workflows/release.yml",
	}
	for _, rel := range required {
		content, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		text := string(content)
		if !strings.Contains(text, "\nconcurrency:\n") {
			t.Fatalf("workflow missing concurrency block: %s", rel)
		}
		if !strings.Contains(text, "cancel-in-progress: true") {
			t.Fatalf("workflow missing cancel-in-progress setting: %s", rel)
		}
	}
}

func TestPRWorkflowPathFilterContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content, err := os.ReadFile(filepath.Join(repoRoot, ".github/workflows/pr.yml"))
	if err != nil {
		t.Fatalf("read .github/workflows/pr.yml: %v", err)
	}
	text := string(content)
	for _, fragment := range []string{
		"dorny/paths-filter@v3",
		"workflow_or_policy:",
		"Skip deep scanners for non-code changes",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("pr workflow missing required path-filter fragment %q", fragment)
		}
	}
}

func TestWorkflowTriggerContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	prWorkflow := mustReadFile(t, filepath.Join(repoRoot, ".github/workflows/pr.yml"))
	if !hasPullRequestTrigger(prWorkflow) {
		t.Fatal("pr workflow must include pull_request trigger")
	}

	mainWorkflow := mustReadFile(t, filepath.Join(repoRoot, ".github/workflows/main.yml"))
	if !strings.Contains(mainWorkflow, "push:") || !strings.Contains(mainWorkflow, "- main") {
		t.Fatal("main workflow must include push trigger for main branch")
	}

	releaseWorkflow := mustReadFile(t, filepath.Join(repoRoot, ".github/workflows/release.yml"))
	if !strings.Contains(releaseWorkflow, "tags:") || !strings.Contains(releaseWorkflow, "v*") {
		t.Fatal("release workflow must include version tag trigger")
	}

	nightlyWorkflow := mustReadFile(t, filepath.Join(repoRoot, ".github/workflows/nightly.yml"))
	if !strings.Contains(nightlyWorkflow, "schedule:") {
		t.Fatal("nightly workflow must include schedule trigger")
	}
}

func loadRequiredChecks(t *testing.T, repoRoot string) []string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(repoRoot, ".github/required-checks.json"))
	if err != nil {
		t.Fatalf("read required checks contract: %v", err)
	}

	var payload struct {
		RequiredChecks []string `json:"required_checks"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		t.Fatalf("parse required checks contract: %v", err)
	}
	return payload.RequiredChecks
}

func listWorkflowFiles(t *testing.T, repoRoot string) []string {
	t.Helper()

	yml, err := filepath.Glob(filepath.Join(repoRoot, ".github/workflows/*.yml"))
	if err != nil {
		t.Fatalf("glob workflow files (*.yml): %v", err)
	}
	yaml, err := filepath.Glob(filepath.Join(repoRoot, ".github/workflows/*.yaml"))
	if err != nil {
		t.Fatalf("glob workflow files (*.yaml): %v", err)
	}
	files := append(yml, yaml...)
	sort.Strings(files)
	return files
}

func duplicateEntries(values []string) []string {
	seen := map[string]int{}
	for _, value := range values {
		key := strings.TrimSpace(value)
		seen[key]++
	}

	dupes := make([]string, 0)
	for key, count := range seen {
		if count > 1 {
			dupes = append(dupes, key)
		}
	}
	sort.Strings(dupes)
	return dupes
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func hasPullRequestTrigger(workflow string) bool {
	return regexp.MustCompile(`(?m)^\s*pull_request\s*:`).MatchString(workflow)
}

func parseWorkflowStatusChecks(workflow string) map[string]struct{} {
	jobIDPattern := regexp.MustCompile(`^  ([A-Za-z0-9_-]+):\s*$`)
	jobNamePattern := regexp.MustCompile(`^    name:\s*(.+)\s*$`)

	checks := map[string]struct{}{}
	lines := strings.Split(workflow, "\n")
	inJobs := false
	currentJobID := ""

	for _, line := range lines {
		if !inJobs {
			if strings.TrimSpace(line) == "jobs:" {
				inJobs = true
			}
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			break
		}

		if matches := jobIDPattern.FindStringSubmatch(line); len(matches) == 2 {
			currentJobID = matches[1]
			checks[currentJobID] = struct{}{}
			continue
		}

		if currentJobID == "" {
			continue
		}

		if matches := jobNamePattern.FindStringSubmatch(line); len(matches) == 2 {
			jobName := normalizeYAMLScalar(matches[1])
			if jobName != "" {
				checks[jobName] = struct{}{}
			}
		}
	}

	return checks
}

func normalizeYAMLScalar(value string) string {
	value = strings.TrimSpace(value)
	if strings.Contains(value, " #") {
		parts := strings.SplitN(value, " #", 2)
		value = strings.TrimSpace(parts[0])
	}
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
			value = strings.TrimSpace(value[1 : len(value)-1])
		}
	}
	return value
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(content)
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	current := wd
	for {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Fatalf("could not locate repo root from %s", wd)
		}
		current = parent
	}
}
