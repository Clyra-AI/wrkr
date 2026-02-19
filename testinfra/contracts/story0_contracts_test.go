package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func TestRequiredChecksContractIncludesCoreJobs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
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

	for _, required := range []string{
		"fast-lane",
		"windows-smoke",
		"core-matrix-ubuntu-latest",
		"acceptance",
		"codeql",
		"release-artifacts",
	} {
		if !containsLine(payload.RequiredChecks, required) {
			t.Fatalf("required check missing from contract: %s", required)
		}
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
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
