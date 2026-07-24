package hygiene

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestAggregateCoverageGateEnforcesGovernedFloor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	exceptions := writeCoverageExceptions(t, root, "2099-12-31", 50, map[string]float64{})
	passingProfile := writeCoverageFixture(t, root, "passing.out", 5, 5)
	_, stderr, err := runCoveragePython(
		t,
		"scripts/check_go_coverage.py",
		passingProfile,
		"85",
		"--include-prefix", "github.com/Clyra-AI/wrkr/core/",
		"--exceptions", exceptions,
	)
	if err != nil {
		t.Fatalf("expected governed aggregate floor to pass, got err=%v stderr=%q", err, stderr)
	}

	regressedProfile := writeCoverageFixture(t, root, "regressed.out", 4, 6)
	_, stderr, err = runCoveragePython(
		t,
		"scripts/check_go_coverage.py",
		regressedProfile,
		"85",
		"--include-prefix", "github.com/Clyra-AI/wrkr/core/",
		"--exceptions", exceptions,
	)
	if err == nil || !strings.Contains(stderr, "governed_floor=50.00%") {
		t.Fatalf("expected aggregate regression to fail against governed floor, err=%v stderr=%q", err, stderr)
	}
}

func TestPerPackageCoverageGateFailsMissingAndRegressedBaselines(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outputPath := filepath.Join(root, "packages.txt")
	mustWriteFile(t, outputPath, "ok  \tgithub.com/Clyra-AI/wrkr/core/example\t1.0s\tcoverage: 49.0% of statements\n")

	missing := writeCoverageExceptions(t, filepath.Join(root, "missing"), "2099-12-31", 50, map[string]float64{})
	_, stderr, err := runCoveragePython(t, "scripts/check_go_package_coverage.py", outputPath, "75", missing)
	if err == nil || !strings.Contains(stderr, "exception=missing") {
		t.Fatalf("expected missing package baseline to fail, err=%v stderr=%q", err, stderr)
	}

	governed := writeCoverageExceptions(
		t,
		filepath.Join(root, "governed"),
		"2099-12-31",
		50,
		map[string]float64{"github.com/Clyra-AI/wrkr/core/example": 50},
	)
	_, stderr, err = runCoveragePython(t, "scripts/check_go_package_coverage.py", outputPath, "75", governed)
	if err == nil || !strings.Contains(stderr, "governed_floor=50.0%") {
		t.Fatalf("expected package regression to fail against governed floor, err=%v stderr=%q", err, stderr)
	}
}

func TestCoverageGateRejectsExpiredExceptions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	exceptions := writeCoverageExceptions(t, root, "2000-01-01", 50, map[string]float64{})
	profile := writeCoverageFixture(t, root, "coverage.out", 5, 5)
	_, stderr, err := runCoveragePython(
		t,
		"scripts/check_go_coverage.py",
		profile,
		"85",
		"--include-prefix", "github.com/Clyra-AI/wrkr/core/",
		"--exceptions", exceptions,
	)
	if err == nil || !strings.Contains(stderr, "coverage exceptions expired on 2000-01-01") {
		t.Fatalf("expected expired exception to fail closed, err=%v stderr=%q", err, stderr)
	}
}

func TestPerPackageCoverageGateRejectsStaleExceptionAfterTargetIsMet(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outputPath := filepath.Join(root, "packages.txt")
	mustWriteFile(t, outputPath, "ok  \tgithub.com/Clyra-AI/wrkr/core/example\t1.0s\tcoverage: 80.0% of statements\n")
	exceptions := writeCoverageExceptions(
		t,
		root,
		"2099-12-31",
		50,
		map[string]float64{"github.com/Clyra-AI/wrkr/core/example": 50},
	)
	_, stderr, err := runCoveragePython(t, "scripts/check_go_package_coverage.py", outputPath, "75", exceptions)
	if err == nil || !strings.Contains(stderr, "governed baseline is stale because coverage=80.0% meets target") {
		t.Fatalf("expected stale package exception to fail, err=%v stderr=%q", err, stderr)
	}
}

func TestCoverageGatesAreProtectedInAutomation(t *testing.T) {
	t.Parallel()

	root := mustFindRepoRoot(t)
	makefile := mustReadFile(t, filepath.Join(root, "Makefile"))
	for _, needle := range []string{
		"test-coverage:",
		"scripts/check_go_coverage.py",
		"scripts/check_go_package_coverage.py",
		".github/coverage-exceptions.json",
		"prepush-full: prepush lint test test-coverage",
	} {
		if !strings.Contains(makefile, needle) {
			t.Fatalf("Makefile coverage contract missing %q", needle)
		}
	}
	for _, workflow := range []string{"pr.yml", "main.yml", "release.yml"} {
		content := mustReadFile(t, filepath.Join(root, ".github/workflows", workflow))
		if !strings.Contains(content, "make test-coverage") {
			t.Fatalf("%s missing protected numeric coverage gate", workflow)
		}
	}
}

func writeCoverageExceptions(
	t *testing.T,
	root string,
	expires string,
	aggregateFloor float64,
	packageBaselines map[string]float64,
) string {
	t.Helper()

	path := filepath.Join(root, "coverage-exceptions.json")
	payload := map[string]any{
		"version":                 1,
		"owner":                   []string{"@coverage-owner"},
		"reason":                  "test governed coverage floor",
		"expires_on":              expires,
		"follow_up":               "raise coverage",
		"compensating_validation": []string{"make test-fast"},
		"aggregate_scopes": map[string]any{
			"go_core_and_command_packages": map[string]any{"minimum_percent": aggregateFloor},
		},
		"package_baselines": packageBaselines,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal coverage exceptions: %v", err)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir coverage fixture root: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatalf("write coverage exceptions: %v", err)
	}
	return path
}

func writeCoverageFixture(t *testing.T, root string, name string, covered, uncovered int) string {
	t.Helper()

	path := filepath.Join(root, name)
	content := strings.Join([]string{
		"mode: atomic",
		"github.com/Clyra-AI/wrkr/core/example/example.go:1.1,1.2 " + strconv.Itoa(covered) + " 1",
		"github.com/Clyra-AI/wrkr/core/example/example.go:2.1,2.2 " + strconv.Itoa(uncovered) + " 0",
		"",
	}, "\n")
	mustWriteFile(t, path, content)
	return path
}

func runCoveragePython(t *testing.T, relativeScript string, args ...string) (string, string, error) {
	t.Helper()

	root := mustFindRepoRoot(t)
	command := append([]string{filepath.Join(root, relativeScript)}, args...)
	cmd := exec.Command("python3", command...)
	cmd.Dir = root
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
