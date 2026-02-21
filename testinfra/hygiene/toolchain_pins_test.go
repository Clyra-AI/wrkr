package hygiene

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckToolchainPinsPassesWhenAligned(t *testing.T) {
	t.Parallel()

	fixtureRoot := writeToolchainPinFixture(t, fixturePins{
		gosecVersion:        "v2.23.0",
		golangciLintVersion: "v2.0.1",
	})
	_, stderr, err := runToolchainPinCheck(t, fixtureRoot)
	if err != nil {
		t.Fatalf("expected checker to pass, got err=%v stderr=%q", err, stderr)
	}
}

func TestCheckToolchainPinsFailsOnDrift(t *testing.T) {
	t.Parallel()

	fixtureRoot := writeToolchainPinFixture(t, fixturePins{
		gosecVersion:        "v2.22.1",
		golangciLintVersion: "v2.0.1",
	})
	_, stderr, err := runToolchainPinCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected checker to fail on pin drift")
	}
	expected := "pin mismatch for gosec: expected v2.23.0 from product/dev_guides.md, found v2.22.1 in .github/workflows/pr.yml"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic mismatch message %q, got %q", expected, stderr)
	}
}

type fixturePins struct {
	gosecVersion        string
	golangciLintVersion string
}

func writeToolchainPinFixture(t *testing.T, versions fixturePins) string {
	t.Helper()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, ".tool-versions"), strings.Join([]string{
		"golang 1.25.7",
		"python 3.13.1",
		"nodejs 22.14.0",
		"",
	}, "\n"))
	mustWriteFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.25.7\n")
	mustWriteFile(t, filepath.Join(root, "Makefile"), "lint-fast:\n\t@echo ok\n")

	mustWriteFile(t, filepath.Join(root, "product/dev_guides.md"), strings.Join([]string{
		"| Tool | Pinned Version |",
		"|------|----------------|",
		"| gosec | `v2.23.0` |",
		"| golangci-lint | `v2.0.1` |",
		"",
	}, "\n"))

	workflow := strings.Join([]string{
		"name: fixture",
		"jobs:",
		"  fast-lane:",
		"    steps:",
		"      - run: go install github.com/securego/gosec/v2/cmd/gosec@" + versions.gosecVersion,
		"      - run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@" + versions.golangciLintVersion,
		"",
	}, "\n")
	mustWriteFile(t, filepath.Join(root, ".github/workflows/pr.yml"), workflow)

	return root
}

func runToolchainPinCheck(t *testing.T, repoRoot string) (string, string, error) {
	t.Helper()

	scriptPath := filepath.Join(mustFindRepoRoot(t), "scripts/check_toolchain_pins.sh")
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = repoRoot

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
