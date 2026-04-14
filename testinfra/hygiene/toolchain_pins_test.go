package hygiene

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCheckToolchainPinsPassesWhenAligned(t *testing.T) {
	t.Parallel()

	fixtureRoot := writeToolchainPinFixture(t, fixturePins{
		gosecVersion:        "v2.23.0",
		golangciLintVersion: "v2.0.1",
		cosignVersion:       "v2.5.3",
		syftVersion:         "v1.32.0",
		grypeVersion:        "v0.99.1",
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
		cosignVersion:       "v2.5.3",
		syftVersion:         "v1.32.0",
		grypeVersion:        "v0.99.1",
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

func TestCheckToolchainPinsFailsOnReleaseIntegrityDrift(t *testing.T) {
	t.Parallel()

	fixtureRoot := writeToolchainPinFixture(t, fixturePins{
		gosecVersion:        "v2.23.0",
		golangciLintVersion: "v2.0.1",
		cosignVersion:       "v2.4.3",
		syftVersion:         "v1.32.0",
		grypeVersion:        "v0.99.1",
	})
	_, stderr, err := runToolchainPinCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected checker to fail on release-integrity pin drift")
	}
	expected := "pin mismatch for cosign: expected v2.5.3 from product/dev_guides.md, found v2.4.3 in .github/workflows/release.yml"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic mismatch message %q, got %q", expected, stderr)
	}
}

func TestCheckToolchainPinsFailsWhenAgentsPinsExplicitGoVersion(t *testing.T) {
	t.Parallel()

	fixtureRoot := writeToolchainPinFixture(t, fixturePins{
		gosecVersion:        "v2.23.0",
		golangciLintVersion: "v2.0.1",
		cosignVersion:       "v2.5.3",
		syftVersion:         "v1.32.0",
		grypeVersion:        "v0.99.1",
		agentsContent: strings.Join([]string{
			"# AGENTS.md",
			"",
			"- Go `1.26.1`",
			"",
		}, "\n"),
	})
	_, stderr, err := runToolchainPinCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected checker to fail when AGENTS.md pins an explicit Go version")
	}
	expected := "AGENTS.md must delegate Go toolchain authority to go.mod and product/dev_guides.md; remove explicit Go version literals"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic AGENTS drift message %q, got %q", expected, stderr)
	}
}

func TestReleaseWorkflowUsesDocumentedReleaseIntegrityPins(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	devGuides := mustReadFile(t, filepath.Join(repoRoot, "product/dev_guides.md"))
	releaseWorkflow := mustReadFile(t, filepath.Join(repoRoot, ".github/workflows/release.yml"))

	expectations := []struct {
		tool       string
		needle     string
		valueLabel string
	}{
		{tool: "Syft", needle: "syft-version:", valueLabel: "Syft"},
		{tool: "Grype", needle: "grype-version:", valueLabel: "Grype"},
		{tool: "cosign", needle: "cosign-release:", valueLabel: "cosign"},
	}

	for _, item := range expectations {
		expectedVersion := mustReadExpectedPin(t, devGuides, item.valueLabel)
		expectedLine := item.needle + " " + expectedVersion
		if !strings.Contains(releaseWorkflow, expectedLine) {
			t.Fatalf("expected release workflow to contain %q for %s pin contract", expectedLine, item.tool)
		}
	}
}

type fixturePins struct {
	gosecVersion        string
	golangciLintVersion string
	cosignVersion       string
	syftVersion         string
	grypeVersion        string
	agentsContent       string
}

func writeToolchainPinFixture(t *testing.T, versions fixturePins) string {
	t.Helper()

	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, ".tool-versions"), strings.Join([]string{
		"golang 1.26.2",
		"python 3.13.1",
		"nodejs 22.14.0",
		"",
	}, "\n"))
	mustWriteFile(t, filepath.Join(root, "go.mod"), "module fixture\n\ngo 1.26.2\n")
	mustWriteFile(t, filepath.Join(root, "Makefile"), "lint-fast:\n\t@echo ok\n")

	mustWriteFile(t, filepath.Join(root, "product/dev_guides.md"), strings.Join([]string{
		"| Tool | Pinned Version |",
		"|------|----------------|",
		"| gosec | `v2.23.0` |",
		"| golangci-lint | `v2.0.1` |",
		"| cosign | `v2.5.3` |",
		"| Syft | `v1.32.0` |",
		"| Grype | `v0.99.1` |",
		"",
	}, "\n"))
	agentsContent := versions.agentsContent
	if agentsContent == "" {
		agentsContent = strings.Join([]string{
			"# AGENTS.md",
			"",
			"- Go: follow `go.mod` for the enforced floor and `product/dev_guides.md` for the org-wide version policy.",
			"",
		}, "\n")
	}
	mustWriteFile(t, filepath.Join(root, "AGENTS.md"), agentsContent)

	workflow := strings.Join([]string{
		"name: fixture",
		"jobs:",
		"  fast-lane:",
		"    steps:",
		"      - run: go install github.com/securego/gosec/v2/cmd/gosec@" + versions.gosecVersion,
		"      - run: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + versions.golangciLintVersion,
		"",
	}, "\n")
	mustWriteFile(t, filepath.Join(root, ".github/workflows/pr.yml"), workflow)
	releaseWorkflow := strings.Join([]string{
		"name: release",
		"jobs:",
		"  release-artifacts:",
		"    steps:",
		"      - uses: anchore/sbom-action@v0",
		"        with:",
		"          syft-version: " + versions.syftVersion,
		"      - uses: anchore/scan-action@v4",
		"        with:",
		"          grype-version: " + versions.grypeVersion,
		"      - uses: sigstore/cosign-installer@v3",
		"        with:",
		"          cosign-release: " + versions.cosignVersion,
		"",
	}, "\n")
	mustWriteFile(t, filepath.Join(root, ".github/workflows/release.yml"), releaseWorkflow)

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

func mustReadExpectedPin(t *testing.T, content string, tool string) string {
	t.Helper()

	pattern := regexp.MustCompile(`(?m)^\|\s*` + regexp.QuoteMeta(tool) + `\s*\|\s*` + "`" + `([^` + "`" + `]+)` + "`" + `\s*\|`)
	matches := pattern.FindStringSubmatch(content)
	if len(matches) != 2 {
		t.Fatalf("expected to find pinned version for %s", tool)
	}
	return matches[1]
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
