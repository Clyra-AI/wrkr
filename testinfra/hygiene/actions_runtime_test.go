package hygiene

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/ci/actionruntime"
)

func TestRepoRejectsDeprecatedGitHubActionRuntimeRefs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	findings, err := actionruntime.Scan(repoRoot)
	if err != nil {
		t.Fatalf("scan workflows: %v", err)
	}
	if len(findings) == 0 {
		return
	}

	lines := actionruntime.FormatFindings(findings)
	t.Fatalf("expected repo workflows to be free of deprecated runtime refs and override flags:\n%s", strings.Join(lines, "\n"))
}

func TestCheckActionsRuntimeFailsOnDeprecatedRefs(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/pr.yml", strings.Join([]string{
		"name: pr",
		"jobs:",
		"  fast-lane:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - name: Checkout",
		"        uses: actions/checkout@v4",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on deprecated workflow refs")
	}
	expected := "deprecated runtime use: .github/workflows/pr.yml -> actions/checkout@v4"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic deprecated-ref message %q, got %q", expected, stderr)
	}
}

func TestCheckActionsRuntimeFailsOnDisallowedOverrideFlags(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/pr.yml", strings.Join([]string{
		"name: pr",
		"jobs:",
		"  fast-lane:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - name: Override runtime",
		"        run: |",
		"          export FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true",
		"          echo forcing",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on disallowed override flags")
	}
	expected := "disallowed override policy: .github/workflows/pr.yml -> FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic override message %q, got %q", expected, stderr)
	}
}

func TestCheckActionsRuntimeFailsOnUnsecureNodeOverrideEnv(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/pr.yml", strings.Join([]string{
		"name: pr",
		"jobs:",
		"  fast-lane:",
		"    runs-on: ubuntu-latest",
		"    env:",
		"      ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: true",
		"    steps:",
		"      - name: Checkout",
		"        uses: actions/checkout@v6.0.2",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on unsecure node override env")
	}
	expected := "disallowed override policy: .github/workflows/pr.yml -> ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic override message %q, got %q", expected, stderr)
	}
}

func TestCheckActionsRuntimeFailsOnDynamicOverrideEnv(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/pr.yml", strings.Join([]string{
		"name: pr",
		"jobs:",
		"  fast-lane:",
		"    runs-on: ubuntu-latest",
		"    env:",
		"      ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION: ${{ vars.unsecure_node }}",
		"    steps:",
		"      - name: Checkout",
		"        uses: actions/checkout@v6.0.2",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on dynamic unsecure node override env")
	}
	expected := "disallowed override policy: .github/workflows/pr.yml -> ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=${{ vars.unsecure_node }}"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic override message %q, got %q", expected, stderr)
	}
}

func TestCheckActionsRuntimeFailsOnGithubEnvOverride(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/pr.yml", strings.Join([]string{
		"name: pr",
		"jobs:",
		"  fast-lane:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - name: Override runtime through GITHUB_ENV",
		"        run: |",
		"          echo \"FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true\" >> \"$GITHUB_ENV\"",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on GITHUB_ENV override writes")
	}
	expected := "disallowed override policy: .github/workflows/pr.yml -> FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic override message %q, got %q", expected, stderr)
	}
}

func TestCheckActionsRuntimePassesOnNode24ReadyRefs(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/pr.yml", strings.Join([]string{
		"name: pr",
		"jobs:",
		"  fast-lane:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - name: Checkout",
		"        uses: actions/checkout@v6.0.2",
		"      - name: Setup Go",
		"        uses: actions/setup-go@v6.3.0",
		"",
	}, "\n"))

	stdout, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err != nil {
		t.Fatalf("expected runtime check to pass, got err=%v stderr=%q", err, stderr)
	}
	if !strings.Contains(stdout, "github actions runtime contract: pass") {
		t.Fatalf("expected pass marker, got stdout=%q", stdout)
	}
}

func TestMovingActionRefRequiresOwnedExpiryException(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/release.yml", releaseWorkflowWithAction("anchore/sbom-action@v0"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on moving release action without exception")
	}
	expected := "moving action ref requires exception: .github/workflows/release.yml -> anchore/sbom-action@v0 (missing exception)"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected deterministic missing-exception message %q, got %q", expected, stderr)
	}
}

func TestMovingActionRefExceptionRequiresOwner(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/release.yml", releaseWorkflowWithAction("anchore/sbom-action@v0"))
	writeActionRefExceptionFixture(t, fixtureRoot, strings.Join([]string{
		"exceptions:",
		"  - workflow: .github/workflows/release.yml",
		"    action: anchore/sbom-action@v0",
		"    reason: scanner compatibility review",
		"    scope: SBOM only",
		"    expires: 2099-01-01",
		"    review_command: scripts/check_actions_runtime.sh",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on exception without owner")
	}
	expected := "anchore/sbom-action@v0 (missing owner)"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected missing-owner message %q, got %q", expected, stderr)
	}
}

func TestExpiredActionRefExceptionFails(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/release.yml", releaseWorkflowWithAction("anchore/sbom-action@v0"))
	writeActionRefExceptionFixture(t, fixtureRoot, strings.Join([]string{
		"exceptions:",
		"  - workflow: .github/workflows/release.yml",
		"    action: anchore/sbom-action@v0",
		"    owner: release-engineering",
		"    reason: scanner compatibility review",
		"    scope: SBOM only",
		"    expires: 2000-01-01",
		"    review_command: scripts/check_actions_runtime.sh",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail on expired exception")
	}
	expected := "anchore/sbom-action@v0 (expired exception)"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected expired-exception message %q, got %q", expected, stderr)
	}
}

func TestActionRefExceptionScopeMustMatchWorkflow(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/release.yml", releaseWorkflowWithAction("anchore/sbom-action@v0"))
	writeActionRefExceptionFixture(t, fixtureRoot, strings.Join([]string{
		"exceptions:",
		"  - workflow: .github/workflows/docs.yml",
		"    action: anchore/sbom-action@v0",
		"    owner: release-engineering",
		"    reason: scanner compatibility review",
		"    scope: SBOM only",
		"    expires: 2099-01-01",
		"    review_command: scripts/check_actions_runtime.sh",
		"",
	}, "\n"))

	_, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err == nil {
		t.Fatal("expected runtime check to fail when exception names a different workflow")
	}
	expected := "anchore/sbom-action@v0 (missing exception)"
	if !strings.Contains(stderr, expected) {
		t.Fatalf("expected workflow-scope mismatch to look like missing exact exception %q, got %q", expected, stderr)
	}
}

func TestPinnedActionRefDoesNotRequireException(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/release.yml", releaseWorkflowWithAction("actions/checkout@0123456789abcdef0123456789abcdef01234567"))

	stdout, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err != nil {
		t.Fatalf("expected pinned action to pass without exception, got err=%v stderr=%q", err, stderr)
	}
	if !strings.Contains(stdout, "github actions runtime contract: pass") {
		t.Fatalf("expected pass marker, got stdout=%q", stdout)
	}
}

func TestActiveActionRefExceptionAllowsMovingReleaseRef(t *testing.T) {
	t.Parallel()

	fixtureRoot := t.TempDir()
	writeWorkflowFixture(t, fixtureRoot, ".github/workflows/release.yml", releaseWorkflowWithAction("anchore/sbom-action@v0"))
	writeActionRefExceptionFixture(t, fixtureRoot, strings.Join([]string{
		"exceptions:",
		"  - workflow: .github/workflows/release.yml",
		"    action: anchore/sbom-action@v0",
		"    owner: release-engineering",
		"    reason: scanner compatibility review",
		"    scope: SBOM only",
		"    expires: 2099-01-01",
		"    review_command: scripts/check_actions_runtime.sh",
		"",
	}, "\n"))

	stdout, stderr, err := runActionsRuntimeCheck(t, fixtureRoot)
	if err != nil {
		t.Fatalf("expected active exception to pass, got err=%v stderr=%q", err, stderr)
	}
	if !strings.Contains(stdout, "github actions runtime contract: pass") {
		t.Fatalf("expected pass marker, got stdout=%q", stdout)
	}
}

func writeWorkflowFixture(t *testing.T, root, relPath, content string) {
	t.Helper()

	path := filepath.Join(root, filepath.Clean(relPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeActionRefExceptionFixture(t *testing.T, root string, content string) {
	t.Helper()

	writeWorkflowFixture(t, root, ".github/action-ref-exceptions.yaml", content)
}

func releaseWorkflowWithAction(action string) string {
	return strings.Join([]string{
		"name: release",
		"jobs:",
		"  release-artifacts:",
		"    runs-on: ubuntu-latest",
		"    steps:",
		"      - name: Release action",
		"        uses: " + action,
		"",
	}, "\n")
}

func runActionsRuntimeCheck(t *testing.T, workflowRoot string) (string, string, error) {
	t.Helper()

	repoRoot := mustFindRepoRoot(t)
	scriptPath := filepath.Join(repoRoot, "scripts", "check_actions_runtime.sh")
	cmd := exec.Command("bash", scriptPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "WRKR_ACTION_RUNTIME_ROOT="+workflowRoot)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}
