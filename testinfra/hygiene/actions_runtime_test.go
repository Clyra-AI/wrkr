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
