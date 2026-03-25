//go:build scenario

package scenarios

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestPermissionFailureSurfacingScenario(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	workflowDir := filepath.Join(reposPath, "beta", ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "release.yml"), []byte("name: release\n"), 0o600); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}
	if err := os.Chmod(workflowDir, 0o000); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(workflowDir, 0o755)
	}()

	statePath := filepath.Join(tmp, "state.json")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", reposPath, "--state", statePath, "--json"})
	detectorErrors, ok := payload["detector_errors"].([]any)
	if !ok || len(detectorErrors) == 0 {
		t.Fatalf("expected detector_errors payload, got %v", payload["detector_errors"])
	}
	found := false
	for _, item := range detectorErrors {
		detectorErr, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if detectorErr["repo"] == "beta" && detectorErr["code"] == "permission_denied" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected permission_denied detector error for beta, got %v", detectorErrors)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--explain"}, &out, &errOut); code != 0 {
		t.Fatalf("explain scan failed: %d (%s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "scan completeness: some files or directories could not be read") {
		t.Fatalf("expected explain output to mention incomplete visibility, got %q", out.String())
	}
}
