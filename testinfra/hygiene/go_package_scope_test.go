package hygiene

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirstPartyGoPackagesExcludeDocsSiteNodeModules(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	fixturePath := filepath.Join(repoRoot, "docs-site", "node_modules", "flatted", "golang", "pkg", "flatted", "flatted.go")
	if err := os.MkdirAll(filepath.Dir(fixturePath), 0o755); err != nil {
		t.Fatalf("mkdir node_modules fixture: %v", err)
	}
	if err := os.WriteFile(fixturePath, []byte("package flatted\n"), 0o644); err != nil {
		t.Fatalf("write node_modules fixture: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(fixturePath)
	})

	stdout, stderr, err := runFirstPartyPackageList(t, repoRoot)
	if err != nil {
		t.Fatalf("first-party package list failed: %v stderr=%q", err, stderr)
	}
	if strings.Contains(stdout, "docs-site/node_modules") {
		t.Fatalf("first-party package list included generated docs-site dependency package:\n%s", stdout)
	}
}

func TestFirstPartyGoPackagesEmitTrackedRootPatterns(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	stdout, stderr, err := runFirstPartyPackageList(t, repoRoot)
	if err != nil {
		t.Fatalf("first-party package list failed: %v stderr=%q", err, stderr)
	}
	patterns := strings.Fields(stdout)
	required := []string{
		"./cmd/...",
		"./core/...",
		"./internal/...",
		"./testinfra/...",
		"./scripts/...",
		"./scenarios/...",
	}
	for _, want := range required {
		if !containsString(patterns, want) {
			t.Fatalf("first-party package list missing %s\npatterns:\n%s", want, stdout)
		}
	}
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "github.com/Clyra-AI/wrkr/") {
			t.Fatalf("first-party package list must emit repo-relative patterns, got %q", pattern)
		}
	}
}

func TestWorkflowGoTestsUseFirstPartyPackageList(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	checkedPaths := []string{
		".github/workflows/pr.yml",
		".github/workflows/release.yml",
		"scripts/run_v1_acceptance.sh",
		"scripts/test_uat_local.sh",
		"Makefile",
	}
	for _, rel := range checkedPaths {
		payload := mustReadFile(t, filepath.Join(repoRoot, filepath.Clean(rel)))
		if strings.Contains(payload, "go test ./...") || strings.Contains(payload, "go vet ./...") {
			t.Fatalf("%s reintroduced unsafe root wildcard Go package discovery", rel)
		}
		if !strings.Contains(payload, "first_party_go_packages.sh") && rel != "Makefile" {
			t.Fatalf("%s must consume scripts/first_party_go_packages.sh for Go package scope", rel)
		}
	}
	makefile := mustReadFile(t, filepath.Join(repoRoot, "Makefile"))
	if !strings.Contains(makefile, "PKG_LIST := scripts/first_party_go_packages.sh") {
		t.Fatalf("Makefile must centralize Go package scope through scripts/first_party_go_packages.sh")
	}
}

func runFirstPartyPackageList(t *testing.T, repoRoot string) (string, string, error) {
	t.Helper()

	cmd := exec.Command("bash", "scripts/first_party_go_packages.sh")
	cmd.Dir = repoRoot
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
