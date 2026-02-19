package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRequiredPlanDocsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	required := []string{
		"product/PLAN_v1.md",
		"product/wrkr.md",
		"product/dev_guides.md",
		"product/Clyra_AI.md",
	}
	for _, rel := range required {
		path := filepath.Join(repoRoot, filepath.Clean(rel))
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required plan artifact missing: %s (%v)", rel, err)
		}
	}
}

func TestGitignoreDoesNotIgnoreProductDocs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content, err := os.ReadFile(filepath.Join(repoRoot, ".gitignore"))
	if err != nil {
		t.Fatalf("read .gitignore: %v", err)
	}
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "product/" || trimmed == "/product/" {
			t.Fatalf(".gitignore cannot ignore product plan artifacts: %q", trimmed)
		}
	}
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
