package hygiene

import (
	"os"
	"os/exec"
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

func TestNoTrackedWrkrLocalState(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	for _, path := range gitTrackedFiles(t, repoRoot) {
		if strings.HasPrefix(path, ".wrkr/") {
			t.Fatalf("transient wrkr local state must not be tracked: %s", path)
		}
	}
}

func TestLicenseContainsFullApache20Text(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content, err := os.ReadFile(filepath.Join(repoRoot, "LICENSE"))
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	text := string(content)
	requiredMarkers := []string{
		"TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
		"1. Definitions.",
		"2. Grant of Copyright License.",
		"3. Grant of Patent License.",
		"4. Redistribution.",
		"7. Disclaimer of Warranty.",
		"8. Limitation of Liability.",
		"APPENDIX: How to apply the Apache License to your work.",
	}
	for _, marker := range requiredMarkers {
		if !strings.Contains(text, marker) {
			t.Fatalf("LICENSE missing Apache-2.0 full-text marker %q", marker)
		}
	}
}

func TestOSSTrustBaselineIncludesCanonicalLicense(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content, err := os.ReadFile(filepath.Join(repoRoot, "LICENSE"))
	if err != nil {
		t.Fatalf("read LICENSE: %v", err)
	}
	if len(strings.Split(string(content), "\n")) < 180 {
		t.Fatalf("LICENSE appears abbreviated; expected canonical Apache-2.0 full text")
	}
	if strings.Contains(string(content), "See the License for the specific language governing permissions and limitations under the License.\n#") {
		t.Fatalf("LICENSE appears to contain an abbreviated notice glued to another document")
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

func gitTrackedFiles(t *testing.T, repoRoot string) []string {
	t.Helper()

	cmd := exec.Command("git", "-C", repoRoot, "ls-files")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("list tracked files: %v", err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}
	paths := strings.Split(trimmed, "\n")
	for i := range paths {
		paths[i] = strings.TrimSpace(paths[i])
	}
	return paths
}
