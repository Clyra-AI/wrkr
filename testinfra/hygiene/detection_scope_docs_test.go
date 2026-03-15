package hygiene

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectionDocsDifferentiateFrameworksScaffoldsAndExplicitCustomSource(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	scanDoc := mustReadFile(t, filepath.Join(repoRoot, "docs/commands/scan.md"))
	matrix := mustReadFile(t, filepath.Join(repoRoot, "docs/trust/detection-coverage-matrix.md"))

	for _, content := range []string{readme, scanDoc, matrix} {
		if !strings.Contains(content, "supported framework-native") {
			t.Fatal("expected detection docs to keep supported framework-native scope explicit")
		}
	}
	if !strings.Contains(readme, "conservative custom-agent scaffolds") {
		t.Fatal("README missing conservative custom-agent scaffold scope")
	}
	if !strings.Contains(matrix, "`wrkr:custom-agent`") {
		t.Fatal("detection coverage matrix missing explicit custom-source marker contract")
	}
	if !strings.Contains(scanDoc, "`wrkr:custom-agent`") {
		t.Fatal("scan command docs missing explicit custom-source marker contract")
	}
}
