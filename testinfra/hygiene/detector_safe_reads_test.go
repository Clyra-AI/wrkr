package hygiene

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWalkBasedDetectorsUseRootBoundReadHelpers(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	targets := []string{
		"core/detect/skills/detector.go",
		"core/detect/promptchannel/detector.go",
		"core/detect/cursor/detector.go",
		"core/detect/dependency/detector.go",
		"core/detect/webmcp/detector.go",
		"core/detect/nonhumanidentity/detector.go",
	}

	for _, rel := range targets {
		content := mustReadFile(t, filepath.Join(repoRoot, rel))
		for _, forbidden := range []string{"os.ReadFile(", "os.Open("} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s must use detect root-bound read helpers instead of %s", rel, forbidden)
			}
		}
	}
}
