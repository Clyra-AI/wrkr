package siteassets

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestGeneratedSiteAssetsMatchCheckedInCopies(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRoot(t)
	assetSet, err := Build(repoRoot)
	if err != nil {
		t.Fatalf("build site assets: %v", err)
	}

	expectedDir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	for _, name := range PublishedFilenames() {
		expectedPath := filepath.Join(expectedDir, name)
		expected, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatalf("read checked-in asset %s: %v", name, err)
		}
		generated, ok := assetSet.Files[name]
		if !ok {
			t.Fatalf("generated asset missing %s", name)
		}
		if string(generated) != string(expected) {
			t.Fatalf("site asset drifted for %s; %s; run `go run ./scripts/generate_site_assets --repo-root . --output-dir ./docs/examples/site-assets`", name, firstDiffSnippet(expected, generated))
		}
	}
}

func firstDiffSnippet(expected, generated []byte) string {
	expectedLines := strings.Split(string(expected), "\n")
	generatedLines := strings.Split(string(generated), "\n")
	limit := len(expectedLines)
	if len(generatedLines) < limit {
		limit = len(generatedLines)
	}
	for idx := 0; idx < limit; idx++ {
		if expectedLines[idx] == generatedLines[idx] {
			continue
		}
		return "first diff at line " + itoa(idx+1) + ": expected=" + expectedLines[idx] + " generated=" + generatedLines[idx]
	}
	if len(expectedLines) != len(generatedLines) {
		return "line count differs: expected=" + itoa(len(expectedLines)) + " generated=" + itoa(len(generatedLines))
	}
	return "content differs"
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

func TestPublishedSiteAssetsPassHygieneChecks(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRoot(t)
	dir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	files := map[string][]byte{}
	for _, name := range PublishedFilenames() {
		payload, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read published asset %s: %v", name, err)
		}
		files[name] = payload
	}
	if err := ValidateFiles(files); err != nil {
		t.Fatalf("published site assets failed hygiene validation: %v", err)
	}
}

func TestPublishedSiteAssetDirectoryHasExpectedFilesOnly(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRoot(t)
	dir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read site-assets dir: %v", err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected nested directory in site-assets: %s", entry.Name())
		}
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	expected := PublishedFilenames()
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Fatalf("unexpected site-assets file count: got=%v want=%v", actual, expected)
	}
	for idx := range actual {
		if actual[idx] != expected[idx] {
			t.Fatalf("unexpected site-assets files: got=%v want=%v", actual, expected)
		}
	}
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not locate repo root")
		}
		wd = next
	}
}
