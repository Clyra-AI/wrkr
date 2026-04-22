package detect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGeneratedPathClassifiesPackageAndGeneratedNoise(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"node_modules/pkg/package.json",
		"dist/app.min.js",
		".yarn/sdks/typescript/lib.js",
		"clients/generated-sdk/openapi.json",
		"target/classes/app.jar",
	} {
		if !IsGeneratedPath(path) {
			t.Fatalf("expected generated path: %s", path)
		}
	}
	for _, path := range []string{
		".github/workflows/release.yml",
		".cursor/mcp.json",
		"AGENTS.md",
	} {
		if IsGeneratedPath(path) {
			t.Fatalf("did not expect generated path: %s", path)
		}
	}
}

func TestWalkFilesHonorsDeepModeGeneratedInclusion(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writePathFilterTestFile(t, root, "src/app.go", "package main\n")
	writePathFilterTestFile(t, root, "node_modules/pkg/package.json", "{}\n")
	writePathFilterTestFile(t, root, "dist/app.min.js", "console.log('generated')\n")

	governanceFiles, err := WalkFilesWithOptions(root, Options{ScanMode: "governance"})
	if err != nil {
		t.Fatalf("walk governance files: %v", err)
	}
	for _, rel := range governanceFiles {
		if IsGeneratedPath(rel) {
			t.Fatalf("governance walk should suppress generated path %s in %v", rel, governanceFiles)
		}
	}

	deepFiles, err := WalkFilesWithOptions(root, Options{ScanMode: "deep"})
	if err != nil {
		t.Fatalf("walk deep files: %v", err)
	}
	for _, want := range []string{"node_modules/pkg/package.json", "dist/app.min.js"} {
		if !pathFilterTestContains(deepFiles, want) {
			t.Fatalf("deep walk should include %s in %v", want, deepFiles)
		}
	}
}

func writePathFilterTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func pathFilterTestContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
