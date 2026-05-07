package dependency

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestDetectSkipsIgnoredUnreadableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission semantics differ on windows")
	}

	root := t.TempDir()
	writeFile(t, root, "go.mod", "module example.com/repo\n\ngo 1.26.1\nrequire github.com/openai/openai-go v0.1.0\n")

	ignoredDir := filepath.Join(root, "node_modules")
	if err := os.MkdirAll(filepath.Join(ignoredDir, "pkg"), 0o755); err != nil {
		t.Fatalf("mkdir ignored dir: %v", err)
	}
	writeFile(t, root, "node_modules/pkg/package.json", "{")

	if err := os.Chmod(ignoredDir, 0o000); err != nil {
		t.Fatalf("chmod ignored dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(ignoredDir, 0o755)
	})

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from go.mod")
	}
}

func TestProjectSignalUsesTokenBoundaries(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "README.md", "Storage management utilities.")

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "storage-service",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no project signal findings, got %d", len(findings))
	}
}

func TestProjectSignalMatchesExplicitToken(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "README.md", "This repository contains an agent runtime.")

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "platform-service",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one project signal finding, got %d", len(findings))
	}
	if findings[0].FindingType != "ai_project_signal" {
		t.Fatalf("expected ai_project_signal finding, got %s", findings[0].FindingType)
	}
}

func TestGeneratedDependencyNoiseSuppressedUnlessDeepMode(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "node_modules/pkg/package.json", "{")

	governance, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{ScanMode: "governance"})
	if err != nil {
		t.Fatalf("governance detect returned error: %v", err)
	}
	for _, finding := range governance {
		if finding.Location == "node_modules/pkg/package.json" {
			t.Fatalf("governance mode should suppress generated dependency evidence, got %+v", governance)
		}
	}

	deep, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{ScanMode: "deep"})
	if err != nil {
		t.Fatalf("deep detect returned error: %v", err)
	}
	if len(deep) != 1 {
		t.Fatalf("expected one deep parse finding, got %+v", deep)
	}
	if deep[0].FindingType != "parse_error" || deep[0].Location != "node_modules/pkg/package.json" {
		t.Fatalf("expected generated package parse error in deep mode, got %+v", deep)
	}
}

func TestPackageJSONIgnoresUnknownMetadataAndExtractsSections(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "name": "@acme/customer-app",
  "author": "Acme",
  "dependencies": {"langchain": "^1.0.0"},
  "devDependencies": {"@langchain/openai": "^1.2.0"},
  "optionalDependencies": {"crewai": "^0.8.0"},
  "peerDependencies": {"autogen": "^0.4.0"},
  "scripts": {"mcp:serve": "node ./scripts/mcp.js", "lint": "eslint ."},
  "workspaces": {"packages": ["apps/*", "packages/*"]},
  "packageManager": "pnpm@10.0.0",
  "exports": {".": "./dist/index.js", "./server": "./dist/server.js"},
  "bin": {"wrkr-helper": "./bin/helper.js"},
  "customField": {"kept": true}
}`)

	manifest, parseErr := parsePackageJSONManifest(root, "package.json")
	if parseErr != nil {
		t.Fatalf("expected tolerant parse, got %#v", parseErr)
	}
	if !reflect.DeepEqual(manifest.DependencyNames(), []string{"@langchain/openai", "autogen", "crewai", "langchain"}) {
		t.Fatalf("unexpected dependency names: %+v", manifest.DependencyNames())
	}
	if !reflect.DeepEqual(manifest.WorkspacePackages, []string{"apps/*", "packages/*"}) {
		t.Fatalf("unexpected workspaces: %+v", manifest.WorkspacePackages)
	}
	if manifest.PackageManager != "pnpm@10.0.0" {
		t.Fatalf("unexpected package manager: %q", manifest.PackageManager)
	}
	if !reflect.DeepEqual(manifest.ExportKeys, []string{".", "./server"}) {
		t.Fatalf("unexpected export keys: %+v", manifest.ExportKeys)
	}
	if !reflect.DeepEqual(manifest.BinNames, []string{"wrkr-helper"}) {
		t.Fatalf("unexpected bin names: %+v", manifest.BinNames)
	}
	if manifest.Scripts["mcp:serve"] == "" {
		t.Fatalf("expected scripts to remain available, got %+v", manifest.Scripts)
	}
}

func TestDetectPackageJSONReadsMonorepoDependencySectionsWithoutParseNoise(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "name": "workspace-root",
  "workspaces": ["apps/*", "packages/*"],
  "dependencies": {"langchain": "^1.0.0"},
  "custom": {"metadata": true}
}`)
	writeFile(t, root, "apps/web/package.json", `{
  "name": "web",
  "devDependencies": {"@langchain/core": "^1.0.0"},
  "peerDependencies": {"autogen": "^0.4.0"},
  "bin": "./bin/web.js"
}`)

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) < 3 {
		t.Fatalf("expected dependency findings from multiple sections, got %+v", findings)
	}
	for _, finding := range findings {
		if finding.FindingType == "parse_error" {
			t.Fatalf("did not expect parse noise for additive package metadata, got %+v", findings)
		}
	}
}

func TestDetectRejectsExternalSymlinkedDependencyManifest(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, outside, "go.mod", "module example.com/outside\n\ngo 1.26.1\nrequire github.com/openai/openai-go v0.1.0\n")
	mustSymlinkOrSkipDependency(t, filepath.Join(outside, "go.mod"), filepath.Join(root, "go.mod"))

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse error finding, got %#v", findings)
	}
	if findings[0].FindingType != "parse_error" || findings[0].ParseError == nil || findings[0].ParseError.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path parse error, got %#v", findings)
	}
}

func TestFrameworkDependencyCreatesCandidateNotActionPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "package.json", `{
  "dependencies": {
    "langchain": "^1.0.0",
    "crewai": "^0.8.0"
  }
}`)

	findings, err := New().Detect(context.Background(), detect.Scope{
		Org:  "acme",
		Repo: "repo",
		Root: root,
	}, detect.Options{})
	if err != nil {
		t.Fatalf("detect returned error: %v", err)
	}

	frameworkCandidates := map[string]bool{}
	for _, finding := range findings {
		if finding.FindingType == "framework_candidate" {
			frameworkCandidates[finding.ToolType] = true
		}
		if finding.FindingType == "agent_framework" {
			t.Fatalf("did not expect source-level agent_framework from dependency-only evidence, got %+v", finding)
		}
	}
	if !frameworkCandidates["langchain"] || !frameworkCandidates["crewai"] {
		t.Fatalf("expected framework candidates for langchain and crewai, got %+v", findings)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func mustSymlinkOrSkipDependency(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink parent: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}
}
