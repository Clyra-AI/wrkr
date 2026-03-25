package detect

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type jsonFixture struct {
	Name string `json:"name"`
}

type yamlFixture struct {
	Enabled bool `yaml:"enabled"`
}

type tomlFixture struct {
	Name string `toml:"name"`
}

func TestParseJSONFileStrictUnknownField(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"name":"ok","extra":true}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed jsonFixture
	parseErr := ParseJSONFile("detector", root, "cfg.json", &parsed)
	if parseErr == nil {
		t.Fatal("expected parse error")
	}
	if parseErr.Detector != "detector" || parseErr.Format != "json" {
		t.Fatalf("unexpected parse error shape: %#v", parseErr)
	}
}

func TestParseJSONFileRejectsTrailingTopLevelDocument(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"name":"ok"}{"name":"extra"}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed jsonFixture
	parseErr := ParseJSONFile("detector", root, "cfg.json", &parsed)
	if parseErr == nil {
		t.Fatal("expected parse error for trailing JSON document")
	}
	if parseErr.Format != "json" {
		t.Fatalf("unexpected parse error format: %#v", parseErr)
	}
}

func TestParseJSONFileAllowUnknownFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"name":"ok","extra":true}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed jsonFixture
	parseErr := ParseJSONFileAllowUnknownFields("detector", root, "cfg.json", &parsed)
	if parseErr != nil {
		t.Fatalf("expected no parse error, got %#v", parseErr)
	}
	if parsed.Name != "ok" {
		t.Fatalf("unexpected parsed result: %#v", parsed)
	}
}

func TestParseYAMLFileStrictUnknownField(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.yaml")
	if err := os.WriteFile(path, []byte("enabled: true\nextra: 1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed yamlFixture
	parseErr := ParseYAMLFile("detector", root, "cfg.yaml", &parsed)
	if parseErr == nil {
		t.Fatal("expected parse error")
	}
	if parseErr.Format != "yaml" {
		t.Fatalf("unexpected parse error format: %#v", parseErr)
	}
}

func TestParseYAMLFileAllowUnknownFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.yaml")
	if err := os.WriteFile(path, []byte("enabled: true\nextra: 1\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed yamlFixture
	parseErr := ParseYAMLFileAllowUnknownFields("detector", root, "cfg.yaml", &parsed)
	if parseErr != nil {
		t.Fatalf("expected no parse error, got %#v", parseErr)
	}
	if !parsed.Enabled {
		t.Fatalf("unexpected parsed result: %#v", parsed)
	}
}

func TestParseTOMLFileStrictUnknownField(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.toml")
	if err := os.WriteFile(path, []byte("name = \"ok\"\nextra = true\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed tomlFixture
	parseErr := ParseTOMLFile("detector", root, "cfg.toml", &parsed)
	if parseErr == nil {
		t.Fatal("expected parse error")
	}
	if parseErr.Format != "toml" {
		t.Fatalf("unexpected parse error format: %#v", parseErr)
	}
}

func TestParseTOMLFileAllowUnknownFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	path := filepath.Join(root, "cfg.toml")
	if err := os.WriteFile(path, []byte("name = \"ok\"\nextra = true\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var parsed tomlFixture
	parseErr := ParseTOMLFileAllowUnknownFields("detector", root, "cfg.toml", &parsed)
	if parseErr != nil {
		t.Fatalf("expected no parse error, got %#v", parseErr)
	}
	if parsed.Name != "ok" {
		t.Fatalf("unexpected parsed result: %#v", parsed)
	}
}

func TestReadFileWithinRootRejectsSymlinkEscape(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "cfg.json")
	if err := os.WriteFile(target, []byte(`{"name":"outside"}`), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}
	mustSymlinkOrSkip(t, target, filepath.Join(root, "cfg.json"))

	_, parseErr := ReadFileWithinRoot("detector", root, "cfg.json")
	if parseErr == nil {
		t.Fatal("expected unsafe_path parse error")
	}
	if parseErr.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path kind, got %#v", parseErr)
	}
}

func TestReadFileWithinRootHandlesDanglingSymlinkDeterministically(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	mustSymlinkOrSkip(t, filepath.Join(root, "missing.json"), filepath.Join(root, "cfg.json"))

	_, parseErr := ReadFileWithinRoot("detector", root, "cfg.json")
	if parseErr == nil {
		t.Fatal("expected file_not_found parse error")
	}
	if parseErr.Kind != "file_not_found" {
		t.Fatalf("expected file_not_found kind, got %#v", parseErr)
	}
}

func TestReadFileWithinRootPermissionDenied(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission fixture is not portable on windows")
	}

	root := t.TempDir()
	path := filepath.Join(root, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"name":"blocked"}`), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(path, 0o600)
	}()

	_, parseErr := ReadFileWithinRoot("detector", root, "cfg.json")
	if parseErr == nil {
		t.Fatal("expected permission parse error")
	}
	if parseErr.Kind != "parse_error" {
		t.Fatalf("expected parse_error kind, got %#v", parseErr)
	}
}

func mustSymlinkOrSkip(t *testing.T, target, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink parent: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}
}
