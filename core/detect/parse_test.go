package detect

import (
	"os"
	"path/filepath"
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
