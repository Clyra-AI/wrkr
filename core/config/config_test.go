package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateTarget(t *testing.T) {
	t.Parallel()

	if err := ValidateTarget(TargetRepo, "acme/backend"); err != nil {
		t.Fatalf("expected repo target to validate: %v", err)
	}
	if err := ValidateTarget(TargetOrg, "acme"); err != nil {
		t.Fatalf("expected org target to validate: %v", err)
	}
	if err := ValidateTarget(TargetPath, "./repos"); err != nil {
		t.Fatalf("expected path target to validate: %v", err)
	}
	if err := ValidateTarget(TargetRepo, "acme"); err == nil {
		t.Fatal("expected invalid repo target to fail")
	}
	if err := ValidateTarget(TargetOrg, "acme/backend"); err == nil {
		t.Fatal("expected invalid org target to fail")
	}
	if err := ValidateTarget(TargetRepo, "acme/.."); err == nil {
		t.Fatal("expected traversal-style repo target to fail")
	}
	if err := ValidateTarget(TargetRepo, "../backend"); err == nil {
		t.Fatal("expected repo owner traversal to fail")
	}
	if err := ValidateTarget(TargetOrg, ".."); err == nil {
		t.Fatal("expected traversal-style org target to fail")
	}
}

func TestSaveLoadDeterministicRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	cfg := Default()
	cfg.DefaultTarget = Target{Mode: TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-token"
	cfg.Auth.Fix.Token = "fix-token"
	cfg.GitHubAPIBase = "https://api.github.com"

	if err := Save(path, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.Version != CurrentVersion {
		t.Fatalf("unexpected version: %q", loaded.Version)
	}
	if loaded.DefaultTarget.Mode != TargetRepo || loaded.DefaultTarget.Value != "acme/backend" {
		t.Fatalf("unexpected default target: %+v", loaded.DefaultTarget)
	}
	if loaded.GitHubAPIBase != "https://api.github.com" {
		t.Fatalf("unexpected github api base: %q", loaded.GitHubAPIBase)
	}

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first write: %v", err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("save config second time: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second write: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("expected byte-stable config serialization\nfirst: %s\nsecond: %s", first, second)
	}
}

func TestResolvePathWithEnv(t *testing.T) {
	t.Setenv("WRKR_CONFIG_PATH", "/tmp/wrkr-config.json")
	path, err := ResolvePath("")
	if err != nil {
		t.Fatalf("resolve path: %v", err)
	}
	if path != "/tmp/wrkr-config.json" {
		t.Fatalf("unexpected env path: %q", path)
	}
}

func TestLoadOlderConfigWithoutGitHubAPIBase(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	payload := []byte("{\n  \"version\": \"v1\",\n  \"auth\": {\n    \"scan\": {},\n    \"fix\": {}\n  },\n  \"default_target\": {\n    \"mode\": \"org\",\n    \"value\": \"acme\"\n  }\n}\n")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.GitHubAPIBase != "" {
		t.Fatalf("expected empty github api base, got %q", loaded.GitHubAPIBase)
	}
	if loaded.DefaultTarget.Mode != TargetOrg || loaded.DefaultTarget.Value != "acme" {
		t.Fatalf("unexpected default target: %+v", loaded.DefaultTarget)
	}
}
