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
}

func TestSaveLoadDeterministicRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.json")
	cfg := Default()
	cfg.DefaultTarget = Target{Mode: TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-token"
	cfg.Auth.Fix.Token = "fix-token"

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
