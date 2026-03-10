package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestScanExplicitTargetIgnoresInvalidDefaultConfig(t *testing.T) {
	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	if err := os.MkdirAll(filepath.Join(home, ".wrkr"), 0o755); err != nil {
		t.Fatalf("mkdir home config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".wrkr", "config.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	t.Setenv("HOME", home)

	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected explicit target scan to ignore invalid default config, got %d: %s", code, errOut.String())
	}
}

func TestScanExplicitConfigStillFailsWhenInvalid(t *testing.T) {
	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	configPath := filepath.Join(tmp, "bad-config.json")
	if err := os.WriteFile(configPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--config", configPath, "--state", filepath.Join(tmp, "state.json"), "--json"}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected explicit invalid config to fail, got %d: %s", code, errOut.String())
	}
	assertErrorCode(t, errOut.Bytes(), "runtime_failure")
}
