//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScenarioMySetupActivationPrefersConcreteSignals(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	t.Setenv("OPENAI_API_KEY", "redacted")

	if err := os.MkdirAll(filepath.Join(tmpHome, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpHome, "Projects", "demo-agent", ".agents"), 0o755); err != nil {
		t.Fatalf("mkdir project markers: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, "Projects", "demo-agent", "AGENTS.md"), []byte("agent"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--my-setup", "--state", statePath, "--json"})
	activation, ok := scanPayload["activation"].(map[string]any)
	if !ok {
		t.Fatalf("expected activation payload, got %v", scanPayload["activation"])
	}
	items, ok := activation["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected activation items, got %v", activation["items"])
	}
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if row["tool_type"] == "policy" {
			t.Fatalf("policy findings must not appear in activation items: %v", items)
		}
	}

	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected report summary object, got %T", reportPayload["summary"])
	}
	if _, ok := summary["activation"].(map[string]any); !ok {
		t.Fatalf("expected additive activation summary in report payload: %v", summary)
	}
}
