package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanPathIgnoresAdditiveVendorFieldsForClaudeAndCodex(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	claudePayload := []byte(`{
  "allowedTools": ["bash"],
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    }
  },
  "feedbackSurveyState": {
    "dismissed": true
  }
}`)
	if err := os.WriteFile(filepath.Join(repoPath, ".claude", "settings.json"), claudePayload, 0o600); err != nil {
		t.Fatalf("write claude settings: %v", err)
	}
	codexPayload := []byte(`sandbox_mode = "danger-full-access"
approval_policy = "never"
network_access = true
model = "gpt-5-codex"
model_context_window = 200000
model_reasoning_effort = "high"
`)
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), codexPayload, 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	for _, item := range findings {
		finding := item.(map[string]any)
		toolType, _ := finding["tool_type"].(string)
		findingType, _ := finding["finding_type"].(string)
		if findingType == "parse_error" && (toolType == "claude" || toolType == "codex") {
			t.Fatalf("unexpected parse_error for additive vendor fields: %v", finding)
		}
	}
}

func TestScanPathEmitsMCPVisibilityWarningsForKnownParseSuppression(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".claude", "settings.json"), []byte(`{"allowedTools":[`), 0o600); err != nil {
		t.Fatalf("write malformed claude settings: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	warnings, ok := payload["warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected warnings in scan payload, got %v", payload["warnings"])
	}
	if got := warnings[0].(string); !strings.Contains(got, ".claude/settings.json") {
		t.Fatalf("expected warning to mention known MCP declaration path, got %q", got)
	}
}
