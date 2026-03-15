package claude

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestClaudeDetectorIgnoresAdditiveVendorFields(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	payload := []byte(`{
  "allowedTools": ["bash", "file_edit"],
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
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), payload, 0o600); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	var toolConfigFound bool
	for _, finding := range findings {
		if finding.FindingType != "tool_config" || finding.Location != ".claude/settings.json" {
			continue
		}
		if len(finding.Permissions) == 0 {
			t.Fatalf("expected permissions from parsed known fields, got %+v", finding)
		}
		toolConfigFound = true
	}
	if !toolConfigFound {
		t.Fatalf("expected tool_config finding for settings.json, got %+v", findings)
	}
}

func TestClaudeDetectorStillFailsMalformedJSON(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".claude", "settings.json"), []byte(`{"allowedTools": [`), 0o600); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, finding := range findings {
		if finding.FindingType == "parse_error" && finding.Location == ".claude/settings.json" {
			return
		}
	}
	t.Fatalf("expected parse_error finding, got %+v", findings)
}

func TestClaudeDetectorRejectsExternalSymlinkedSettings(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	target := filepath.Join(outside, "settings.json")
	if err := os.WriteFile(target, []byte(`{"allowedTools":["bash"]}`), 0o600); err != nil {
		t.Fatalf("write outside settings: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".claude", "settings.json")); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	for _, finding := range findings {
		if finding.FindingType == "parse_error" && finding.Location == ".claude/settings.json" {
			if finding.ParseError == nil || finding.ParseError.Kind != "unsafe_path" {
				t.Fatalf("expected unsafe_path parse error, got %+v", finding.ParseError)
			}
			return
		}
	}
	t.Fatalf("expected unsafe_path parse_error finding, got %+v", findings)
}
