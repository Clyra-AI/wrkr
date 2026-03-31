package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanExtensionFindingDoesNotEmitAuthoritativeSurfaces(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	repoPath := filepath.Join(tmp, "repo", ".wrkr", "detectors")
	if err := os.MkdirAll(repoPath, 0o755); err != nil {
		t.Fatalf("mkdir extension detector path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "extensions.json"), []byte(`{
  "version": "v1",
  "detectors": [
    {
      "id": "custom-note",
      "finding_type": "custom_extension_note",
      "tool_type": "custom_detector",
      "location": "README.md",
      "severity": "low"
    }
  ]
}
`), 0o600); err != nil {
		t.Fatalf("write extension descriptor: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", tmp, "--state", filepath.Join(tmp, "state.json"), "--json"}, &out, &errOut)
	if code != exitSuccess {
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
	foundCustom := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "custom_extension_note" && finding["tool_type"] == "custom_detector" {
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Fatalf("expected custom extension finding in raw findings, got %v", findings)
	}

	inventory, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory object, got %T", payload["inventory"])
	}
	if tools, ok := inventory["tools"].([]any); ok {
		for _, item := range tools {
			tool, ok := item.(map[string]any)
			if ok && tool["tool_type"] == "custom_detector" {
				t.Fatalf("extension finding must not become inventory tool, got %v", tool)
			}
		}
	}
	if rows, ok := payload["agent_privilege_map"].([]any); ok {
		for _, item := range rows {
			row, ok := item.(map[string]any)
			if ok && row["tool_type"] == "custom_detector" {
				t.Fatalf("extension finding must not become agent privilege row, got %v", row)
			}
		}
	}
	if paths, ok := payload["action_paths"].([]any); ok {
		for _, item := range paths {
			path, ok := item.(map[string]any)
			if ok && path["tool_type"] == "custom_detector" {
				t.Fatalf("extension finding must not become action path, got %v", path)
			}
		}
	}
}
