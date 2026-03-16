package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReportPDFDeterministicForFixedState(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	pdfPath := filepath.Join(tmp, "report.pdf")
	snapshot := map[string]any{
		"version": "v1",
		"inventory": map[string]any{
			"tools": []any{
				map[string]any{"tool_type": "cursor"},
				map[string]any{"tool_type": "mcp"},
				map[string]any{"tool_type": "mcp"},
			},
		},
		"profile": map[string]any{
			"failing_rules": []any{"WRKR-001", "WRKR-002"},
		},
		"risk_report": map[string]any{
			"generated_at": "2026-02-20T12:00:00Z",
			"top_findings": []any{
				map[string]any{
					"risk_score": 9.1,
					"finding": map[string]any{
						"finding_type": "policy_violation",
						"location":     "WRKR-001",
					},
				},
			},
			"ranked_findings": []any{
				map[string]any{
					"risk_score": 9.1,
					"finding": map[string]any{
						"finding_type": "policy_violation",
						"location":     "WRKR-001",
					},
				},
			},
		},
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal state payload: %v", err)
	}
	if err := os.WriteFile(statePath, append(payload, '\n'), 0o600); err != nil {
		t.Fatalf("write state payload: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"report", "--pdf", "--pdf-path", pdfPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report --pdf failed: %d %s", code, errOut.String())
	}
	first, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read first pdf: %v", err)
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"report", "--pdf", "--pdf-path", pdfPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report --pdf second run failed: %d %s", code, errOut.String())
	}
	second, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read second pdf: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("expected deterministic report pdf bytes for fixed state")
	}
}

func TestReportMySetupSummaryIncludesActivationProjection(t *testing.T) {
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

	statePath := filepath.Join(t.TempDir(), "state.json")
	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--my-setup", "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--state", statePath, "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", payload["summary"])
	}
	activation, ok := summary["activation"].(map[string]any)
	if !ok {
		t.Fatalf("expected activation summary, got %v", summary["activation"])
	}
	items, ok := activation["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected activation items in report summary, got %v", activation["items"])
	}
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if row["tool_type"] == "policy" {
			t.Fatalf("policy findings must not appear in report activation items: %v", items)
		}
	}
}
