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
