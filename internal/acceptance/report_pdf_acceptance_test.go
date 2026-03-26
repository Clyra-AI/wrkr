package acceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

// Acceptance fixtures for executive report PDF output and detailed wrapped output.
func TestAcceptanceExecutiveReportPDFFixtures(t *testing.T) {
	t.Run("executive_summary_fixture_keeps_key_sections_visible", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state.json")
		writeJSON(t, statePath, map[string]any{
			"version": "v1",
			"inventory": map[string]any{
				"tools": []any{
					map[string]any{"tool_type": "codex"},
					map[string]any{"tool_type": "mcp"},
				},
			},
			"profile": map[string]any{
				"failing_rules": []any{"WRKR-004"},
			},
			"risk_report": map[string]any{
				"generated_at": "2026-03-26T12:00:00Z",
				"top_findings": []any{
					map[string]any{
						"risk_score": 9.1,
						"finding": map[string]any{
							"finding_type": "policy_violation",
							"location":     ".github/workflows/pr.yml",
						},
					},
				},
				"ranked_findings": []any{
					map[string]any{
						"risk_score": 9.1,
						"finding": map[string]any{
							"finding_type": "policy_violation",
							"location":     ".github/workflows/pr.yml",
						},
					},
				},
			},
		})

		pdfPath := filepath.Join(t.TempDir(), "executive-summary.pdf")
		var out bytes.Buffer
		var errOut bytes.Buffer
		if code := cli.Run([]string{"report", "--state", statePath, "--template", "exec", "--pdf", "--pdf-path", pdfPath, "--json"}, &out, &errOut); code != 0 {
			t.Fatalf("report --pdf failed: %d %s", code, errOut.String())
		}

		payload, err := os.ReadFile(pdfPath)
		if err != nil {
			t.Fatalf("read pdf: %v", err)
		}
		content := string(payload)
		for _, required := range []string{
			"Wrkr Deterministic Report",
			"Executive posture summary",
			"Top prioritized risks",
			"Next executive actions",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("expected executive PDF fixture to keep %q visible, got %q", required, content)
			}
		}
	})

	t.Run("detailed_report_fixture_wraps_and_paginates", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state.json")
		ranked := make([]any, 0, 70)
		for i := 0; i < 70; i++ {
			ranked = append(ranked, map[string]any{
				"risk_score": 9.0 - (float64(i) * 0.01),
				"finding": map[string]any{
					"finding_type": "policy_violation",
					"location":     "service-" + strconv.Itoa(i) + "/tail-marker-" + strings.Repeat("segment-", 8),
				},
			})
		}
		writeJSON(t, statePath, map[string]any{
			"version": "v1",
			"inventory": map[string]any{
				"tools": []any{
					map[string]any{"tool_type": "codex"},
					map[string]any{"tool_type": "mcp"},
					map[string]any{"tool_type": "cursor"},
				},
			},
			"risk_report": map[string]any{
				"generated_at":    "2026-03-26T12:00:00Z",
				"top_findings":    ranked[:5],
				"ranked_findings": ranked,
			},
		})

		pdfPath := filepath.Join(t.TempDir(), "detailed-report.pdf")
		var out bytes.Buffer
		var errOut bytes.Buffer
		if code := cli.Run([]string{"report", "--state", statePath, "--template", "exec", "--pdf", "--pdf-path", pdfPath, "--json"}, &out, &errOut); code != 0 {
			t.Fatalf("report --pdf failed: %d %s", code, errOut.String())
		}

		payload, err := os.ReadFile(pdfPath)
		if err != nil {
			t.Fatalf("read pdf: %v", err)
		}
		content := string(payload)
		if !strings.Contains(content, "/Count 2") {
			t.Fatalf("expected multi-page PDF fixture, got %q", content)
		}
		if !strings.Contains(content, "tail-marker") {
			t.Fatalf("expected wrapped detailed PDF fixture to preserve tail marker, got %q", content)
		}
	})
}
