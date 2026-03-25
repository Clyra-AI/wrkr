package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestReportOrgSummaryIncludesGovernFirstActivationProjection(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	snapshot := map[string]any{
		"version": "v1",
		"target": map[string]any{
			"mode":  "org",
			"value": "acme",
		},
		"inventory": map[string]any{
			"agent_privilege_map": []any{
				map[string]any{
					"agent_id":                   "wrkr:alpha:acme",
					"framework":                  "langchain",
					"repos":                      []any{"payments"},
					"location":                   "agents/payments.py",
					"risk_score":                 8.8,
					"write_capable":              true,
					"production_write":           true,
					"approval_classification":    "approved",
					"security_visibility_status": "approved",
				},
			},
		},
		"risk_report": map[string]any{
			"generated_at":    "2026-03-25T12:00:00Z",
			"top_findings":    []any{},
			"ranked_findings": []any{},
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
	if code := Run([]string{"report", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report failed: %d %s", code, errOut.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	activation, ok := summary["activation"].(map[string]any)
	if !ok {
		t.Fatalf("expected activation summary, got %v", summary["activation"])
	}
	items, ok := activation["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one govern-first activation item, got %v", activation["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected activation item type: %T", items[0])
	}
	if first["item_class"] != "production_target_backed" {
		t.Fatalf("expected production_target_backed item class, got %v", first["item_class"])
	}
}

func TestReportIncludesActionPathsProjection(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	snapshot := map[string]any{
		"version": "v1",
		"target": map[string]any{
			"mode":  "org",
			"value": "acme",
		},
		"inventory": map[string]any{
			"agent_privilege_map": []any{
				map[string]any{
					"agent_id":                   "wrkr:alpha:acme",
					"framework":                  "langchain",
					"org":                        "acme",
					"repos":                      []any{"payments"},
					"location":                   "agents/payments.py",
					"risk_score":                 8.8,
					"write_capable":              true,
					"production_write":           true,
					"approval_classification":    "approved",
					"security_visibility_status": "approved",
				},
			},
		},
		"risk_report": map[string]any{
			"generated_at":    "2026-03-25T12:00:00Z",
			"top_findings":    []any{},
			"ranked_findings": []any{},
			"attack_paths": []any{
				map[string]any{
					"org":        "acme",
					"repo":       "payments",
					"path_score": 9.1,
				},
			},
			"action_paths": []any{
				map[string]any{
					"path_id":            "apc-123456",
					"org":                "acme",
					"repo":               "payments",
					"recommended_action": "control",
					"write_capable":      true,
					"production_write":   true,
					"attack_path_score":  9.1,
					"risk_score":         8.8,
					"tool_type":          "langchain",
					"location":           "agents/payments.py",
				},
			},
			"action_path_to_control_first": map[string]any{
				"summary": map[string]any{
					"total_paths":                    1,
					"write_capable_paths":            1,
					"production_target_backed_paths": 1,
					"govern_first_paths":             0,
				},
				"path": map[string]any{
					"path_id":            "apc-123456",
					"org":                "acme",
					"repo":               "payments",
					"recommended_action": "control",
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
	if code := Run([]string{"report", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report failed: %d %s", code, errOut.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if _, ok := reportPayload["action_paths"].([]any); !ok {
		t.Fatalf("expected top-level action_paths, got %v", reportPayload["action_paths"])
	}
	if _, ok := reportPayload["action_path_to_control_first"].(map[string]any); !ok {
		t.Fatalf("expected top-level action_path_to_control_first, got %v", reportPayload["action_path_to_control_first"])
	}
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	if _, ok := summary["action_paths"].([]any); !ok {
		t.Fatalf("expected summary action_paths, got %v", summary["action_paths"])
	}
}

func TestReportPublicShareRedactsActionPathProjection(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	snapshot := map[string]any{
		"version": "v1",
		"target": map[string]any{
			"mode":  "org",
			"value": "acme",
		},
		"inventory": map[string]any{},
		"risk_report": map[string]any{
			"generated_at":    "2026-03-25T12:00:00Z",
			"top_findings":    []any{},
			"ranked_findings": []any{},
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-123456",
					"org":                        "acme",
					"repo":                       "payments",
					"agent_id":                   "wrkr:alpha:acme",
					"tool_type":                  "langchain",
					"location":                   "agents/payments.py",
					"risk_score":                 8.8,
					"attack_path_score":          9.1,
					"recommended_action":         "control",
					"matched_production_targets": []any{"deploy/prod"},
				},
			},
			"action_path_to_control_first": map[string]any{
				"summary": map[string]any{
					"total_paths":                    1,
					"write_capable_paths":            1,
					"production_target_backed_paths": 1,
					"govern_first_paths":             0,
				},
				"path": map[string]any{
					"path_id":            "apc-123456",
					"org":                "acme",
					"repo":               "payments",
					"agent_id":           "wrkr:alpha:acme",
					"tool_type":          "langchain",
					"location":           "agents/payments.py",
					"recommended_action": "control",
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
	if code := Run([]string{"report", "--state", statePath, "--template", "public", "--share-profile", "public", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report failed: %d %s", code, errOut.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	actionPaths, ok := reportPayload["action_paths"].([]any)
	if !ok || len(actionPaths) != 1 {
		t.Fatalf("expected one action path, got %v", reportPayload["action_paths"])
	}
	firstPath, ok := actionPaths[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected action path type: %T", actionPaths[0])
	}
	for key, prefix := range map[string]string{
		"path_id":  "path-",
		"org":      "org-",
		"repo":     "repo-",
		"agent_id": "agent-",
		"location": "loc-",
	} {
		value, _ := firstPath[key].(string)
		if !strings.HasPrefix(value, prefix) {
			t.Fatalf("expected %s to be redacted with prefix %q, got %q", key, prefix, value)
		}
	}
	targets, ok := firstPath["matched_production_targets"].([]any)
	if !ok || len(targets) != 1 {
		t.Fatalf("expected one redacted production target, got %v", firstPath["matched_production_targets"])
	}
	targetValue, _ := targets[0].(string)
	if !strings.HasPrefix(targetValue, "target-") {
		t.Fatalf("expected redacted production target, got %q", targetValue)
	}

	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	controlFirst, ok := summary["action_path_to_control_first"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary action_path_to_control_first, got %v", summary["action_path_to_control_first"])
	}
	path, ok := controlFirst["path"].(map[string]any)
	if !ok {
		t.Fatalf("expected control-first path object, got %v", controlFirst["path"])
	}
	repo, _ := path["repo"].(string)
	if !strings.HasPrefix(repo, "repo-") {
		t.Fatalf("expected redacted control-first repo, got %q", repo)
	}
}
