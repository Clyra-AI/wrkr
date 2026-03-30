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

func TestReportHelpMatchesBehaviorContract(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%q", code, errOut.String())
	}

	helpText := errOut.String()
	for _, sentence := range []string{reportBehaviorContractSentenceOne, reportBehaviorContractSentenceTwo} {
		if !strings.Contains(helpText, sentence) {
			t.Fatalf("report help missing behavior contract sentence %q", sentence)
		}
	}

	repoRoot := mustRepoRoot(t)
	docsText, err := os.ReadFile(filepath.Join(repoRoot, "docs/commands/report.md"))
	if err != nil {
		t.Fatalf("read report docs: %v", err)
	}
	for _, sentence := range []string{reportBehaviorContractSentenceOne, reportBehaviorContractSentenceTwo} {
		if !strings.Contains(string(docsText), sentence) {
			t.Fatalf("docs/commands/report.md missing behavior contract sentence %q", sentence)
		}
	}
}

func TestRenderSimplePDFWrapsAndPaginatesLongContent(t *testing.T) {
	t.Parallel()

	lines := []string{
		strings.Repeat("long-line-segment ", 16) + "tail-marker",
	}
	for i := 0; i < 80; i++ {
		lines = append(lines, "section line "+strings.Repeat("x", 24))
	}

	payload := string(renderSimplePDF(lines))
	if !strings.Contains(payload, "/Count 2") {
		t.Fatalf("expected multi-page PDF payload, got %q", payload)
	}
	if !strings.Contains(payload, "tail-marker") {
		t.Fatalf("expected wrapped content to preserve tail marker, got %q", payload)
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

func TestReportAssessmentSummaryPrioritizesGovernFirstPaths(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	snapshot := map[string]any{
		"version": "v1",
		"target": map[string]any{
			"mode":  "org",
			"value": "acme",
		},
		"profile": map[string]any{
			"profile": "assessment",
		},
		"inventory": map[string]any{
			"non_human_identities": []any{
				map[string]any{
					"identity_type": "github_app",
					"subject":       "github_app",
					"source":        "workflow_static_signal",
				},
			},
		},
		"risk_report": map[string]any{
			"generated_at": "2026-03-25T12:00:00Z",
			"top_findings": []any{
				map[string]any{
					"canonical_key": "secret|1",
					"risk_score":    9.5,
					"finding": map[string]any{
						"finding_type": "secret_presence",
						"severity":     "high",
						"tool_type":    "secret",
						"org":          "acme",
						"repo":         "payments",
						"location":     ".env",
					},
				},
			},
			"ranked_findings": []any{
				map[string]any{
					"canonical_key": "secret|1",
					"risk_score":    9.5,
					"finding": map[string]any{
						"finding_type": "secret_presence",
						"severity":     "high",
						"tool_type":    "secret",
						"org":          "acme",
						"repo":         "payments",
						"location":     ".env",
					},
				},
			},
			"action_paths": []any{
				map[string]any{
					"path_id":                   "apc-123456",
					"org":                       "acme",
					"repo":                      "payments",
					"recommended_action":        "control",
					"write_capable":             true,
					"production_write":          true,
					"attack_path_score":         9.1,
					"risk_score":                8.8,
					"tool_type":                 "langchain",
					"location":                  "agents/payments.py",
					"execution_identity":        "github_app",
					"execution_identity_type":   "github_app",
					"execution_identity_source": "workflow_static_signal",
					"execution_identity_status": "known",
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
					"path_id":                   "apc-123456",
					"org":                       "acme",
					"repo":                      "payments",
					"recommended_action":        "control",
					"write_capable":             true,
					"production_write":          true,
					"attack_path_score":         9.1,
					"risk_score":                8.8,
					"tool_type":                 "langchain",
					"location":                  "agents/payments.py",
					"execution_identity":        "github_app",
					"execution_identity_type":   "github_app",
					"execution_identity_source": "workflow_static_signal",
					"execution_identity_status": "known",
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
	if _, ok := reportPayload["assessment_summary"].(map[string]any); !ok {
		t.Fatalf("expected top-level assessment_summary, got %v", reportPayload["assessment_summary"])
	}
	if _, ok := reportPayload["exposure_groups"].([]any); !ok {
		t.Fatalf("expected top-level exposure_groups, got %v", reportPayload["exposure_groups"])
	}
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	assessmentSummary, ok := summary["assessment_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary assessment_summary, got %v", summary["assessment_summary"])
	}
	for _, key := range []string{"ownerless_exposure", "identity_exposure_summary", "identity_to_review_first", "identity_to_revoke_first"} {
		if _, present := assessmentSummary[key]; !present {
			t.Fatalf("expected assessment_summary key %q, got %v", key, assessmentSummary)
		}
	}
	topRisks, ok := summary["top_risks"].([]any)
	if !ok || len(topRisks) == 0 {
		t.Fatalf("expected top_risks payload, got %v", summary["top_risks"])
	}
	first, ok := topRisks[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected top_risks item type: %T", topRisks[0])
	}
	if first["finding_type"] != "action_path" {
		t.Fatalf("expected action_path to lead top_risks when action_paths exist, got %v", first)
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
					"execution_identity":         "github_app",
					"execution_identity_type":    "github_app",
					"execution_identity_status":  "known",
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
		"path_id":            "path-",
		"org":                "org-",
		"repo":               "repo-",
		"agent_id":           "agent-",
		"location":           "loc-",
		"execution_identity": "identity-",
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
	assessmentSummary, ok := summary["assessment_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary assessment_summary, got %v", summary["assessment_summary"])
	}
	reviewFirst, ok := assessmentSummary["identity_to_review_first"].(map[string]any)
	if !ok {
		t.Fatalf("expected redacted identity_to_review_first, got %v", assessmentSummary["identity_to_review_first"])
	}
	identityValue, _ := reviewFirst["execution_identity"].(string)
	if !strings.HasPrefix(identityValue, "identity-") {
		t.Fatalf("expected redacted review identity, got %q", identityValue)
	}
	exposureGroups, ok := reportPayload["exposure_groups"].([]any)
	if !ok || len(exposureGroups) == 0 {
		t.Fatalf("expected redacted exposure_groups, got %v", reportPayload["exposure_groups"])
	}
	firstGroup, ok := exposureGroups[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected exposure_groups item type: %T", exposureGroups[0])
	}
	groupID, _ := firstGroup["group_id"].(string)
	if !strings.HasPrefix(groupID, "group-") {
		t.Fatalf("expected redacted exposure group id, got %q", groupID)
	}
}
