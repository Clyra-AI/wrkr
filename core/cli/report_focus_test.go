package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestReportFocusPathRejectsUnknownPathID(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":            "apc-known",
					"org":                "acme",
					"repo":               "acme/release",
					"tool_type":          "compiled_action",
					"location":           ".github/workflows/release.yml",
					"confidence_lane":    "confirmed_action_path",
					"action_path_type":   "ci_cd_workflow",
					"recommended_action": "control",
					"approval_gap":       true,
					"credential_access":  true,
				},
			},
		},
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--focus-path", "apc-missing",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestReportFocusPathRejectsContextOnlyPathID(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":           "apc-context-only",
					"org":               "acme",
					"repo":              "acme/release",
					"tool_type":         "compiled_action",
					"location":          "README.md",
					"confidence_lane":   "context_only",
					"action_path_type":  "plain_source_code",
					"approval_gap":      false,
					"credential_access": false,
				},
			},
		},
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--focus-path", "apc-context-only",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestReportFocusPathSelectsExplicitPrimaryView(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-default",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/release.yml",
					"confidence_lane":            "confirmed_action_path",
					"action_path_type":           "ci_cd_workflow",
					"delegation_readiness_state": "approval_required",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"approval_gap":               true,
					"credential_access":          true,
				},
				map[string]any{
					"path_id":                    "apc-focused",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/deploy.yml",
					"confidence_lane":            "confirmed_action_path",
					"action_path_type":           "ci_cd_workflow",
					"delegation_readiness_state": "proof_required",
					"recommended_control":        "proof_required",
					"recommended_action":         "proof",
					"approval_gap":               true,
					"credential_access":          true,
				},
			},
		},
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "internal",
		"--focus-path", "apc-focused",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom object, got %T", payload["agent_action_bom"])
	}
	summary, ok := bom["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected bom summary object, got %T", bom["summary"])
	}
	primaryView, ok := summary["primary_view"].(map[string]any)
	if !ok {
		t.Fatalf("expected primary_view object, got %T", summary["primary_view"])
	}
	if primaryView["path_id"] != "apc-focused" {
		t.Fatalf("expected focused path id, got %v", primaryView)
	}
	if primaryView["selection_reason"] != "explicit_focus_path" {
		t.Fatalf("expected explicit focus selection reason, got %v", primaryView)
	}
}
