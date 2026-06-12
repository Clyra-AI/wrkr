package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestReportFocusPresetRejectsUnknownPreset(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--focus", "not-a-preset", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestReportFocusPresetBuildsReleaseView(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-release",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/release.yml",
					"write_capable":              true,
					"credential_access":          true,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "release_adjacent",
					"confidence_lane":            "confirmed_action_path",
					"delegation_readiness_state": "approval_required",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"attack_path_score":          8.9,
					"risk_score":                 8.9,
				},
				map[string]any{
					"path_id":                    "apc-internal",
					"org":                        "acme",
					"repo":                       "acme/docs",
					"tool_type":                  "compiled_action",
					"location":                   "scripts/lint.sh",
					"write_capable":              true,
					"credential_access":          false,
					"approval_gap":               false,
					"action_path_type":           "legacy_script",
					"target_class":               "developer_productivity",
					"confidence_lane":            "confirmed_action_path",
					"delegation_readiness_state": "review_required",
					"recommended_control":        "owner_review",
					"recommended_action":         "review",
					"attack_path_score":          5.0,
					"risk_score":                 5.0,
				},
			},
		},
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--state", statePath, "--focus", "release", "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	focusView, ok := payload["focus_view"].(map[string]any)
	if !ok {
		t.Fatalf("expected focus_view object, got %T", payload["focus_view"])
	}
	if focusView["preset"] != "release" {
		t.Fatalf("expected release preset, got %v", focusView)
	}
	if focusView["matching_paths"] != float64(1) {
		t.Fatalf("expected one release path, got %v", focusView)
	}
}

func TestReportFocusPresetAndFocusPathCoexist(t *testing.T) {
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
					"write_capable":              true,
					"credential_access":          true,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "release_adjacent",
					"confidence_lane":            "confirmed_action_path",
					"delegation_readiness_state": "approval_required",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"attack_path_score":          8.9,
					"risk_score":                 8.9,
				},
				map[string]any{
					"path_id":                    "apc-focused",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/deploy.yml",
					"write_capable":              true,
					"credential_access":          true,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "production_impacting",
					"confidence_lane":            "confirmed_action_path",
					"delegation_readiness_state": "proof_required",
					"recommended_control":        "proof_required",
					"recommended_action":         "proof",
					"attack_path_score":          9.5,
					"risk_score":                 9.5,
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
		"--focus", "write-deploy",
		"--focus-path", "apc-focused",
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	focusView, ok := payload["focus_view"].(map[string]any)
	if !ok || focusView["preset"] != "write-deploy" {
		t.Fatalf("expected write-deploy focus view, got %v", payload["focus_view"])
	}
	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom, got %T", payload["agent_action_bom"])
	}
	summary, ok := bom["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected bom summary, got %T", bom["summary"])
	}
	primaryView, ok := summary["primary_view"].(map[string]any)
	if !ok || primaryView["path_id"] != "apc-focused" {
		t.Fatalf("expected explicit primary view, got %v", summary["primary_view"])
	}
}

func TestReportFocusPresetSupportsShareProfile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-private",
					"org":                        "acme",
					"repo":                       "private-repo",
					"tool_type":                  "compiled_action",
					"location":                   "/Users/example/private/.github/workflows/release.yml",
					"write_capable":              true,
					"credential_access":          true,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "release_adjacent",
					"confidence_lane":            "confirmed_action_path",
					"delegation_readiness_state": "approval_required",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"attack_path_score":          8.9,
					"risk_score":                 8.9,
				},
			},
		},
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--share-profile", "customer-redacted",
		"--focus", "release",
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	focusView, ok := payload["focus_view"].(map[string]any)
	if !ok {
		t.Fatalf("expected focus_view, got %T", payload["focus_view"])
	}
	highlights, ok := focusView["highlights"].([]any)
	if !ok || len(highlights) != 1 {
		t.Fatalf("expected one focus highlight, got %v", focusView["highlights"])
	}
	highlight, ok := highlights[0].(map[string]any)
	if !ok {
		t.Fatalf("expected highlight object, got %T", highlights[0])
	}
	if highlight["repo"] == "private-repo" {
		t.Fatalf("expected share profile redaction in focus view, got %v", highlight)
	}
}

func TestReportFocusPresetSupportsBaseline(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-drift",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/release.yml",
					"write_capable":              true,
					"credential_access":          true,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "release_adjacent",
					"confidence_lane":            "confirmed_action_path",
					"delegation_readiness_state": "approval_required",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"attack_path_score":          8.9,
					"risk_score":                 8.9,
				},
			},
		},
	})

	loaded, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	baseline := regress.BuildBaseline(loaded, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	baselinePath := filepath.Join(tmp, "baseline.json")
	if err := regress.SaveBaseline(baselinePath, baseline); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--baseline", baselinePath,
		"--focus", "drift-review",
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	focusView, ok := payload["focus_view"].(map[string]any)
	if !ok || focusView["preset"] != "drift-review" {
		t.Fatalf("expected drift-review focus view, got %v", payload["focus_view"])
	}
	if focusView["empty_state_status"] != "no_drift_detected" {
		t.Fatalf("expected no_drift_detected empty state, got %v", focusView)
	}
}

func TestReportFocusPresetFiltersToDriftedPaths(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	baselineStatePath := filepath.Join(tmp, "baseline-state.json")
	currentStatePath := filepath.Join(tmp, "current-state.json")
	writeJSONFile(t, baselineStatePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-release",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/release.yml",
					"write_capable":              true,
					"credential_access":          false,
					"approval_gap":               false,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "internal_tooling",
					"boundary_label":             "report_only",
					"approval_evidence_state":    "verified",
					"owner_evidence_state":       "verified",
					"proof_evidence_state":       "verified",
					"runtime_evidence_state":     "unknown",
					"target_evidence_state":      "verified",
					"credential_evidence_state":  "verified",
					"control_resolution_state":   "detected_control",
					"delegation_readiness_state": "review_required",
					"confidence_lane":            "confirmed_action_path",
					"recommended_control":        "owner_review",
					"recommended_action":         "review",
					"attack_path_score":          7.2,
					"risk_score":                 7.2,
				},
			},
		},
	})
	writeJSONFile(t, currentStatePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-28T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-release",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/release.yml",
					"write_capable":              true,
					"credential_access":          true,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "release_adjacent",
					"boundary_label":             "approval_capable",
					"approval_evidence_state":    "unknown",
					"owner_evidence_state":       "verified",
					"proof_evidence_state":       "verified",
					"runtime_evidence_state":     "verified",
					"target_evidence_state":      "verified",
					"credential_evidence_state":  "verified",
					"control_resolution_state":   "detected_control",
					"delegation_readiness_state": "ready_for_control",
					"confidence_lane":            "confirmed_action_path",
					"recommended_control":        "allow",
					"recommended_action":         "control",
					"attack_path_score":          8.4,
					"risk_score":                 8.4,
				},
				map[string]any{
					"path_id":                    "apc-new-write",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/write.yml",
					"write_capable":              true,
					"credential_access":          false,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "production_impacting",
					"boundary_label":             "report_only",
					"approval_evidence_state":    "unknown",
					"owner_evidence_state":       "unknown",
					"proof_evidence_state":       "unknown",
					"runtime_evidence_state":     "unknown",
					"target_evidence_state":      "unknown",
					"credential_evidence_state":  "unknown",
					"control_resolution_state":   "no_visible_control",
					"delegation_readiness_state": "approval_required",
					"confidence_lane":            "confirmed_action_path",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"attack_path_score":          9.1,
					"risk_score":                 9.1,
				},
			},
		},
	})

	loaded, err := state.Load(baselineStatePath)
	if err != nil {
		t.Fatalf("load baseline state: %v", err)
	}
	baseline := regress.BuildBaseline(loaded, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	baselinePath := filepath.Join(tmp, "baseline.json")
	if err := regress.SaveBaseline(baselinePath, baseline); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", currentStatePath,
		"--baseline", baselinePath,
		"--share-profile", "internal",
		"--focus", "drift-review",
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	focusView, ok := payload["focus_view"].(map[string]any)
	if !ok || focusView["preset"] != "drift-review" {
		t.Fatalf("expected drift-review focus view, got %v", payload["focus_view"])
	}
	pathIDs, ok := focusView["path_ids"].([]any)
	if !ok || len(pathIDs) != 2 {
		t.Fatalf("expected two drifted path ids, got %v", focusView["path_ids"])
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", payload["summary"])
	}
	regressDrift, ok := summary["regress_drift"].(map[string]any)
	if !ok {
		t.Fatalf("expected regress_drift summary, got %v", summary["regress_drift"])
	}
	if regressDrift["comparison_status"] != "ok" {
		t.Fatalf("expected comparison_status=ok, got %v", regressDrift["comparison_status"])
	}
	categories, ok := regressDrift["drift_categories"].([]any)
	if !ok || len(categories) == 0 {
		t.Fatalf("expected drift categories, got %v", regressDrift["drift_categories"])
	}
}

func TestReportFocusPresetShowsUnavailableDriftComparisonState(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	baselineStatePath := filepath.Join(tmp, "baseline-state.json")
	currentStatePath := filepath.Join(tmp, "current-state.json")
	writeJSONFile(t, baselineStatePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-27T12:00:00Z",
		},
	})
	writeJSONFile(t, currentStatePath, map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-05-28T12:00:00Z",
			"action_paths": []any{
				map[string]any{
					"path_id":                    "apc-release",
					"org":                        "acme",
					"repo":                       "acme/release",
					"tool_type":                  "compiled_action",
					"location":                   ".github/workflows/release.yml",
					"write_capable":              true,
					"credential_access":          false,
					"approval_gap":               true,
					"action_path_type":           "ci_cd_workflow",
					"target_class":               "release_adjacent",
					"boundary_label":             "report_only",
					"approval_evidence_state":    "unknown",
					"owner_evidence_state":       "unknown",
					"proof_evidence_state":       "unknown",
					"runtime_evidence_state":     "unknown",
					"target_evidence_state":      "unknown",
					"credential_evidence_state":  "unknown",
					"control_resolution_state":   "no_visible_control",
					"delegation_readiness_state": "approval_required",
					"confidence_lane":            "confirmed_action_path",
					"recommended_control":        "approval_required",
					"recommended_action":         "control",
					"attack_path_score":          9.1,
					"risk_score":                 9.1,
				},
			},
		},
	})

	loaded, err := state.Load(baselineStatePath)
	if err != nil {
		t.Fatalf("load baseline state: %v", err)
	}
	baseline := regress.BuildBaseline(loaded, time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC))
	baselinePath := filepath.Join(tmp, "baseline.json")
	if err := regress.SaveBaseline(baselinePath, baseline); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", currentStatePath,
		"--baseline", baselinePath,
		"--focus", "drift-review",
		"--json",
	}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	focusView, ok := payload["focus_view"].(map[string]any)
	if !ok {
		t.Fatalf("expected focus view, got %T", payload["focus_view"])
	}
	if focusView["empty_state_status"] != "drift_comparison_unavailable" {
		t.Fatalf("expected drift_comparison_unavailable, got %v", focusView["empty_state_status"])
	}
}
