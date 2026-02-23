package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCampaignAggregateJSON(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	inputA := filepath.Join(tmp, "scan-a.json")
	inputB := filepath.Join(tmp, "scan-b.json")
	scanPayload := map[string]any{
		"status": "ok",
		"target": map[string]any{"mode": "repo", "value": "acme/backend"},
		"source_manifest": map[string]any{
			"target": map[string]any{"mode": "repo", "value": "acme/backend"},
			"repos": []any{
				map[string]any{"repo": "acme/backend", "location": ".wrkr/materialized-sources/acme/backend", "source": "github_repo_materialized"},
			},
		},
		"inventory": map[string]any{
			"inventory_version": "1",
			"generated_at":      "2026-02-23T18:00:00Z",
			"org":               "acme",
			"tools": []any{
				map[string]any{
					"tool_id":                 "wrkr:codex:acme",
					"agent_id":                "wrkr:codex:acme",
					"discovery_method":        "static",
					"tool_type":               "codex",
					"org":                     "acme",
					"repos":                   []any{"acme/backend"},
					"locations":               []any{},
					"endpoint_class":          "workspace",
					"data_class":              "code",
					"autonomy_level":          "interactive",
					"risk_score":              3.2,
					"approval_status":         "missing",
					"approval_classification": "unapproved",
					"lifecycle_state":         "discovered",
				},
			},
			"approval_summary": map[string]any{
				"approved_tools":          0,
				"unapproved_tools":        1,
				"unknown_tools":           0,
				"approved_percent":        0.0,
				"unapproved_percent":      100.0,
				"unknown_percent":         0.0,
				"unapproved_per_approved": nil,
			},
			"privilege_budget": map[string]any{
				"total_tools":             1,
				"write_capable_tools":     1,
				"credential_access_tools": 1,
				"exec_capable_tools":      1,
				"production_write": map[string]any{
					"configured": true,
					"status":     "configured",
					"count":      1,
				},
			},
			"agent_privilege_map":     []any{},
			"summary":                 map[string]any{"total_tools": 1, "high_risk": 0, "medium_risk": 0, "low_risk": 1},
			"repo_exposure_summaries": []any{},
		},
		"privilege_budget": map[string]any{
			"total_tools":             2,
			"write_capable_tools":     1,
			"credential_access_tools": 1,
			"exec_capable_tools":      1,
			"production_write": map[string]any{
				"configured": true,
				"status":     "configured",
				"count":      1,
			},
		},
		"findings": []any{
			map[string]any{
				"finding_type": "tool_config",
				"severity":     "low",
				"tool_type":    "codex",
				"location":     ".codex/config.toml",
				"repo":         "acme/backend",
				"org":          "acme",
				"detector":     "codex",
			},
		},
	}
	payloadBytes, err := json.Marshal(scanPayload)
	if err != nil {
		t.Fatalf("marshal scan payload: %v", err)
	}
	if err := os.WriteFile(inputA, payloadBytes, 0o600); err != nil {
		t.Fatalf("write inputA: %v", err)
	}
	if err := os.WriteFile(inputB, payloadBytes, 0o600); err != nil {
		t.Fatalf("write inputB: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"campaign", "aggregate", "--input-glob", filepath.Join(tmp, "*.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("campaign aggregate failed: code=%d stderr=%s", code, errOut.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("parse campaign output: %v", err)
	}
	if envelope["status"] != "ok" {
		t.Fatalf("unexpected status: %v", envelope["status"])
	}
	campaign, ok := envelope["campaign"].(map[string]any)
	if !ok {
		t.Fatalf("expected campaign object: %v", envelope)
	}
	metrics, ok := campaign["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object: %v", campaign)
	}
	if metrics["tools_detected_total"] != float64(2) {
		t.Fatalf("expected tools_detected_total=2, got %v", metrics["tools_detected_total"])
	}
	if metrics["unapproved_tools"] != float64(2) {
		t.Fatalf("expected unapproved_tools=2, got %v", metrics["unapproved_tools"])
	}
	if metrics["production_write_status"] != "configured" {
		t.Fatalf("unexpected production_write_status: %v", metrics["production_write_status"])
	}
	if _, ok := campaign["segments"].(map[string]any); !ok {
		t.Fatalf("expected segments object in campaign payload: %v", campaign)
	}
}

func TestCampaignAggregateMissingInputGlobExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"campaign", "aggregate", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
}

func TestCampaignAggregateWithSegmentMetadataAndMarkdown(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	inputPath := filepath.Join(tmp, "scan.json")
	mdPath := filepath.Join(tmp, "campaign.md")
	metadataPath := filepath.Join(tmp, "segments.yaml")

	scanPayload := map[string]any{
		"status": "ok",
		"target": map[string]any{"mode": "org", "value": "acme"},
		"source_manifest": map[string]any{
			"target": map[string]any{"mode": "org", "value": "acme"},
			"repos": []any{
				map[string]any{"repo": "acme/backend", "location": ".wrkr/materialized-sources/acme/backend", "source": "github_repo_materialized"},
			},
		},
		"inventory": map[string]any{
			"inventory_version":  "1",
			"generated_at":       "2026-02-23T18:00:00Z",
			"org":                "acme",
			"tools":              []any{},
			"methodology":        map[string]any{"wrkr_version": "devel", "scan_started_at": "", "scan_completed_at": "", "scan_duration_seconds": 0.0, "repo_count": 1, "file_count_processed": 1, "detectors": []any{}},
			"approval_summary":   map[string]any{"approved_tools": 0, "unapproved_tools": 0, "unknown_tools": 0, "approved_percent": 0.0, "unapproved_percent": 0.0, "unknown_percent": 0.0, "unapproved_per_approved": nil},
			"adoption_summary":   map[string]any{"org_wide": 0, "team_level": 0, "individual": 0, "one_off": 0},
			"regulatory_summary": map[string]any{"by_regulation": []any{}, "by_control": []any{}},
			"privilege_budget": map[string]any{
				"total_tools":             0,
				"write_capable_tools":     0,
				"credential_access_tools": 0,
				"exec_capable_tools":      0,
				"production_write": map[string]any{
					"configured": false,
					"status":     "not_configured",
					"count":      nil,
				},
			},
			"agent_privilege_map":     []any{},
			"summary":                 map[string]any{"total_tools": 0, "high_risk": 0, "medium_risk": 0, "low_risk": 0},
			"repo_exposure_summaries": []any{},
		},
		"privilege_budget": map[string]any{
			"total_tools":             0,
			"write_capable_tools":     0,
			"credential_access_tools": 0,
			"exec_capable_tools":      0,
			"production_write": map[string]any{
				"configured": false,
				"status":     "not_configured",
				"count":      nil,
			},
		},
		"findings": []any{},
	}
	payloadBytes, err := json.Marshal(scanPayload)
	if err != nil {
		t.Fatalf("marshal scan payload: %v", err)
	}
	if err := os.WriteFile(inputPath, payloadBytes, 0o600); err != nil {
		t.Fatalf("write input scan: %v", err)
	}
	segmentPayload := []byte(`
schema_version: v1
orgs:
  acme:
    industry: fintech
    size_band: medium
`)
	if err := os.WriteFile(metadataPath, segmentPayload, 0o600); err != nil {
		t.Fatalf("write segment metadata: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"campaign", "aggregate",
		"--input-glob", inputPath,
		"--segment-metadata", metadataPath,
		"--md",
		"--md-path", mdPath,
		"--template", "public",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("campaign aggregate failed: code=%d stderr=%s", code, errOut.String())
	}
	var envelope map[string]any
	if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
		t.Fatalf("parse campaign output: %v", err)
	}
	campaign, ok := envelope["campaign"].(map[string]any)
	if !ok {
		t.Fatalf("expected campaign object: %v", envelope)
	}
	segments, ok := campaign["segments"].(map[string]any)
	if !ok {
		t.Fatalf("expected segments object: %v", campaign)
	}
	industryBands, ok := segments["industry_bands"].([]any)
	if !ok || len(industryBands) == 0 {
		t.Fatalf("expected industry_bands in segments: %v", segments)
	}
	firstBand, ok := industryBands[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected industry band payload: %T", industryBands[0])
	}
	if firstBand["segment"] != "fintech" {
		t.Fatalf("expected metadata-driven industry segment fintech, got %v", firstBand["segment"])
	}
	if _, ok := envelope["md_path"].(string); !ok {
		t.Fatalf("expected md_path in envelope: %v", envelope)
	}
	markdownPayload, readErr := os.ReadFile(mdPath)
	if readErr != nil {
		t.Fatalf("read markdown output: %v", readErr)
	}
	if !bytes.Contains(markdownPayload, []byte("## 1. Headline Findings")) {
		t.Fatalf("unexpected markdown content: %s", markdownPayload)
	}
}
