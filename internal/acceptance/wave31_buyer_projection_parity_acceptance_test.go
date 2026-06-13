package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWave31BuyerProjectionParityAcrossConsumers(t *testing.T) {
	paths := loadAcceptancePaths(t)

	statePath := filepath.Join(t.TempDir(), "after-state.json")
	afterRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "after")
	afterScanRoot := filepath.Join(afterRoot, "repos")
	runtimeEvidencePath := filepath.Join(afterRoot, "runtime-evidence.json")
	reportMDPath := filepath.Join(t.TempDir(), "agent-action-bom.md")

	runJSONOK(t, "scan", "--path", afterScanRoot, "--state", statePath, "--json")
	runJSONOK(t, "ingest", "--state", statePath, "--input", runtimeEvidencePath, "--json")
	reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "customer-redacted", "--md", "--md-path", reportMDPath, "--json")
	evidencePayload := runJSONOK(t, "evidence", "--frameworks", "soc2", "--state", statePath, "--output", filepath.Join(t.TempDir(), "bundle"), "--json")

	reportSummary := requireObject(t, reportPayload, "summary")
	reportBOM := requireObject(t, reportPayload, "agent_action_bom")
	reportBOMSummary := requireObject(t, reportBOM, "summary")
	primaryView := requireObject(t, reportBOMSummary, "primary_view")
	pathID, _ := primaryView["path_id"].(string)
	if strings.TrimSpace(pathID) == "" {
		t.Fatalf("expected primary_view.path_id, got %v", primaryView)
	}

	actionPath := actionPathByID(t, requireArrayFromObject(t, reportSummary, "action_paths"), pathID)
	bomItem := bomItemByID(t, requireArrayFromObject(t, reportBOM, "items"), pathID)
	backlogItem := backlogItemByPathID(t, requireArrayFromObject(t, requireObject(t, reportSummary, "control_backlog"), "items"), pathID)
	graphNode := graphPathNodeByPathID(t, requireArrayFromObject(t, requireObject(t, reportSummary, "control_path_graph"), "nodes"), pathID)
	registryEntry := registryEntryByPathID(t, requireArrayFromObject(t, reportSummary, "action_surface_registry"), pathID)
	evidenceBOM := requireObject(t, evidencePayload, "agent_action_bom")
	evidenceItem := bomItemByID(t, requireArrayFromObject(t, evidenceBOM, "items"), pathID)

	for _, key := range []string{
		"control_resolution_state",
		"approval_evidence_state",
		"owner_evidence_state",
		"proof_evidence_state",
		"target_evidence_state",
		"credential_evidence_state",
		"delegation_readiness_state",
		"recommended_control",
		"control_state",
		"risk_zone",
		"review_burden",
	} {
		if actionPath[key] != bomItem[key] {
			t.Fatalf("expected report action path and BOM item to agree on %s, action=%v bom=%v", key, actionPath[key], bomItem[key])
		}
		if bomItem[key] != backlogItem[key] {
			t.Fatalf("expected BOM item and backlog item to agree on %s, bom=%v backlog=%v", key, bomItem[key], backlogItem[key])
		}
		if bomItem[key] != evidenceItem[key] {
			t.Fatalf("expected report/evidence BOM items to agree on %s, report=%v evidence=%v", key, bomItem[key], evidenceItem[key])
		}
	}
	if actionPath["boundary_label"] != bomItem["boundary_label"] {
		t.Fatalf("expected action path and BOM item to agree on boundary_label, action=%v bom=%v", actionPath["boundary_label"], bomItem["boundary_label"])
	}

	if bomItem["credential_authority_ref"] != graphNode["credential_authority_ref"] {
		t.Fatalf("expected graph node credential authority ref to match BOM item, graph=%v bom=%v", graphNode["credential_authority_ref"], bomItem["credential_authority_ref"])
	}
	if bomItem["boundary_label"] != graphNode["boundary_label"] {
		t.Fatalf("expected graph node boundary label to match BOM item, graph=%v bom=%v", graphNode["boundary_label"], bomItem["boundary_label"])
	}
	if registryEntry["confidence_lane"] != bomItem["confidence_lane"] {
		t.Fatalf("expected registry entry confidence lane to match BOM item, registry=%v bom=%v", registryEntry["confidence_lane"], bomItem["confidence_lane"])
	}
	if !arrayContainsString(t, registryEntry["path_ids"], pathID) {
		t.Fatalf("expected registry entry path_ids to contain %s, got %v", pathID, registryEntry["path_ids"])
	}

	if reportSummary["repeat_usage_signals"] == nil {
		t.Fatalf("expected summary repeat_usage_signals, got %v", reportSummary["repeat_usage_signals"])
	}
	if reportBOMSummary["repeat_usage_signals"] == nil {
		t.Fatalf("expected BOM repeat_usage_signals, got %v", reportBOMSummary["repeat_usage_signals"])
	}

	markdown, err := os.ReadFile(reportMDPath)
	if err != nil {
		t.Fatalf("read report markdown: %v", err)
	}
	for _, required := range []string{
		firstStringValue(t, bomItem["repo"]),
		firstStringValue(t, bomItem["location"]),
		firstStringValue(t, bomItem["remediation"]),
	} {
		if required == "" {
			continue
		}
		if !strings.Contains(string(markdown), required) {
			t.Fatalf("expected markdown to preserve %q from the canonical projection", required)
		}
	}
}

func actionPathByID(t *testing.T, values []any, pathID string) map[string]any {
	t.Helper()
	for _, value := range values {
		item := requireObjectItem(t, value)
		if item["path_id"] == pathID {
			return item
		}
	}
	t.Fatalf("missing action path %q", pathID)
	return nil
}

func bomItemByID(t *testing.T, values []any, pathID string) map[string]any {
	t.Helper()
	for _, value := range values {
		item := requireObjectItem(t, value)
		if item["path_id"] == pathID {
			return item
		}
	}
	t.Fatalf("missing BOM item %q", pathID)
	return nil
}

func backlogItemByPathID(t *testing.T, values []any, pathID string) map[string]any {
	t.Helper()
	for _, value := range values {
		item := requireObjectItem(t, value)
		if item["linked_action_path_id"] == pathID {
			return item
		}
	}
	t.Fatalf("missing backlog item for %q", pathID)
	return nil
}

func graphPathNodeByPathID(t *testing.T, values []any, pathID string) map[string]any {
	t.Helper()
	var fallback map[string]any
	for _, value := range values {
		item := requireObjectItem(t, value)
		if item["path_id"] == pathID {
			if item["credential_authority_ref"] != nil {
				return item
			}
			if fallback == nil {
				fallback = item
			}
		}
	}
	if fallback != nil {
		return fallback
	}
	t.Fatalf("missing graph node for %q", pathID)
	return nil
}

func registryEntryByPathID(t *testing.T, values []any, pathID string) map[string]any {
	t.Helper()
	for _, value := range values {
		item := requireObjectItem(t, value)
		if arrayContainsString(t, item["path_ids"], pathID) {
			return item
		}
	}
	t.Fatalf("missing registry entry for %q", pathID)
	return nil
}

func arrayContainsString(t *testing.T, value any, want string) bool {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		return false
	}
	for _, candidate := range values {
		if text, ok := candidate.(string); ok && text == want {
			return true
		}
	}
	return false
}

func firstStringValue(t *testing.T, value any) string {
	t.Helper()
	text, _ := value.(string)
	return strings.TrimSpace(text)
}
