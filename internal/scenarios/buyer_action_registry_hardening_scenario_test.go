//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestScenarioBuyerActionRegistryHardening(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "buyer-action-registry-hardening", "repos")
	expectedRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "buyer-action-registry-hardening", "expected")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	designPartnerMD := filepath.Join(tmp, "design-partner.md")
	designPartnerEvidence := filepath.Join(tmp, "design-partner-evidence.json")

	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	internalReport := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--json"})
	customerReport := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "customer-redacted", "--json"})
	_ = runScenarioCommandJSON(t, []string{
		"report",
		"--state", statePath,
		"--template", "design-partner-summary",
		"--share-profile", "design-partner",
		"--md", "--md-path", designPartnerMD,
		"--evidence-json", "--evidence-json-path", designPartnerEvidence,
		"--json",
	})

	assertScenarioJSONEquals(t, filepath.Join(expectedRoot, "scan-summary.json"), buyerActionRegistryScanSummary(t, scanPayload))
	assertScenarioJSONEquals(t, filepath.Join(expectedRoot, "report-internal-summary.json"), buyerActionRegistryInternalReportSummary(t, internalReport))
	assertScenarioJSONEquals(t, filepath.Join(expectedRoot, "report-customer-redacted-summary.json"), buyerActionRegistryCustomerReportSummary(t, customerReport))
	assertScenarioJSONEquals(t, filepath.Join(expectedRoot, "evidence-design-partner-summary.json"), buyerActionRegistryEvidenceSummary(t, designPartnerEvidence))
	assertScenarioMarkdownLinesEqual(t, filepath.Join(expectedRoot, "design-partner-lines.txt"), designPartnerMD)
}

func buyerActionRegistryScanSummary(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	actionPaths := requireArray(t, payload, "action_paths")
	laneCounts := laneCountsByActionPath(t, actionPaths)
	confirmed := firstActionPathByLane(t, actionPaths, "confirmed_action_path")
	mutable := firstActionPathWithMutableEndpoint(t, actionPaths)
	return map[string]any{
		"action_path_count": float64(len(actionPaths)),
		"lane_counts":       laneCounts,
		"confirmed_path": map[string]any{
			"repo":            confirmed["repo"],
			"location":        confirmed["location"],
			"confidence_lane": confirmed["confidence_lane"],
		},
		"mutable_surface_path": map[string]any{
			"repo":                 mutable["repo"],
			"location":             mutable["location"],
			"confidence_lane":      mutable["confidence_lane"],
			"semantics":            mutableEndpointSemantics(t, mutable),
			"config_fingerprint":   mutable["config_fingerprint"],
			"action_lineage_kinds": lineageKinds(t, requireObject(t, mutable, "action_lineage")),
		},
	}
}

func buyerActionRegistryInternalReportSummary(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	summary := requireObject(t, payload, "summary")
	bom := requireObject(t, summary, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	registry := requireArrayFromObject(t, summary, "action_surface_registry")
	confirmed := firstItemByLane(t, items, "confirmed_action_path")
	semantic := firstItemByLane(t, items, "semantic_review_candidate")
	return map[string]any{
		"template":       summary["template"],
		"share_profile":  summary["share_profile"],
		"bom_count":      float64(len(items)),
		"registry_count": float64(len(registry)),
		"lane_counts":    laneCountsByItems(t, items),
		"confirmed_item": map[string]any{
			"repo":           confirmed["repo"],
			"location":       confirmed["location"],
			"remediation":    confirmed["remediation"],
			"proof_coverage": confirmed["proof_coverage"],
			"policy_status":  confirmed["policy_status"],
			"credential_authority": map[string]any{
				"credential_present":                requireObject(t, confirmed, "credential_authority")["credential_present"],
				"credential_referenced_by_workflow": requireObject(t, confirmed, "credential_authority")["credential_referenced_by_workflow"],
				"credential_usable_by_path":         requireObject(t, confirmed, "credential_authority")["credential_usable_by_path"],
				"access_type":                       requireObject(t, confirmed, "credential_authority")["access_type"],
				"standing_access":                   requireObject(t, confirmed, "credential_authority")["standing_access"],
				"rotation_evidence_status":          requireObject(t, confirmed, "credential_authority")["rotation_evidence_status"],
				"credential_source":                 requireObject(t, confirmed, "credential_authority")["credential_source"],
				"confidence":                        requireObject(t, confirmed, "credential_authority")["confidence"],
			},
			"lineage_statuses": lineageStatuses(t, requireObject(t, confirmed, "action_lineage")),
		},
		"semantic_item": map[string]any{
			"repo":            semantic["repo"],
			"location":        semantic["location"],
			"remediation":     semantic["remediation"],
			"confidence_lane": semantic["confidence_lane"],
			"proof_coverage":  semantic["proof_coverage"],
		},
		"registry_surface_types": uniqueSortedValues(t, registry, "surface_type"),
	}
}

func buyerActionRegistryCustomerReportSummary(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	summary := requireObject(t, payload, "summary")
	metadata := requireObject(t, summary, "share_profile_metadata")
	bom := requireObject(t, summary, "agent_action_bom")
	first := requireObjectItem(t, requireArrayFromObject(t, bom, "items")[0])
	lineage := requireObject(t, first, "action_lineage")
	firstSegment := requireObjectItem(t, requireArrayFromObject(t, lineage, "segments")[0])
	graphRefs := requireObject(t, first, "graph_refs")
	return map[string]any{
		"template":      summary["template"],
		"share_profile": summary["share_profile"],
		"metadata": map[string]any{
			"redaction_applied":      metadata["redaction_applied"],
			"redaction_version":      metadata["redaction_version"],
			"selected_fields":        metadata["selected_fields"],
			"profile_default_fields": metadata["profile_default_fields"],
		},
		"first_item": map[string]any{
			"repo":       first["repo"],
			"location":   first["location"],
			"owner":      first["owner"],
			"proof_refs": first["proof_refs"],
			"graph_ref_prefixes": map[string]any{
				"node": prefixFromArray(t, graphRefs["node_ids"], "node-"),
				"edge": prefixFromArray(t, graphRefs["edge_ids"], "edge-"),
			},
			"lineage_prefixes": map[string]any{
				"segment":  prefixString(t, firstSegment["segment_id"], "segment-"),
				"label":    prefixString(t, firstSegment["label"], "label-"),
				"evidence": prefixFromArray(t, firstSegment["evidence_refs"], "evidence-"),
			},
		},
		"proof_chain": requireObject(t, summary, "proof")["chain_path"],
	}
}

func buyerActionRegistryEvidenceSummary(t *testing.T, evidencePath string) map[string]any {
	t.Helper()
	payload := loadScenarioJSONFile(t, evidencePath)
	registry := requireArray(t, payload, "action_surface_registry")
	bom := requireObject(t, payload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	metadata := requireObject(t, payload, "share_profile_metadata")
	firstRegistry := requireObjectItem(t, registry[0])
	firstItem := requireObjectItem(t, items[0])
	return map[string]any{
		"template":      payload["template"],
		"share_profile": payload["share_profile"],
		"metadata": map[string]any{
			"redaction_applied":      metadata["redaction_applied"],
			"redaction_version":      metadata["redaction_version"],
			"selected_fields":        metadata["selected_fields"],
			"profile_default_fields": metadata["profile_default_fields"],
		},
		"registry_count": float64(len(registry)),
		"bom_count":      float64(len(items)),
		"first_registry": map[string]any{
			"surface_type":    firstRegistry["surface_type"],
			"remediation":     firstRegistry["remediation"],
			"confidence_lane": firstRegistry["confidence_lane"],
		},
		"first_bom": map[string]any{
			"repo":            firstItem["repo"],
			"location":        firstItem["location"],
			"remediation":     firstItem["remediation"],
			"confidence_lane": firstItem["confidence_lane"],
		},
	}
}

func assertScenarioJSONEquals(t *testing.T, path string, actual map[string]any) {
	t.Helper()
	if os.Getenv("WRKR_UPDATE_GOLDENS") == "1" {
		payload, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatalf("marshal %s: %v", path, err)
		}
		if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	expected := loadScenarioJSONFile(t, path)
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("scenario mismatch for %s\nexpected=%v\nactual=%v", path, expected, actual)
	}
}

func assertScenarioMarkdownLinesEqual(t *testing.T, expectedPath, actualPath string) {
	t.Helper()
	expectedPayload, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected markdown lines: %v", err)
	}
	actualPayload, err := os.ReadFile(actualPath)
	if err != nil {
		t.Fatalf("read actual markdown: %v", err)
	}
	if os.Getenv("WRKR_UPDATE_GOLDENS") == "1" {
		if err := os.WriteFile(expectedPath, actualPayload, 0o600); err != nil {
			t.Fatalf("write %s: %v", expectedPath, err)
		}
		return
	}
	expectedLines := filteredScenarioMarkdownLines(string(expectedPayload))
	actualLines := filteredScenarioMarkdownLines(string(actualPayload))
	if len(actualLines) < len(expectedLines) {
		t.Fatalf("expected at least %d markdown lines, got %d", len(expectedLines), len(actualLines))
	}
	if !reflect.DeepEqual(expectedLines, actualLines[:len(expectedLines)]) {
		t.Fatalf("markdown lines mismatch\nexpected=%v\nactual=%v", expectedLines, actualLines[:len(expectedLines)])
	}
}

func loadScenarioJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return out
}

func filteredScenarioMarkdownLines(markdown string) []string {
	raw := strings.Split(markdown, "\n")
	lines := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "- Generated at:") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

func laneCountsByActionPath(t *testing.T, items []any) map[string]any {
	t.Helper()
	counts := map[string]float64{}
	for _, item := range items {
		path := requireObjectItem(t, item)
		key, _ := path["confidence_lane"].(string)
		counts[key]++
	}
	out := map[string]any{}
	for key, value := range counts {
		out[key] = value
	}
	return out
}

func laneCountsByItems(t *testing.T, items []any) map[string]any {
	t.Helper()
	counts := map[string]float64{}
	for _, item := range items {
		row := requireObjectItem(t, item)
		key, _ := row["confidence_lane"].(string)
		counts[key]++
	}
	out := map[string]any{}
	for key, value := range counts {
		out[key] = value
	}
	return out
}

func firstActionPathByLane(t *testing.T, items []any, lane string) map[string]any {
	t.Helper()
	for _, item := range items {
		path := requireObjectItem(t, item)
		if path["confidence_lane"] == lane {
			return path
		}
	}
	t.Fatalf("missing action path lane %q", lane)
	return nil
}

func firstActionPathWithMutableEndpoint(t *testing.T, items []any) map[string]any {
	t.Helper()
	for _, item := range items {
		path := requireObjectItem(t, item)
		if arr, ok := path["mutable_endpoint_semantics"].([]any); ok && len(arr) > 0 {
			return path
		}
	}
	t.Fatal("missing mutable endpoint action path")
	return nil
}

func firstItemByLane(t *testing.T, items []any, lane string) map[string]any {
	t.Helper()
	for _, item := range items {
		row := requireObjectItem(t, item)
		if row["confidence_lane"] == lane {
			return row
		}
	}
	t.Fatalf("missing BOM lane %q", lane)
	return nil
}

func mutableEndpointSemantics(t *testing.T, item map[string]any) []any {
	t.Helper()
	values := requireArrayFromObject(t, item, "mutable_endpoint_semantics")
	out := make([]any, 0, len(values))
	for _, entry := range values {
		obj := requireObjectItem(t, entry)
		out = append(out, obj["semantic"])
	}
	return out
}

func lineageKinds(t *testing.T, lineage map[string]any) []any {
	t.Helper()
	segments := requireArrayFromObject(t, lineage, "segments")
	out := make([]any, 0, len(segments))
	for _, segment := range segments {
		obj := requireObjectItem(t, segment)
		out = append(out, obj["kind"])
	}
	return out
}

func lineageStatuses(t *testing.T, lineage map[string]any) []any {
	t.Helper()
	segments := requireArrayFromObject(t, lineage, "segments")
	out := make([]any, 0, len(segments))
	for _, segment := range segments {
		obj := requireObjectItem(t, segment)
		out = append(out, map[string]any{
			"kind":   obj["kind"],
			"status": obj["status"],
		})
	}
	return out
}

func uniqueSortedValues(t *testing.T, items []any, key string) []any {
	t.Helper()
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range items {
		obj := requireObjectItem(t, item)
		value, _ := obj[key].(string)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	values := make([]any, 0, len(out))
	for _, value := range out {
		values = append(values, value)
	}
	return values
}

func prefixFromArray(t *testing.T, value any, prefix string) any {
	t.Helper()
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected array with prefix %q, got %v", prefix, value)
	}
	return prefixString(t, items[0], prefix)
}

func prefixString(t *testing.T, value any, prefix string) any {
	t.Helper()
	text, ok := value.(string)
	if !ok || !strings.HasPrefix(text, prefix) {
		t.Fatalf("expected %v to have prefix %q", value, prefix)
	}
	return prefix
}

func requireObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("expected object for %q, got %T", key, payload[key])
	}
	return value
}

func requireArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected array for %q, got %T", key, payload[key])
	}
	return value
}

func requireArrayFromObject(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected array for %q, got %T", key, payload[key])
	}
	return value
}

func requireObjectItem(t *testing.T, value any) map[string]any {
	t.Helper()
	item, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object item, got %T", value)
	}
	return item
}
