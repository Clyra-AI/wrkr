//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestComposedActionPathContractFixtures(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	fixturePath := filepath.Join(repoRoot, "scenarios", "wrkr", "composed-action-paths", "expected", "composition-contract-fixtures.json")
	payload := readScenarioJSONMap(t, fixturePath)
	assertNoUnsafeFixtureStrings(t, payload)

	items, ok := payload["canonical_scenarios"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected canonical_scenarios, got %+v", payload["canonical_scenarios"])
	}
	wantScenarioIDs := map[string]struct{}{
		"sensitive-read-to-external-send":        {},
		"secret-access-to-network-call":          {},
		"workflow-mutation-to-production-deploy": {},
		"package-modification-to-release":        {},
		"standing-credentials":                   {},
		"incomplete-outcomes":                    {},
		"controlled-transition":                  {},
		"uncontrolled-transition":                {},
	}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("scenario fixture item has wrong shape: %#v", raw)
		}
		scenarioID := stringField(t, item, "scenario_id")
		delete(wantScenarioIDs, scenarioID)
		composition := mapField(t, item, "composition")
		compositionID := stringField(t, composition, "composition_id")
		if compositionID == "" {
			t.Fatalf("%s missing composition_id", scenarioID)
		}
		pathIDs := stringSliceField(t, composition, "path_ids")
		if len(pathIDs) == 0 {
			t.Fatalf("%s missing path_ids", scenarioID)
		}
		for _, pathID := range pathIDs {
			if filepath.IsAbs(pathID) {
				t.Fatalf("%s path_id must not be absolute: %s", scenarioID, pathID)
			}
		}
		contract := mapField(t, composition, "proposed_action_contract")
		if stringField(t, contract, "composition_ref") != compositionID {
			t.Fatalf("%s proposed contract does not point back to composition: %+v", scenarioID, contract)
		}
		if reportOnly, _ := contract["report_only"].(bool); !reportOnly {
			t.Fatalf("%s proposed contract must remain report_only=true", scenarioID)
		}
		contractRefs := stringSliceField(t, composition, "proposed_action_contract_refs")
		if len(contractRefs) != 1 || contractRefs[0] != stringField(t, contract, "contract_id") {
			t.Fatalf("%s contract refs must match contract id, refs=%v contract=%+v", scenarioID, contractRefs, contract)
		}
		primaryView := mapField(t, item, "agent_action_bom_primary_view")
		if stringField(t, primaryView, "composition_id") != compositionID {
			t.Fatalf("%s primary view must point at the same composition, got %+v", scenarioID, primaryView)
		}
		if len(stringSliceField(t, item, "decision_trace_refs")) == 0 {
			t.Fatalf("%s missing decision_trace_refs", scenarioID)
		}
		if len(stringSliceField(t, item, "evidence_refs")) == 0 {
			t.Fatalf("%s missing evidence_refs", scenarioID)
		}
		if familyKey := stringField(t, mapField(t, item, "regress_snapshot"), "composition_family_key"); familyKey == "" {
			t.Fatalf("%s missing regress composition family key", scenarioID)
		}
	}
	if len(wantScenarioIDs) > 0 {
		t.Fatalf("missing canonical composition scenarios: %v", wantScenarioIDs)
	}

	assertCrossProductActionContractManifest(t, repoRoot)
}

func assertCrossProductActionContractManifest(t *testing.T, repoRoot string) {
	t.Helper()
	rel := filepath.Join("scenarios", "cross-product", "action-contract-interop", "expected", "fixture-manifest.json")
	payload := readScenarioJSONMap(t, filepath.Join(repoRoot, rel))
	assertNoUnsafeFixtureStrings(t, payload)
	rows, ok := payload["scenarios"].([]any)
	if !ok || len(rows) != 9 {
		t.Fatalf("%s must contain nine production fixture rows: %+v", rel, payload["scenarios"])
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%s row has wrong shape: %#v", rel, raw)
		}
		for _, field := range []string{"scenario_id", "artifact_path", "artifact_sha256", "contract_id", "contract_family_id", "canonical_content_digest"} {
			if stringField(t, row, field) == "" {
				t.Fatalf("%s row missing %s: %+v", rel, field, row)
			}
		}
		artifactPath := stringField(t, row, "artifact_path")
		if filepath.IsAbs(artifactPath) || strings.Contains(filepath.ToSlash(artifactPath), "..") {
			t.Fatalf("%s row has unsafe artifact path: %+v", rel, row)
		}
		if _, err := os.Stat(filepath.Join(repoRoot, filepath.FromSlash(artifactPath))); err != nil {
			t.Fatalf("%s row artifact is missing: %v", rel, err)
		}
	}
}

func readScenarioJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	return out
}

func stringField(t *testing.T, value map[string]any, key string) string {
	t.Helper()
	got, _ := value[key].(string)
	return strings.TrimSpace(got)
}

func mapField(t *testing.T, value map[string]any, key string) map[string]any {
	t.Helper()
	got, ok := value[key].(map[string]any)
	if !ok {
		t.Fatalf("expected map field %s, got %#v", key, value[key])
	}
	return got
}

func stringSliceField(t *testing.T, value map[string]any, key string) []string {
	t.Helper()
	raw, _ := value[key].([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
			out = append(out, strings.TrimSpace(text))
		}
	}
	return out
}

func assertNoUnsafeFixtureStrings(t *testing.T, value any) {
	t.Helper()
	unsafe := regexp.MustCompile(`(?i)(/Users/|[A-Z]:\\|ghp_|sk_live_|BEGIN PRIVATE|secret_value|raw_payload)`)
	walkScenarioFixtureStrings(t, value, func(text string) {
		if unsafe.MatchString(text) {
			t.Fatalf("fixture contains unsafe string %q", text)
		}
	})
}

func walkScenarioFixtureStrings(t *testing.T, value any, visit func(string)) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			visit(key)
			walkScenarioFixtureStrings(t, child, visit)
		}
	case []any:
		for _, child := range typed {
			walkScenarioFixtureStrings(t, child, visit)
		}
	case string:
		visit(typed)
	}
}
