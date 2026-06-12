//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/enterprisepressure"
)

const (
	sprint0ScenarioRepoCount       = 96
	sprint0ScenarioStateByteBudget = 16 << 20
	sprint0ScenarioEvidenceBudget  = 2 << 20
	sprint0ScenarioMarkdownCap     = 1500
)

func TestScenarioSprint0LargeScanBudgetContract(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	_ = repoRoot

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-pressure")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, sprint0ScenarioRepoCount); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "last-scan.json")
	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json"})
	requirePositiveScenarioSuppressedCount(t, scanPayload, "findings")
	requirePositiveScenarioSuppressedCount(t, scanPayload, "inventory_agents")
	requireScenarioPolicyOutcomeGrouping(t, scanPayload)

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(stateBytes) > sprint0ScenarioStateByteBudget {
		t.Fatalf("expected last-scan.json under %d bytes, got %d", sprint0ScenarioStateByteBudget, len(stateBytes))
	}

	mdPath := filepath.Join(tmp, "agent-action-bom.md")
	evidencePath := filepath.Join(tmp, "agent-action-bom-evidence.json")
	reportPayload := runScenarioCommandJSON(t, []string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--md", "--md-path", mdPath,
		"--evidence-json", "--evidence-json-path", evidencePath,
		"--json",
	})

	summary := requireScenarioObject(t, reportPayload, "summary")
	if stringValue(summary["share_profile"]) != "customer-redacted" {
		t.Fatalf("expected customer-redacted share profile, got %v", summary["share_profile"])
	}
	requireScenarioPolicyOutcomeGrouping(t, summary)
	requireScenarioCanonicalRefs(t, reportPayload)

	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence artifact: %v", err)
	}
	if len(evidenceBytes) > sprint0ScenarioEvidenceBudget {
		t.Fatalf("expected agent-action-bom-evidence.json under %d bytes, got %d", sprint0ScenarioEvidenceBudget, len(evidenceBytes))
	}

	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown artifact: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(markdownBytes), "\n"), "\n")
	if len(lines) > sprint0ScenarioMarkdownCap+2 {
		t.Fatalf("expected markdown under %d lines plus truncation note, got %d", sprint0ScenarioMarkdownCap+2, len(lines))
	}

	reportBytes, err := json.Marshal(reportPayload)
	if err != nil {
		t.Fatalf("marshal report payload: %v", err)
	}
	combined := string(reportBytes) + "\n" + string(evidenceBytes) + "\n" + string(markdownBytes)
	for _, forbidden := range []string{
		"release-bot",
		"triage-bot",
		"github.example.com/acme/enterprise-001/pull/108",
		"/Users/",
		enterprisepressure.RepoName(1),
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("expected shareable artifacts to redact %q", forbidden)
		}
	}
	requireScenarioOwnerFieldsRedacted(t, reportPayload)
}

func requirePositiveScenarioSuppressedCount(t *testing.T, payload map[string]any, key string) {
	t.Helper()

	counts := requireScenarioObject(t, payload, "suppressed_counts")
	value, ok := counts[key]
	if !ok {
		t.Fatalf("expected suppressed_counts[%q], got %v", key, counts)
	}
	number, ok := value.(float64)
	if !ok || number <= 0 {
		t.Fatalf("expected suppressed_counts[%q] > 0, got %v", key, value)
	}
}

func requireScenarioPolicyOutcomeGrouping(t *testing.T, payload map[string]any) {
	t.Helper()

	outcomes := requireArray(t, payload, "policy_outcomes")
	for _, raw := range outcomes {
		outcome := requireObjectItem(t, raw)
		suppressed, _ := outcome["suppressed_count"].(float64)
		repos, _ := outcome["top_repo_refs"].([]any)
		if suppressed > 0 && len(repos) > 0 {
			return
		}
	}
	t.Fatalf("expected grouped policy outcomes with suppressed repo examples, got %v", outcomes)
}

func requireScenarioCanonicalRefs(t *testing.T, payload map[string]any) {
	t.Helper()

	bom := requireScenarioObject(t, payload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	hasCredentialAuthorityRef := false
	hasAuthorityBindingRefs := false
	hasEndpointRefs := false
	for _, raw := range items {
		item := requireObjectItem(t, raw)
		if item["credential_authority_ref"] != nil {
			hasCredentialAuthorityRef = true
		}
		if refs, ok := item["authority_binding_refs"].([]any); ok && len(refs) > 0 {
			hasAuthorityBindingRefs = true
		}
		if endpointRefs, ok := item["mutable_endpoint_semantic_refs"].([]any); ok && len(endpointRefs) > 0 {
			hasEndpointRefs = true
		}
	}
	if !hasCredentialAuthorityRef && !hasAuthorityBindingRefs && !hasEndpointRefs {
		t.Fatalf("expected canonical ref joins in BOM items, got %v", items)
	}
}

func requireScenarioOwnerFieldsRedacted(t *testing.T, payload map[string]any) {
	t.Helper()

	bom := requireScenarioObject(t, payload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	for _, raw := range items {
		item := requireObjectItem(t, raw)
		owner := stringValue(item["owner"])
		if strings.HasPrefix(owner, "@acme/") {
			t.Fatalf("expected shareable owner field to be redacted, got %q", owner)
		}
	}
}
