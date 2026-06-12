package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/enterprisepressure"
)

const (
	sprint0AcceptanceRepoCount       = 96
	sprint0AcceptanceStateByteBudget = 16 << 20
	sprint0AcceptanceEvidenceBudget  = 2 << 20
	sprint0AcceptanceMarkdownLineCap = 1500
)

func TestSprint0AgentActionBOMArtifactsStayBoundedAndRedacted(t *testing.T) {
	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-pressure")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, sprint0AcceptanceRepoCount); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "last-scan.json")
	scanPayload := runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json")
	requirePositiveAcceptanceSuppressedCount(t, scanPayload, "findings")
	requirePositiveAcceptanceSuppressedCount(t, scanPayload, "inventory_agents")
	requireAcceptancePolicyOutcomeGrouping(t, scanPayload)

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(stateBytes) > sprint0AcceptanceStateByteBudget {
		t.Fatalf("expected last-scan.json under %d bytes, got %d", sprint0AcceptanceStateByteBudget, len(stateBytes))
	}

	mdPath := filepath.Join(tmp, "agent-action-bom.md")
	evidencePath := filepath.Join(tmp, "agent-action-bom-evidence.json")
	reportPayload := runJSONOK(
		t,
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--md", "--md-path", mdPath,
		"--evidence-json", "--evidence-json-path", evidencePath,
		"--json",
	)

	summary := requireObject(t, reportPayload, "summary")
	if summary["share_profile"] != "customer-redacted" {
		t.Fatalf("expected customer-redacted share profile, got %v", summary["share_profile"])
	}
	metadata := requireObject(t, summary, "share_profile_metadata")
	if metadata["redaction_applied"] != true {
		t.Fatalf("expected redaction metadata, got %v", metadata)
	}
	requireAcceptancePolicyOutcomeGrouping(t, summary)
	requireAcceptanceCanonicalRefs(t, reportPayload)

	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence artifact: %v", err)
	}
	if len(evidenceBytes) > sprint0AcceptanceEvidenceBudget {
		t.Fatalf("expected agent-action-bom-evidence.json under %d bytes, got %d", sprint0AcceptanceEvidenceBudget, len(evidenceBytes))
	}

	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown artifact: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(markdownBytes), "\n"), "\n")
	if len(lines) > sprint0AcceptanceMarkdownLineCap+2 {
		t.Fatalf("expected markdown under %d lines plus truncation note, got %d", sprint0AcceptanceMarkdownLineCap+2, len(lines))
	}

	summaryBytes, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal report summary: %v", err)
	}
	combined := string(summaryBytes) + "\n" + string(evidenceBytes) + "\n" + string(markdownBytes)
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
	requireAcceptanceOwnerFieldsRedacted(t, reportPayload)
}

func requirePositiveAcceptanceSuppressedCount(t *testing.T, payload map[string]any, key string) {
	t.Helper()

	counts, ok := payload["suppressed_counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected suppressed_counts, got %T", payload["suppressed_counts"])
	}
	value, ok := counts[key]
	if !ok {
		t.Fatalf("expected suppressed_counts[%q], got %v", key, counts)
	}
	number, ok := value.(float64)
	if !ok || number <= 0 {
		t.Fatalf("expected suppressed_counts[%q] > 0, got %v", key, value)
	}
}

func requireAcceptancePolicyOutcomeGrouping(t *testing.T, payload map[string]any) {
	t.Helper()

	outcomes, ok := payload["policy_outcomes"].([]any)
	if !ok || len(outcomes) == 0 {
		t.Fatalf("expected policy_outcomes, got %T (%v)", payload["policy_outcomes"], payload["policy_outcomes"])
	}
	for _, raw := range outcomes {
		outcome := requireObjectItem(t, raw)
		suppressed, _ := outcome["suppressed_count"].(float64)
		repos, _ := outcome["top_repo_refs"].([]any)
		if suppressed > 0 && len(repos) > 0 {
			return
		}
	}
	t.Fatalf("expected grouped policy outcomes with bounded repo examples, got %v", outcomes)
}

func requireAcceptanceCanonicalRefs(t *testing.T, reportPayload map[string]any) {
	t.Helper()

	bom := requireObject(t, reportPayload, "agent_action_bom")
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

func requireAcceptanceOwnerFieldsRedacted(t *testing.T, reportPayload map[string]any) {
	t.Helper()

	bom := requireObject(t, reportPayload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	for _, raw := range items {
		item := requireObjectItem(t, raw)
		owner, _ := item["owner"].(string)
		if strings.HasPrefix(owner, "@acme/") {
			t.Fatalf("expected shareable owner field to be redacted, got %q", owner)
		}
	}
}
