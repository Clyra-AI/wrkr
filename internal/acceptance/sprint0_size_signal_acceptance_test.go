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
	sprint0AcceptanceLeadLineCap     = 45
	sprint0AcceptanceLeadSectionCap  = 5
	sprint0EndpointDenseRepoCount    = 4
	sprint0EndpointDenseStateBudget  = 24 << 20
)

func TestSprint0AgentActionBOMArtifactsStayBoundedAndRedacted(t *testing.T) {
	t.Parallel()

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
	if len(lines) > sprint0AcceptanceMarkdownLineCap {
		t.Fatalf("expected markdown at or under %d lines including truncation note, got %d", sprint0AcceptanceMarkdownLineCap, len(lines))
	}
	requireAcceptanceLeadEvidenceBundle(t, evidenceBytes)
	contextIdx := strings.Index(string(markdownBytes), "## Report Context Appendix")
	if contextIdx < 0 {
		t.Fatalf("expected report context appendix in BOM markdown, got %q", string(markdownBytes))
	}
	lead := string(markdownBytes[:contextIdx])
	leadLines := strings.Split(strings.TrimRight(lead, "\n"), "\n")
	if len(leadLines) > sprint0AcceptanceLeadLineCap {
		t.Fatalf("expected BOM lead view under %d lines, got %d", sprint0AcceptanceLeadLineCap, len(leadLines))
	}
	if strings.Count(lead, "\n## ") > sprint0AcceptanceLeadSectionCap {
		t.Fatalf("expected BOM lead view to stay within %d sections, got %q", sprint0AcceptanceLeadSectionCap, lead)
	}
	for _, machineID := range []string{"xrg-", "path=", "examples=path-", "apc-"} {
		if strings.Contains(lead, machineID) {
			t.Fatalf("expected BOM lead view to hide machine id %q, got %q", machineID, lead)
		}
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
	requireAcceptanceOwnerFieldsRedacted(t, reportPayload)
}

func TestSprint0EndpointDenseArtifactsUseGroupedEndpointProjection(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "endpoint-dense-pressure")
	if err := enterprisepressure.MaterializeEndpointDense(scanRoot, sprint0EndpointDenseRepoCount, enterprisepressure.DefaultDenseOpenAPIOperations); err != nil {
		t.Fatalf("materialize endpoint-dense fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "endpoint-dense-scan.json")
	scanPayload := runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json")
	actionPaths := requireArrayFromObject(t, scanPayload, "action_paths")
	groupedPathFound := false
	for _, raw := range actionPaths {
		path := requireObjectItem(t, raw)
		count, _ := path["endpoint_ref_count"].(float64)
		refs := requireOptionalArrayLength(path["mutable_endpoint_semantic_refs"])
		if int(count) > refs && int(count) >= 1000 {
			groupedPathFound = true
		}
	}
	if !groupedPathFound {
		t.Fatalf("expected grouped endpoint-dense action path, got %v", actionPaths)
	}

	reportPayload := runJSONOK(
		t,
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--json",
	)
	bom := requireObject(t, reportPayload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	groupedItemFound := false
	for _, raw := range items {
		item := requireObjectItem(t, raw)
		count, _ := item["endpoint_ref_count"].(float64)
		refs := requireOptionalArrayLength(item["mutable_endpoint_semantic_refs"])
		if int(count) > refs && int(count) >= 1000 {
			groupedItemFound = true
			if refs > 8 {
				t.Fatalf("expected bounded endpoint ref samples, got %d in %v", refs, item)
			}
			if requireOptionalArrayLength(item["endpoint_ref_samples"]) == 0 {
				t.Fatalf("expected endpoint_ref_samples on grouped BOM item, got %v", item)
			}
		}
	}
	if !groupedItemFound {
		t.Fatalf("expected grouped endpoint-dense BOM item, got %v", items)
	}

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read endpoint-dense state: %v", err)
	}
	if len(stateBytes) > sprint0EndpointDenseStateBudget {
		t.Fatalf("expected endpoint-dense state under %d bytes, got %d", sprint0EndpointDenseStateBudget, len(stateBytes))
	}
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

func requireAcceptanceLeadEvidenceBundle(t *testing.T, evidenceBytes []byte) {
	t.Helper()

	var evidence map[string]any
	if err := json.Unmarshal(evidenceBytes, &evidence); err != nil {
		t.Fatalf("unmarshal evidence artifact: %v", err)
	}
	if focused, _ := evidence["focused_bundle_available"].(bool); !focused {
		t.Fatalf("expected default agent-action-bom evidence to be a focused lead bundle, got %v", evidence["focused_bundle_available"])
	}
	if _, ok := evidence["control_path_graph"]; ok {
		t.Fatalf("expected lead evidence bundle to omit full control_path_graph")
	}
	if _, ok := evidence["workflow_chains"]; ok {
		t.Fatalf("expected lead evidence bundle to omit full workflow_chains")
	}
	if full, ok := evidence["full_export_available"].(bool); ok && !full {
		t.Fatalf("expected full_export_available to be true when present, got %v", evidence["full_export_available"])
	}
	if counts, ok := evidence["suppressed_counts"].(map[string]any); ok {
		if graphNodes, ok := counts["graph_nodes"].(float64); ok && graphNodes <= 0 {
			t.Fatalf("expected positive graph node suppression when graph_nodes is present, got %v", counts)
		}
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

func requireOptionalArrayLength(value any) int {
	items, ok := value.([]any)
	if !ok {
		return 0
	}
	return len(items)
}
