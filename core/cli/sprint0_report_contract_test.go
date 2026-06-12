package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/enterprisepressure"
)

const (
	sprint0CLILargeScanRepoCount   = 32
	sprint0CLIStateByteBudget      = 5 << 20
	sprint0CLIEvidenceByteBudget   = 2 << 20
	sprint0CLIMarkdownLineBudget   = 1500
	sprint0CLIExpectedShareProfile = "customer-redacted"
)

func TestSprint0LargeScanSizeSignalBudget(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-pressure")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, sprint0CLILargeScanRepoCount); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "last-scan.json")
	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var scanPayload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &scanPayload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	requirePositiveCLISuppressedCount(t, scanPayload, "findings")
	requirePositiveCLISuppressedCount(t, scanPayload, "inventory_agents")
	requireGroupedCLIPolicyOutcome(t, scanPayload)

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if len(stateBytes) > sprint0CLIStateByteBudget {
		t.Fatalf("expected %s under %d bytes, got %d", filepath.Base(statePath), sprint0CLIStateByteBudget, len(stateBytes))
	}

	mdPath := filepath.Join(tmp, "agent-action-bom.md")
	evidencePath := filepath.Join(tmp, "agent-action-bom-evidence.json")
	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", sprint0CLIExpectedShareProfile,
		"--md",
		"--md-path", mdPath,
		"--evidence-json",
		"--evidence-json-path", evidencePath,
		"--json",
	}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	if summary["share_profile"] != sprint0CLIExpectedShareProfile {
		t.Fatalf("expected share profile %q, got %v", sprint0CLIExpectedShareProfile, summary["share_profile"])
	}
	metadata, ok := summary["share_profile_metadata"].(map[string]any)
	if !ok || metadata["redaction_applied"] != true {
		t.Fatalf("expected redaction metadata on shareable summary, got %v", summary["share_profile_metadata"])
	}
	requireGroupedCLIPolicyOutcome(t, summary)
	requireReportContainsCanonicalRefs(t, reportPayload)

	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence artifact: %v", err)
	}
	if len(evidenceBytes) > sprint0CLIEvidenceByteBudget {
		t.Fatalf("expected %s under %d bytes, got %d", filepath.Base(evidencePath), sprint0CLIEvidenceByteBudget, len(evidenceBytes))
	}

	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown artifact: %v", err)
	}
	markdownLines := strings.Split(strings.TrimRight(string(markdownBytes), "\n"), "\n")
	if len(markdownLines) > sprint0CLIMarkdownLineBudget+2 {
		t.Fatalf("expected markdown under %d lines plus truncation note, got %d", sprint0CLIMarkdownLineBudget+2, len(markdownLines))
	}
	if !strings.Contains(string(markdownBytes), "## Primary Workflow BOM") {
		t.Fatalf("expected primary workflow BOM section, got %q", string(markdownBytes))
	}

	combined := reportOut.String() + "\n" + string(evidenceBytes) + "\n" + string(markdownBytes)
	for _, forbidden := range []string{
		"release-bot",
		"triage-bot",
		"github.example.com/acme/enterprise-001/pull/108",
		"/Users/",
		enterprisepressure.RepoName(1),
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("expected shareable artifacts to redact %q, got %q", forbidden, combined)
		}
	}
	assertShareableOwnerFieldsRedacted(t, reportPayload)
}

func TestShareableArtifactsDoNotLeakOwners(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-shareable")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, 16); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	if code := Run([]string{"scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", sprint0CLIExpectedShareProfile,
		"--json",
	}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}

	payload := map[string]any{}
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	assertShareableOwnerFieldsRedacted(t, payload)
}

func TestShareableDefaultMasksOwnerLikeTokensAcrossArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-default-shareable")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, 16); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	if code := Run([]string{"scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	mdPath := filepath.Join(tmp, "agent-action-bom.md")
	evidencePath := filepath.Join(tmp, "agent-action-bom-evidence.json")
	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--md",
		"--md-path", mdPath,
		"--evidence-json",
		"--evidence-json-path", evidencePath,
		"--json",
	}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}

	payload := map[string]any{}
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", payload["summary"])
	}
	if summary["share_profile"] != sprint0CLIExpectedShareProfile {
		t.Fatalf("expected default share profile %q, got %v", sprint0CLIExpectedShareProfile, summary["share_profile"])
	}
	assertShareableOwnerFieldsRedacted(t, payload)
	assertShareableProjectionUsesCanonicalRefsOnly(t, payload)
	assertShareabilityStatus(t, summary, "shareable")

	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown artifact: %v", err)
	}
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read evidence artifact: %v", err)
	}
	combined := reportOut.String() + "\n" + string(markdownBytes) + "\n" + string(evidenceBytes)
	for _, forbidden := range []string{
		"release-bot",
		"triage-bot",
		"github.example.com/acme/enterprise-001/pull/108",
		"/Users/",
		enterprisepressure.RepoName(1),
	} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("expected shareable default artifacts to redact %q, got %q", forbidden, combined)
		}
	}
}

func TestInternalProfileIsExplicitAndNonShareable(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-internal")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, 16); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	if code := Run([]string{"scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed with code %d", code)
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "internal",
		"--json",
	}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}

	payload := map[string]any{}
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", payload["summary"])
	}
	if summary["share_profile"] != "internal" {
		t.Fatalf("expected explicit internal share profile, got %v", summary["share_profile"])
	}
	assertShareabilityStatus(t, summary, "internal_only")

	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom object, got %T", payload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected agent_action_bom.items, got %T (%v)", bom["items"], bom["items"])
	}
	firstItem, _ := items[0].(map[string]any)
	owner, _ := firstItem["owner"].(string)
	if owner == "" || strings.HasPrefix(owner, "owner-") {
		t.Fatalf("expected explicit internal output to keep a non-redacted owner, got %q", owner)
	}
}

func requirePositiveCLISuppressedCount(t *testing.T, payload map[string]any, key string) {
	t.Helper()

	counts, ok := payload["suppressed_counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected suppressed_counts map, got %T", payload["suppressed_counts"])
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

func requireGroupedCLIPolicyOutcome(t *testing.T, payload map[string]any) {
	t.Helper()

	outcomes, ok := payload["policy_outcomes"].([]any)
	if !ok || len(outcomes) == 0 {
		t.Fatalf("expected grouped policy_outcomes, got %T (%v)", payload["policy_outcomes"], payload["policy_outcomes"])
	}
	for _, raw := range outcomes {
		outcome, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		suppressed, _ := outcome["suppressed_count"].(float64)
		repos, _ := outcome["top_repo_refs"].([]any)
		if suppressed > 0 && len(repos) > 0 {
			return
		}
	}
	t.Fatalf("expected at least one grouped policy outcome with bounded repo examples, got %v", outcomes)
}

func requireReportContainsCanonicalRefs(t *testing.T, payload map[string]any) {
	t.Helper()

	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom object, got %T", payload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected agent_action_bom.items, got %T (%v)", bom["items"], bom["items"])
	}
	hasCredentialAuthorityRef := false
	hasAuthorityBindingRefs := false
	hasEndpointRefs := false
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
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

func assertShareableOwnerFieldsRedacted(t *testing.T, payload map[string]any) {
	t.Helper()

	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom object, got %T", payload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected agent_action_bom.items, got %T (%v)", bom["items"], bom["items"])
	}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		owner, _ := item["owner"].(string)
		if strings.HasPrefix(owner, "@acme/") {
			t.Fatalf("expected shareable owner field to be redacted, got %q", owner)
		}
	}
}

func assertShareableProjectionUsesCanonicalRefsOnly(t *testing.T, payload map[string]any) {
	t.Helper()

	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom object, got %T", payload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected agent_action_bom.items, got %T (%v)", bom["items"], bom["items"])
	}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if item["credential_authority"] != nil || item["authority_bindings"] != nil || item["mutable_endpoint_semantics"] != nil {
			t.Fatalf("expected shareable BOM item to omit embedded canonical payloads, got %+v", item)
		}
		if item["credential_authority_ref"] == nil && item["authority_binding_refs"] == nil && item["mutable_endpoint_semantic_refs"] == nil {
			t.Fatalf("expected shareable BOM item to keep canonical refs, got %+v", item)
		}
	}
}

func assertShareabilityStatus(t *testing.T, summary map[string]any, expected string) {
	t.Helper()

	metadata, ok := summary["artifact_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_metadata object, got %T", summary["artifact_metadata"])
	}
	if metadata["shareability_status"] != expected {
		t.Fatalf("expected shareability_status=%q, got %v", expected, metadata["shareability_status"])
	}
}
