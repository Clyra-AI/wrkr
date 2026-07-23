package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuyerActionRegistryHardeningAcceptance(t *testing.T) {
	t.Parallel()

	paths := loadAcceptancePaths(t)
	scanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "buyer-action-registry-hardening", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdPath := filepath.Join(tmp, "design-partner.md")
	evidencePath := filepath.Join(tmp, "design-partner-evidence.json")

	scanPayload := runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--json")
	actionPaths := requireArray(t, scanPayload, "action_paths")
	if len(actionPaths) < 4 {
		t.Fatalf("expected multiple action paths, got %d", len(actionPaths))
	}

	designPartner := runJSONOK(t,
		"report",
		"--state", statePath,
		"--template", "design-partner-summary",
		"--share-profile", "design-partner",
		"--md", "--md-path", mdPath,
		"--evidence-json", "--evidence-json-path", evidencePath,
		"--json",
	)
	summary := requireObject(t, designPartner, "summary")
	if summary["template"] != "design-partner-summary" || summary["share_profile"] != "design-partner" {
		t.Fatalf("unexpected design-partner report summary: %v", summary)
	}
	metadata := requireObject(t, summary, "share_profile_metadata")
	if metadata["redaction_applied"] != true {
		t.Fatalf("expected redaction metadata, got %v", metadata)
	}
	mdPayload, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read design-partner markdown: %v", err)
	}
	markdown := string(mdPayload)
	for _, want := range []string{
		"Wrkr Design Partner Summary",
		"## Top Validated Findings",
		"Boundary: static posture from saved scan state only; no live runtime observation, endpoint probing, or control-layer enforcement",
		"Evidence class: confirmed path",
		"Inferred relationship:",
		"Unresolved context:",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("expected markdown to contain %q, got %q", want, markdown)
		}
	}

	customer := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "customer-redacted", "--json")
	customerSummary := requireObject(t, customer, "summary")
	if customerSummary["share_profile"] != "customer-redacted" {
		t.Fatalf("unexpected customer share profile: %v", customerSummary["share_profile"])
	}
	customerProof := requireObject(t, customerSummary, "proof")
	if customerProof["chain_path"] != "redacted://proof-chain.json" {
		t.Fatalf("expected redacted proof chain path, got %v", customerProof["chain_path"])
	}
	customerBOM := requireObject(t, customerSummary, "agent_action_bom")
	customerItems := requireArrayFromObject(t, customerBOM, "items")
	firstCustomer := requireObjectItem(t, customerItems[0])
	for key, prefix := range map[string]string{"repo": "repo-", "location": "loc-", "owner": "owner-"} {
		value, _ := firstCustomer[key].(string)
		if !strings.HasPrefix(value, prefix) {
			t.Fatalf("expected %s redaction prefix %q, got %q", key, prefix, value)
		}
	}

	evidencePayload := loadAcceptanceJSONFile(t, evidencePath)
	evidenceRegistry := requireArray(t, evidencePayload, "action_surface_registry")
	evidenceBOM := requireObject(t, evidencePayload, "agent_action_bom")
	evidenceItems := requireArrayFromObject(t, evidenceBOM, "items")
	if len(evidenceRegistry) == 0 || len(evidenceItems) == 0 {
		t.Fatalf("expected evidence registry and BOM items, got registry=%d items=%d", len(evidenceRegistry), len(evidenceItems))
	}
	firstRegistry := requireObjectItem(t, evidenceRegistry[0])
	firstEvidenceItem := requireObjectItem(t, evidenceItems[0])
	if firstRegistry["remediation"] != firstEvidenceItem["remediation"] {
		t.Fatalf("expected registry and BOM remediation to agree, registry=%v bom=%v", firstRegistry["remediation"], firstEvidenceItem["remediation"])
	}
}

func loadAcceptanceJSONFile(t *testing.T, path string) map[string]any {
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
