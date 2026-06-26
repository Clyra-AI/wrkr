package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportInventoryAnonymize(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--anonymize", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("export failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse export payload: %v", err)
	}
	org, _ := payload["org"].(string)
	if org == "" || !strings.HasPrefix(org, "org-") {
		t.Fatalf("expected anonymized org prefix org-*, got %q", org)
	}
}

func TestExportAppendixJSONAndCSV(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	csvDir := filepath.Join(tmp, "appendix-csv")
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"export", "--format", "appendix", "--csv-dir", csvDir, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("appendix export failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse appendix payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
	appendix, ok := payload["appendix"].(map[string]any)
	if !ok {
		t.Fatalf("expected appendix object, got %T", payload["appendix"])
	}
	for _, key := range []string{"inventory_rows", "privilege_rows", "approval_gap_rows", "regulatory_rows"} {
		if _, exists := appendix[key]; !exists {
			t.Fatalf("appendix missing key %s: %v", key, appendix)
		}
	}
	csvFiles, ok := payload["csv_files"].(map[string]any)
	if !ok {
		t.Fatalf("expected csv_files map, got %T", payload["csv_files"])
	}
	for _, key := range []string{"inventory", "privilege_map", "approval_gap", "regulatory_matrix"} {
		value, exists := csvFiles[key]
		if !exists {
			t.Fatalf("missing csv key %s in %v", key, csvFiles)
		}
		if _, ok := value.(string); !ok {
			t.Fatalf("expected csv path string for %s, got %T", key, value)
		}
	}
}

func TestExportInventoryRejectsCSVDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--csv-dir", filepath.Join(tmp, "csv"), "--state", statePath, "--json"}, &out, &errOut); code != 6 {
		t.Fatalf("expected exit 6, got %d (%s)", code, errOut.String())
	}
}

func TestExportTicketsDryRunDoesNotUseNetwork(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	writeJSONFile(t, statePath, map[string]any{
		"version": "v1",
		"control_backlog": map[string]any{
			"control_backlog_version": "1",
			"summary":                 map[string]any{"total_items": 1},
			"items": []any{map[string]any{
				"id":                   "cb-1",
				"repo":                 "payments",
				"path":                 ".github/workflows/release.yml",
				"control_surface_type": "ci_automation",
				"control_path_type":    "ci_automation",
				"capability":           "repo_write",
				"owner":                "@acme/payments",
				"evidence_source":      "risk_action_path",
				"evidence_basis":       []any{"workflow_permission"},
				"approval_status":      "unapproved",
				"security_visibility":  "unknown_to_security",
				"signal_class":         "unique_wrkr_signal",
				"recommended_action":   "approve",
				"confidence":           "medium",
				"sla":                  "7d",
				"closure_criteria":     "Record owner-approved evidence and rescan.",
			}},
		},
	})
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"export", "tickets", "--top", "10", "--format", "jira", "--dry-run", "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("export tickets failed: %d %s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse tickets payload: %v", err)
	}
	if payload["ticket_export_version"] != "1" || payload["format"] != "jira" || payload["dry_run"] != true {
		t.Fatalf("unexpected ticket export payload: %v", payload)
	}
	tickets, ok := payload["tickets"].([]any)
	if !ok || len(tickets) != 1 {
		t.Fatalf("expected one ticket, got %v", payload["tickets"])
	}
	first, _ := tickets[0].(map[string]any)
	for _, key := range []string{"owner", "evidence", "recommended_action", "sla", "closure_criteria", "proof_requirements"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("ticket missing %s: %v", key, first)
		}
	}
}

func TestExportTicketsUnsupportedFormatExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"export", "tickets", "--format", "email", "--dry-run", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit 6, got %d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObj, _ := payload["error"].(map[string]any)
	if errObj["code"] != "invalid_input" {
		t.Fatalf("expected invalid_input, got %v", payload)
	}
}

func TestExportDeclarationsGeneratesReviewDispositionSnippet(t *testing.T) {
	t.Parallel()

	statePath, selection := seedDeclarationExportSelection(t)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"export", "declarations",
		"--state", statePath,
		"--resolution-key", selection["resolution_key"],
		"--action", "accept_risk_with_expiry",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("export declarations failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse declaration export payload: %v", err)
	}
	snippet, ok := payload["snippet"].(map[string]any)
	if !ok {
		t.Fatalf("expected snippet object, got %T", payload["snippet"])
	}
	if snippet["correlation_kind"] != "resolution_key" {
		t.Fatalf("expected resolution_key correlation, got %v", snippet)
	}
	content, _ := snippet["content"].(string)
	if !strings.Contains(content, "state: accepted_risk") || !strings.Contains(content, selection["resolution_key"]) {
		t.Fatalf("expected accepted_risk declaration content, got %q", content)
	}
}

func TestExportDeclarationsShareableOwnerSnippetWarns(t *testing.T) {
	t.Parallel()

	statePath, selection := seedOwnerDeclarationExportSelection(t)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"export", "declarations",
		"--state", statePath,
		"--resolution-key", selection["resolution_key"],
		"--action", "declare_repo_owner",
		"--share-profile", "customer-redacted",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("shareable export declarations failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse shareable declaration export payload: %v", err)
	}
	snippet := payload["snippet"].(map[string]any)
	if snippet["directly_applicable"] != false {
		t.Fatalf("expected shareable owner declaration to require internal artifacts, got %v", snippet)
	}
	warnings, _ := snippet["warnings"].([]any)
	if len(warnings) == 0 {
		t.Fatalf("expected shareable owner declaration warning, got %v", snippet)
	}
}

func TestExportDeclarationsRejectsUnsafePatchPath(t *testing.T) {
	t.Parallel()

	statePath, selection := seedDeclarationExportSelection(t)
	tmp := t.TempDir()
	patchPath := filepath.Join(tmp, "existing-dir")
	if err := os.MkdirAll(patchPath, 0o750); err != nil {
		t.Fatalf("mkdir patch path: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"export", "declarations",
		"--state", statePath,
		"--resolution-key", selection["resolution_key"],
		"--action", "accept_risk_with_expiry",
		"--patch-path", patchPath,
		"--json",
	}, &out, &errOut)
	if code != exitUnsafeBlocked {
		t.Fatalf("expected unsafe patch path to fail with exit %d, got %d stdout=%q stderr=%q", exitUnsafeBlocked, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "unsafe_operation_blocked", exitUnsafeBlocked)
}

func seedDeclarationExportSelection(t *testing.T) (string, map[string]string) {
	t.Helper()

	statePath, reportPayload := seedDeclarationExportStateAndReport(t)
	bom, ok := reportPayload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom, got %T", reportPayload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected BOM items, got %v", bom["items"])
	}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		actions, _ := item["closure_actions"].([]any)
		if !hasNamedClosureAction(actions, "accept_risk_with_expiry") {
			continue
		}
		resolutionKey, _ := item["resolution_key"].(string)
		pathID, _ := item["path_id"].(string)
		if resolutionKey != "" && pathID != "" {
			return statePath, map[string]string{"resolution_key": resolutionKey, "path_id": pathID}
		}
	}
	t.Fatalf("expected a BOM item with resolution_key and accept_risk_with_expiry action, got %v", items)
	return "", nil
}

func seedOwnerDeclarationExportSelection(t *testing.T) (string, map[string]string) {
	t.Helper()

	statePath, reportPayload := seedDeclarationExportStateAndReport(t)
	bom, ok := reportPayload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom, got %T", reportPayload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected BOM items, got %v", bom["items"])
	}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		actions, _ := item["closure_actions"].([]any)
		if !hasNamedClosureAction(actions, "declare_repo_owner") {
			continue
		}
		resolutionKey, _ := item["resolution_key"].(string)
		if resolutionKey != "" {
			return statePath, map[string]string{"resolution_key": resolutionKey}
		}
	}
	t.Fatalf("expected a BOM item with declare_repo_owner action, got %v", items)
	return "", nil
}

func seedDeclarationExportStateAndReport(t *testing.T) (string, map[string]any) {
	t.Helper()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d (%s)", code, reportErr.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	return statePath, reportPayload
}

func hasNamedClosureAction(actions []any, actionType string) bool {
	for _, raw := range actions {
		item, _ := raw.(map[string]any)
		if item["action_type"] == actionType {
			return true
		}
	}
	return false
}
