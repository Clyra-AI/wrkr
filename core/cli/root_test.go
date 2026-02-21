package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRunJSON(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), `"status":"ok"`) {
		t.Fatalf("expected json status output, got %q", out.String())
	}
}

func TestRunHelpReturnsExit0(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage of wrkr:") {
		t.Fatalf("expected help usage output, got %q", errOut.String())
	}
}

func TestRunInvalidFlagReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--nope"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
}

func TestRunInvalidFlagWithJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--json", "--nope"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on parse error, got %q", out.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestRunInvalidFlagBeforeJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--nope", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on parse error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestRunUnknownCommandReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"unknown-cmd"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for unknown command, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "unsupported command") {
		t.Fatalf("expected unsupported command error, got %q", errOut.String())
	}
}

func TestRunUnknownCommandWithJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"unknown-cmd", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for unknown command, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestRunQuietExplainWithoutJSONReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--quiet", "--explain"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for invalid flag combination, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "--quiet and --explain") {
		t.Fatalf("expected quiet/explain validation message, got %q", errOut.String())
	}
}

func TestInitNonInteractiveWritesConfig(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d with stderr %q", code, errOut.String())
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
}

func TestScanMutuallyExclusiveTargetsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/backend", "--org", "acme", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
}

func TestScanUsesConfiguredDefaultTarget(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	statePath := filepath.Join(tmp, "last-scan.json")

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	initCode := Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &initOut, &initErr)
	if initCode != 0 {
		t.Fatalf("init failed: exit %d stderr %s", initCode, initErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--config", configPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: exit %d stderr %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	target := payload["target"].(map[string]any)
	if target["mode"] != "repo" || target["value"] != "acme/backend" {
		t.Fatalf("unexpected target: %v", target)
	}
}

func TestScanDiffOnlyReturnsDelta(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir pathA: %v", err)
	}

	var out1 bytes.Buffer
	var err1 bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out1, &err1)
	if code != 0 {
		t.Fatalf("first scan failed: %d %s", code, err1.String())
	}
	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta: %v", err)
	}

	var out2 bytes.Buffer
	var err2 bytes.Buffer
	code = Run([]string{"scan", "--path", reposPath, "--state", statePath, "--diff", "--json"}, &out2, &err2)
	if code != 0 {
		t.Fatalf("diff scan failed: %d %s", code, err2.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out2.Bytes(), &payload); err != nil {
		t.Fatalf("parse diff output: %v", err)
	}
	diffPayload, ok := payload["diff"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff object, got %v", payload)
	}
	added, _ := diffPayload["added"].([]any)
	if len(added) == 0 {
		t.Fatalf("expected added findings, got none payload=%v", payload)
	}
	foundNewRepo := false
	for _, item := range added {
		finding, castOK := item.(map[string]any)
		if !castOK {
			continue
		}
		if finding["tool_type"] == "source_repo" && finding["repo"] == "beta" {
			foundNewRepo = true
			break
		}
	}
	if !foundNewRepo {
		t.Fatalf("expected diff to include beta source discovery, payload=%v", payload)
	}
	removed, _ := diffPayload["removed"].([]any)
	if len(removed) != 0 {
		t.Fatalf("expected no removed findings, got %d", len(removed))
	}
}

func TestScanEnrichRequiresNetworkSource(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/backend", "--enrich", "--json"}, &out, &errOut)
	if code != 7 {
		t.Fatalf("expected exit 7, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", payload)
	}
	if errorPayload["code"] != "dependency_missing" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
}

func TestScanIncludesInventoryProfileAndScore(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--profile", "standard", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	for _, key := range []string{"inventory", "repo_exposure_summaries", "profile", "posture_score", "ranked_findings"} {
		if _, present := payload[key]; !present {
			t.Fatalf("missing %s in payload: %v", key, payload)
		}
	}
}

func TestReportExportScoreCommands(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--top", "5", "--state", statePath, "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}
	var reportPayload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if _, ok := reportPayload["top_findings"].([]any); !ok {
		t.Fatalf("expected top_findings array in report payload: %v", reportPayload)
	}

	var exportOut bytes.Buffer
	var exportErr bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--state", statePath, "--json"}, &exportOut, &exportErr); code != 0 {
		t.Fatalf("export failed: %d %s", code, exportErr.String())
	}
	var exportPayload map[string]any
	if err := json.Unmarshal(exportOut.Bytes(), &exportPayload); err != nil {
		t.Fatalf("parse export payload: %v", err)
	}
	if _, present := exportPayload["tools"]; !present {
		t.Fatalf("expected tools in export payload: %v", exportPayload)
	}

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score failed: %d %s", code, scoreErr.String())
	}
	var scorePayload map[string]any
	if err := json.Unmarshal(scoreOut.Bytes(), &scorePayload); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	if _, present := scorePayload["grade"]; !present {
		t.Fatalf("expected grade in score payload: %v", scorePayload)
	}
}

func TestScoreQuietAndExplainContracts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--quiet"}, &out, &errOut); code != 0 {
		t.Fatalf("score --quiet failed: %d %s", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for score --quiet, got %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"score", "--state", statePath, "--explain"}, &out, &errOut); code != 0 {
		t.Fatalf("score --explain failed: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "wrkr score") {
		t.Fatalf("expected explain output, got %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	code := Run([]string{"score", "--state", statePath, "--quiet", "--explain"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for score --quiet --explain, got %d", code)
	}
}

func TestReportUsesRankedFindingsWhenTopExceedsStoredTopN(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")

	snapshot := map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-02-20T12:00:00Z",
			"top_findings": []any{
				map[string]any{
					"canonical_key": "k1",
					"risk_score":    9.1,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-001"},
				},
			},
			"ranked_findings": []any{
				map[string]any{
					"canonical_key": "k1",
					"risk_score":    9.1,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-001"},
				},
				map[string]any{
					"canonical_key": "k2",
					"risk_score":    8.0,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-002"},
				},
				map[string]any{
					"canonical_key": "k3",
					"risk_score":    7.0,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-003"},
				},
			},
		},
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(statePath, append(payload, '\n'), 0o600); err != nil {
		t.Fatalf("write state snapshot: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"report", "--top", "3", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report failed: %d %s", code, errOut.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	topFindings, ok := reportPayload["top_findings"].([]any)
	if !ok {
		t.Fatalf("expected top_findings array, got %T", reportPayload["top_findings"])
	}
	if len(topFindings) != 3 {
		t.Fatalf("expected 3 top findings from ranked set, got %d", len(topFindings))
	}
}

func TestIdentityAndLifecycleCommands(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryPayload, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	tools, ok := inventoryPayload["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected inventory tools, got %v", inventoryPayload["tools"])
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected first tool shape: %T", tools[0])
	}
	agentID, ok := firstTool["agent_id"].(string)
	if !ok || agentID == "" {
		t.Fatalf("expected agent_id in first inventory tool: %v", firstTool)
	}
	org, _ := firstTool["org"].(string)

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	var showOut bytes.Buffer
	var showErr bytes.Buffer
	if code := Run([]string{"identity", "show", agentID, "--state", statePath, "--json"}, &showOut, &showErr); code != 0 {
		t.Fatalf("identity show failed: %d %s", code, showErr.String())
	}
	var showPayload map[string]any
	if err := json.Unmarshal(showOut.Bytes(), &showPayload); err != nil {
		t.Fatalf("parse identity show payload: %v", err)
	}
	identityPayload, ok := showPayload["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity object, got %T", showPayload["identity"])
	}
	status, _ := identityPayload["status"].(string)
	if status != "approved" && status != "active" {
		t.Fatalf("expected approved/active status after approval, got %q", status)
	}

	var lifecycleOut bytes.Buffer
	var lifecycleErr bytes.Buffer
	if code := Run([]string{"lifecycle", "--org", org, "--state", statePath, "--json"}, &lifecycleOut, &lifecycleErr); code != 0 {
		t.Fatalf("lifecycle failed: %d %s", code, lifecycleErr.String())
	}
	var lifecyclePayload map[string]any
	if err := json.Unmarshal(lifecycleOut.Bytes(), &lifecyclePayload); err != nil {
		t.Fatalf("parse lifecycle payload: %v", err)
	}
	if _, ok := lifecyclePayload["identities"].([]any); !ok {
		t.Fatalf("expected identities array in lifecycle payload: %v", lifecyclePayload)
	}
}

func TestVerifyAndEvidenceCommands(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed: %d %s", code, verifyErr.String())
	}
	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyOut.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("parse verify payload: %v", err)
	}
	chainPayload, ok := verifyPayload["chain"].(map[string]any)
	if !ok {
		t.Fatalf("expected chain payload, got %T", verifyPayload["chain"])
	}
	if intact, _ := chainPayload["intact"].(bool); !intact {
		t.Fatalf("expected intact chain payload: %v", chainPayload)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	var evidenceOut bytes.Buffer
	var evidenceErr bytes.Buffer
	if code := Run([]string{"evidence", "--frameworks", "soc2,eu-ai-act", "--state", statePath, "--output", outputDir, "--json"}, &evidenceOut, &evidenceErr); code != 0 {
		t.Fatalf("evidence failed: %d %s", code, evidenceErr.String())
	}
	var evidencePayload map[string]any
	if err := json.Unmarshal(evidenceOut.Bytes(), &evidencePayload); err != nil {
		t.Fatalf("parse evidence payload: %v", err)
	}
	if evidencePayload["status"] != "ok" {
		t.Fatalf("unexpected evidence status: %v", evidencePayload["status"])
	}
	if _, err := os.Stat(filepath.Join(outputDir, "manifest.json")); err != nil {
		t.Fatalf("expected manifest.json in evidence output: %v", err)
	}
}

func TestVerifyTamperedChainReturnsExit2(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")
	payload, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain map[string]any
	if err := json.Unmarshal(payload, &chain); err != nil {
		t.Fatalf("parse chain json: %v", err)
	}
	records, ok := chain["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected records in proof chain: %v", chain)
	}
	first, ok := records[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected record shape: %T", records[0])
	}
	integrity, ok := first["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("missing integrity block in first record: %v", first)
	}
	integrity["record_hash"] = "sha256:tampered"
	mutated, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered chain: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(chainPath, mutated, 0o600); err != nil {
		t.Fatalf("write tampered chain: %v", err)
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr)
	if code != 2 {
		t.Fatalf("expected exit 2 for tampered chain, got %d", code)
	}
	var errorPayload map[string]any
	if err := json.Unmarshal(verifyErr.Bytes(), &errorPayload); err != nil {
		t.Fatalf("parse verify error payload: %v", err)
	}
	errObject, ok := errorPayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in verify payload: %v", errorPayload)
	}
	if errObject["code"] != "verification_failure" {
		t.Fatalf("unexpected verification error code: %v", errObject["code"])
	}
}

func TestReportPDFCommandWritesDeterministicPDFEnvelope(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	pdfPath := filepath.Join(tmp, "report.pdf")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--pdf", "--pdf-path", pdfPath, "--state", statePath, "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report --pdf failed: %d %s", code, reportErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected report payload: %v", payload)
	}
	if payload["pdf_path"] != pdfPath {
		t.Fatalf("unexpected pdf_path value: %v", payload["pdf_path"])
	}

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read generated pdf: %v", err)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4\n")) {
		t.Fatalf("expected PDF header, got %q", string(pdfBytes[:minInt(len(pdfBytes), 16)]))
	}
}

func TestReportMarkdownPublicShareContract(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdPath := filepath.Join(tmp, "report-public.md")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--state", statePath, "--md", "--md-path", mdPath, "--template", "public", "--share-profile", "public", "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report public markdown failed: %d %s", code, reportErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if payload["md_path"] != mdPath {
		t.Fatalf("unexpected md_path: %v", payload["md_path"])
	}
	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("expected markdown output file: %v", err)
	}
	findings, ok := payload["top_findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected top_findings array: %v", payload)
	}
	firstFinding, _ := findings[0].(map[string]any)
	findingPayload, _ := firstFinding["finding"].(map[string]any)
	location, _ := findingPayload["location"].(string)
	if strings.Contains(location, "/") {
		t.Fatalf("expected public share location redaction, got %q", location)
	}
}

func TestReportRejectsInvalidTemplateAndShareProfile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--state", statePath, "--template", "unknown", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for invalid template, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = Run([]string{"report", "--state", statePath, "--share-profile", "external", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for invalid share profile, got %d", code)
	}
}

func TestManifestGenerateCreatesUnderReviewBaseline(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	manifestPath := filepath.Join(tmp, "generated-manifest.yaml")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryPayload, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	tools, ok := inventoryPayload["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected non-empty inventory tools")
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected tool payload: %T", tools[0])
	}
	agentID, _ := firstTool["agent_id"].(string)
	if agentID == "" {
		t.Fatalf("missing agent_id in inventory tool: %v", firstTool)
	}

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	var manifestOut bytes.Buffer
	var manifestErr bytes.Buffer
	if code := Run([]string{"manifest", "generate", "--state", statePath, "--output", manifestPath, "--json"}, &manifestOut, &manifestErr); code != 0 {
		t.Fatalf("manifest generate failed: %d %s", code, manifestErr.String())
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read generated manifest: %v", err)
	}
	var generated struct {
		Identities []struct {
			Status        string `yaml:"status"`
			ApprovalState string `yaml:"approval_status"`
		} `yaml:"identities"`
	}
	if err := yaml.Unmarshal(manifestBytes, &generated); err != nil {
		t.Fatalf("parse generated manifest yaml: %v", err)
	}
	if len(generated.Identities) == 0 {
		t.Fatal("expected manifest identities")
	}
	for _, record := range generated.Identities {
		if record.Status != "under_review" {
			t.Fatalf("expected under_review status, got %q", record.Status)
		}
		if record.ApprovalState != "missing" {
			t.Fatalf("expected missing approval status, got %q", record.ApprovalState)
		}
	}
}

func TestEvidenceCommandRejectsUnsafeOutputPathWithExit8(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	outputDir := filepath.Join(tmp, "unsafe-output")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "not-managed.txt"), []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write non-managed file: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", outputDir, "--json"}, &out, &errOut)
	if code != 8 {
		t.Fatalf("expected exit 8, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on unsafe path error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse evidence error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload: %v", payload)
	}
	if errObj["code"] != "unsafe_operation_blocked" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(8) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not find repo root")
		}
		wd = next
	}
}
