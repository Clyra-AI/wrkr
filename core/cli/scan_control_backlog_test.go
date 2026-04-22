package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/state"
)

func TestScanJSONRetainsLegacyFindingSurfacesWithControlBacklog(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(filepath.Join(repoRoot, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	first := runScanPayload(t, repoRoot, filepath.Join(t.TempDir(), "state-a.json"))
	second := runScanPayload(t, repoRoot, filepath.Join(t.TempDir(), "state-b.json"))

	for _, key := range []string{"findings", "top_findings", "inventory", "control_backlog", "scan_quality"} {
		if _, ok := first[key]; !ok {
			t.Fatalf("expected key %s in scan payload: %v", key, first)
		}
	}
	backlog, ok := first["control_backlog"].(map[string]any)
	if !ok {
		t.Fatalf("expected control_backlog object, got %T", first["control_backlog"])
	}
	if backlog["control_backlog_version"] != "1" {
		t.Fatalf("unexpected backlog version: %v", backlog["control_backlog_version"])
	}
	items, ok := backlog["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected backlog items, got %v", backlog["items"])
	}
	firstItems := normalizeBacklogItemsForDeterminism(first)
	secondItems := normalizeBacklogItemsForDeterminism(second)
	if string(firstItems) != string(secondItems) {
		t.Fatalf("expected deterministic backlog items\nfirst=%s\nsecond=%s", firstItems, secondItems)
	}
}

func TestScanSavesControlBacklogAndQualityInState(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(filepath.Join(repoRoot, "AGENTS.md"), []byte("agent instructions\n"), 0o600); err != nil {
		if mkErr := os.MkdirAll(repoRoot, 0o755); mkErr != nil {
			t.Fatalf("mkdir repo: %v", mkErr)
		}
		if writeErr := os.WriteFile(filepath.Join(repoRoot, "AGENTS.md"), []byte("agent instructions\n"), 0o600); writeErr != nil {
			t.Fatalf("write AGENTS.md: %v", writeErr)
		}
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	_ = runScanPayload(t, repoRoot, statePath)
	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if snapshot.ScanMode != "governance" {
		t.Fatalf("expected default governance scan mode, got %q", snapshot.ScanMode)
	}
	if snapshot.ControlBacklog == nil || snapshot.ControlBacklog.ControlBacklogVersion != "1" {
		t.Fatalf("expected saved control backlog, got %+v", snapshot.ControlBacklog)
	}
	if snapshot.ScanQuality == nil || snapshot.ScanQuality.ScanQualityVersion != "1" {
		t.Fatalf("expected saved scan quality, got %+v", snapshot.ScanQuality)
	}
}

func TestInvalidScanModeJSONErrorEnvelope(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--mode", "wide", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestScanModeGovernanceSuppressesGeneratedPathNoiseAndDeepKeepsDebugEvidence(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(filepath.Join(repoRoot, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatalf("mkdir generated dependency path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "package.json"), []byte(`{"dependencies":{}}`), 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "node_modules", "pkg", "package.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write generated package.json: %v", err)
	}

	governance := runScanPayloadWithArgs(t, []string{"scan", "--path", repoRoot, "--state", filepath.Join(t.TempDir(), "state-governance.json"), "--json"})
	if payloadContainsPath(governance["findings"], "node_modules/pkg/package.json") {
		t.Fatalf("governance findings should suppress generated package parse evidence: %v", governance["findings"])
	}
	if payloadContainsPath(governance["control_backlog"], "node_modules/pkg/package.json") {
		t.Fatalf("governance backlog should suppress generated package parse evidence: %v", governance["control_backlog"])
	}
	if !payloadContainsPath(governance["scan_quality"], "node_modules") {
		t.Fatalf("governance scan_quality should report generated/package suppression: %v", governance["scan_quality"])
	}

	deep := runScanPayloadWithArgs(t, []string{"scan", "--path", repoRoot, "--mode", "deep", "--state", filepath.Join(t.TempDir(), "state-deep.json"), "--json"})
	if !payloadContainsPath(deep["findings"], "node_modules/pkg/package.json") {
		t.Fatalf("deep findings should keep generated package parse evidence: %v", deep["findings"])
	}
	if !payloadContainsAction(deep["scan_quality"], "suppress") {
		t.Fatalf("deep scan_quality should mark generated parse issue as suppress: %v", deep["scan_quality"])
	}
}

func TestScanDiffRejectsMismatchedScanModes(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "app")
	if err := os.MkdirAll(repoRoot, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, "AGENTS.md"), []byte("agent instructions\n"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}
	statePath := filepath.Join(t.TempDir(), "state.json")
	_ = runScanPayloadWithArgs(t, []string{"scan", "--path", repoRoot, "--mode", "deep", "--state", statePath, "--json"})

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", repoRoot, "--mode", "governance", "--state", statePath, "--diff", "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on invalid diff mode mismatch, got %q", out.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
	if !bytes.Contains(errOut.Bytes(), []byte("requires matching scan modes")) {
		t.Fatalf("expected scan mode mismatch message, got %s", errOut.String())
	}
}

func runScanPayload(t *testing.T, repoRoot, statePath string) map[string]any {
	t.Helper()

	return runScanPayloadWithArgs(t, []string{"scan", "--path", repoRoot, "--state", statePath, "--json"})
}

func runScanPayloadWithArgs(t *testing.T, args []string) map[string]any {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run(args, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("scan failed: %d stderr=%s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	return payload
}

func normalizeBacklogItemsForDeterminism(payload map[string]any) []byte {
	backlog, _ := payload["control_backlog"].(map[string]any)
	items := backlog["items"]
	encoded, _ := json.Marshal(items)
	return encoded
}

func payloadContainsPath(value any, path string) bool {
	encoded, _ := json.Marshal(value)
	return bytes.Contains(encoded, []byte(path))
}

func payloadContainsAction(value any, action string) bool {
	encoded, _ := json.Marshal(value)
	return bytes.Contains(encoded, []byte(`"recommended_action":"`+action+`"`))
}
