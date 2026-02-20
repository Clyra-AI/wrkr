package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
)

func TestChainIntact(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	writeChain(t, path, chain)

	result, err := Chain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("expected intact chain result, got %+v", result)
	}
	if result.Reason != "ok" {
		t.Fatalf("expected reason ok, got %s", result.Reason)
	}
}

func TestChainTamperDetected(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	chain.Records[1].Integrity.PreviousRecordHash = "sha256:tampered"
	writeChain(t, path, chain)

	result, err := Chain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if result.Intact {
		t.Fatalf("expected tamper detection result, got %+v", result)
	}
	if result.Reason != "chain_integrity_failure" {
		t.Fatalf("unexpected reason: %s", result.Reason)
	}
}

func TestChainMixedSourceCompatibility(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecordWithSource(t, chain, "scan_finding", "wrkr", map[string]any{"finding_type": "policy_violation"})
	appendRecordWithSource(t, chain, "risk_assessment", "axym", map[string]any{"assessment_type": "finding_risk"})
	appendRecordWithSource(t, chain, "approval", "gait", map[string]any{"event_type": "approval"})
	writeChain(t, path, chain)

	result, err := Chain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("expected mixed-source chain to be intact, got %+v", result)
	}
}

func appendRecord(t *testing.T, chain *proof.Chain, recordType string, event map[string]any) {
	t.Helper()
	appendRecordWithSource(t, chain, recordType, "wrkr", event)
}

func appendRecordWithSource(t *testing.T, chain *proof.Chain, recordType, sourceProduct string, event map[string]any) {
	t.Helper()
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: sourceProduct,
		Type:          recordType,
		Event:         event,
		Controls:      proof.Controls{PermissionsEnforced: true},
	})
	if err != nil {
		t.Fatalf("new record: %v", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		t.Fatalf("append to chain: %v", err)
	}
}

func writeChain(t *testing.T, path string, chain *proof.Chain) {
	t.Helper()
	payload, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal chain: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write chain: %v", err)
	}
}
