package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProofChainMayContainControlEvidenceRecognizesGovernanceEventNames(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "proof-chain.json")
	payload := []byte(`{"records":[{"event_type":"rotation_evidence_attached"},{"event_type":"proof_artifact_generated"},{"event_type":"review_cadence_set"}]}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write proof chain: %v", err)
	}

	if !proofChainMayContainControlEvidence(path) {
		t.Fatal("expected governance event names to trigger control evidence loading")
	}
}
