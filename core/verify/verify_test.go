package verify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/signing"
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

func TestChainMatchesProofVerifierOnHeadHashMismatch(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	chain.HeadHash = "sha256:tampered"
	writeChain(t, path, chain)

	got, err := Chain(path)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var parsed proof.Chain
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	want, err := proof.VerifyChain(&parsed)
	if err != nil {
		t.Fatalf("proof verify chain: %v", err)
	}

	expected := Result{
		Intact:             want.Intact,
		Count:              want.Count,
		HeadHash:           want.HeadHash,
		BreakPoint:         want.BreakPoint,
		BreakIndex:         want.BreakIndex,
		Reason:             "chain_integrity_failure",
		VerificationMode:   verificationModeChainOnly,
		AuthenticityStatus: authenticityStatusUnavailable,
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected verify result\nwant=%+v\ngot=%+v", expected, got)
	}
}

func TestChainWithPublicKeyAcceptsSignedChain(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	key, err := proof.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if _, err := proof.SignChain(chain, key); err != nil {
		t.Fatalf("sign chain: %v", err)
	}
	writeChain(t, path, chain)

	result, err := ChainWithPublicKey(path, proof.PublicKey{Public: key.Public, KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("verify signed chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("expected intact signed chain result, got %+v", result)
	}
	if result.Reason != "ok" {
		t.Fatalf("expected reason ok, got %s", result.Reason)
	}
	if result.VerificationMode != verificationModeSignature {
		t.Fatalf("expected signature verification mode, got %s", result.VerificationMode)
	}
	if result.AuthenticityStatus != authenticityStatusVerified {
		t.Fatalf("expected verified authenticity status, got %s", result.AuthenticityStatus)
	}
}

func TestChainWithPublicKeyAcceptsAttestedChain(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	writeChain(t, path, chain)

	key, err := proof.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	chainPayload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	attestation := chainAttestation{
		Version:     "v1",
		ChainSHA:    digestBytes(chainPayload),
		ChainBytes:  int64(len(chainPayload)),
		RecordCount: len(chain.Records),
		HeadHash:    chain.HeadHash,
	}
	digest, err := digestAttestationPayload(chainAttestationPayload{
		Version:     attestation.Version,
		ChainSHA:    attestation.ChainSHA,
		ChainBytes:  attestation.ChainBytes,
		RecordCount: attestation.RecordCount,
		HeadHash:    attestation.HeadHash,
	})
	if err != nil {
		t.Fatalf("digest attestation payload: %v", err)
	}
	signature, err := signing.SignDigest(digest, key)
	if err != nil {
		t.Fatalf("sign attestation payload: %v", err)
	}
	attestation.Signature = signature
	encoded, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(attestationPath(path), encoded, 0o600); err != nil {
		t.Fatalf("write attestation: %v", err)
	}

	result, err := ChainWithPublicKey(path, proof.PublicKey{Public: key.Public, KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("verify attested chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("expected intact attested chain result, got %+v", result)
	}
	if result.Reason != "ok" {
		t.Fatalf("expected reason ok, got %s", result.Reason)
	}
	if result.VerificationMode != verificationModeAttestation {
		t.Fatalf("expected attestation verification mode, got %s", result.VerificationMode)
	}
	if result.AuthenticityStatus != authenticityStatusVerified {
		t.Fatalf("expected verified authenticity status, got %s", result.AuthenticityStatus)
	}
}

func TestChainWithPublicKeyRejectsAttestedNonJSONPayload(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "chain.json")
	if err := os.WriteFile(path, []byte("not-json-at-all\n"), 0o600); err != nil {
		t.Fatalf("write chain payload: %v", err)
	}
	key, err := proof.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	writeAttestation(t, path, key, 999, "sha256:fakehead")

	if _, err := ChainWithPublicKey(path, proof.PublicKey{Public: key.Public, KeyID: key.KeyID}); err == nil {
		t.Fatal("expected parse failure for attested non-JSON chain")
	} else if ErrorCodeFor(err) != ErrorCodeParseChain {
		t.Fatalf("unexpected error code: %s", ErrorCodeFor(err))
	}
}

func TestChainWithPublicKeyRejectsAttestedStructuralCorruption(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	chain.Records[1].Integrity.PreviousRecordHash = "sha256:tampered"
	writeChain(t, path, chain)

	key, err := proof.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	writeAttestation(t, path, key, len(chain.Records), chain.HeadHash)

	result, err := ChainWithPublicKey(path, proof.PublicKey{Public: key.Public, KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("verify attested structurally invalid chain: %v", err)
	}
	if result.Intact {
		t.Fatalf("expected structural integrity failure, got %+v", result)
	}
	if result.Reason != "chain_integrity_failure" {
		t.Fatalf("unexpected reason: %s", result.Reason)
	}
	if result.VerificationMode != verificationModeAttestation {
		t.Fatalf("expected attestation verification mode, got %s", result.VerificationMode)
	}
	if result.AuthenticityStatus != authenticityStatusVerified {
		t.Fatalf("expected verified authenticity status, got %s", result.AuthenticityStatus)
	}
}

func TestChainWithPublicKeyRejectsInvalidSignedChain(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	key, err := proof.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if _, err := proof.SignChain(chain, key); err != nil {
		t.Fatalf("sign chain: %v", err)
	}
	chain.Records[1].Event["assessment_type"] = "tampered"
	rehashChain(t, chain)
	writeChain(t, path, chain)

	if _, err := ChainWithPublicKey(path, proof.PublicKey{Public: key.Public, KeyID: key.KeyID}); err == nil {
		t.Fatalf("expected signature verification failure")
	} else if ErrorCodeFor(err) != ErrorCodeVerifyChainFailure {
		t.Fatalf("unexpected error code: %s", ErrorCodeFor(err))
	}
}

func TestChainWithPublicKeyFallsBackWhenSignatureUnavailable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "chain.json")
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding", map[string]any{"finding_type": "policy_violation"})
	appendRecord(t, chain, "risk_assessment", map[string]any{"assessment_type": "finding_risk"})
	writeChain(t, path, chain)

	key, err := proof.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	result, err := ChainWithPublicKey(path, proof.PublicKey{Public: key.Public, KeyID: key.KeyID})
	if err != nil {
		t.Fatalf("verify unsigned chain: %v", err)
	}
	if !result.Intact {
		t.Fatalf("expected unsigned chain fallback result, got %+v", result)
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

func rehashChain(t *testing.T, chain *proof.Chain) {
	t.Helper()

	prev := ""
	for i := range chain.Records {
		chain.Records[i].Integrity.PreviousRecordHash = prev
		hash, err := proof.ComputeRecordHash(&chain.Records[i])
		if err != nil {
			t.Fatalf("compute record hash: %v", err)
		}
		chain.Records[i].Integrity.RecordHash = hash
		prev = hash
	}
	chain.HeadHash = prev
	chain.RecordCount = len(chain.Records)
}

func writeAttestation(t *testing.T, path string, key proof.SigningKey, recordCount int, headHash string) {
	t.Helper()

	chainPayload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	attestation := chainAttestation{
		Version:     "v1",
		ChainSHA:    digestBytes(chainPayload),
		ChainBytes:  int64(len(chainPayload)),
		RecordCount: recordCount,
		HeadHash:    headHash,
	}
	digest, err := digestAttestationPayload(chainAttestationPayload{
		Version:     attestation.Version,
		ChainSHA:    attestation.ChainSHA,
		ChainBytes:  attestation.ChainBytes,
		RecordCount: attestation.RecordCount,
		HeadHash:    attestation.HeadHash,
	})
	if err != nil {
		t.Fatalf("digest attestation payload: %v", err)
	}
	signature, err := signing.SignDigest(digest, key)
	if err != nil {
		t.Fatalf("sign attestation payload: %v", err)
	}
	attestation.Signature = signature
	encoded, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		t.Fatalf("marshal attestation: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(attestationPath(path), encoded, 0o600); err != nil {
		t.Fatalf("write attestation: %v", err)
	}
}
