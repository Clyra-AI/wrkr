package proofemit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/signing"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const chainAttestationVersion = "v1"

type chainAttestation struct {
	Version     string            `json:"version"`
	ChainSHA    string            `json:"chain_sha256"`
	ChainBytes  int64             `json:"chain_bytes"`
	RecordCount int               `json:"record_count"`
	HeadHash    string            `json:"head_hash"`
	Signature   signing.Signature `json:"signature"`
}

type chainAttestationPayload struct {
	Version     string `json:"version"`
	ChainSHA    string `json:"chain_sha256"`
	ChainBytes  int64  `json:"chain_bytes"`
	RecordCount int    `json:"record_count"`
	HeadHash    string `json:"head_hash"`
}

func chainAttestationPath(path string) string {
	dir := filepath.Dir(strings.TrimSpace(path))
	if dir == "" || dir == "." {
		dir = ".wrkr"
	}
	return filepath.Join(dir, "proof-chain.attestation.json")
}

func saveChainAttestation(chainPath string, recordCount int, headHash string, key signing.SigningKey) error {
	payload, err := os.ReadFile(chainPath) // #nosec G304 -- attestation is bound to the explicit local proof chain path.
	if err != nil {
		return fmt.Errorf("read proof chain for attestation: %w", err)
	}

	attestation := chainAttestation{
		Version:     chainAttestationVersion,
		ChainSHA:    digestBytes(payload),
		ChainBytes:  int64(len(payload)),
		RecordCount: recordCount,
		HeadHash:    strings.TrimSpace(headHash),
	}
	digest, err := digestAttestationPayload(chainAttestationPayload{
		Version:     attestation.Version,
		ChainSHA:    attestation.ChainSHA,
		ChainBytes:  attestation.ChainBytes,
		RecordCount: attestation.RecordCount,
		HeadHash:    attestation.HeadHash,
	})
	if err != nil {
		return fmt.Errorf("digest proof chain attestation: %w", err)
	}
	signature, err := signing.SignDigest(digest, key)
	if err != nil {
		return fmt.Errorf("sign proof chain attestation: %w", err)
	}
	attestation.Signature = signature

	encoded, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal proof chain attestation: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := atomicwrite.WriteFile(chainAttestationPath(chainPath), encoded, 0o600); err != nil {
		return fmt.Errorf("write proof chain attestation: %w", err)
	}
	return nil
}

func digestAttestationPayload(payload chainAttestationPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonical, err := canon.Canonicalize(raw, canon.DomainJSON)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func digestBytes(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}
