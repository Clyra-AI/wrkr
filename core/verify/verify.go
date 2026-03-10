package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/canon"
	"github.com/Clyra-AI/proof/core/signing"
)

type Result struct {
	Intact             bool   `json:"intact"`
	Count              int    `json:"count"`
	HeadHash           string `json:"head_hash,omitempty"`
	BreakPoint         string `json:"break_point,omitempty"`
	BreakIndex         int    `json:"break_index,omitempty"`
	Reason             string `json:"reason"`
	VerificationMode   string `json:"verification_mode,omitempty"`
	AuthenticityStatus string `json:"authenticity_status,omitempty"`
}

type ErrorCode string

const (
	ErrorCodeUnknown            ErrorCode = "unknown"
	ErrorCodeInvalidInput       ErrorCode = "invalid_input"
	ErrorCodeReadChain          ErrorCode = "read_chain"
	ErrorCodeParseChain         ErrorCode = "parse_chain"
	ErrorCodeVerifyChainFailure ErrorCode = "verify_chain_failure"
)

type ChainError struct {
	Code ErrorCode
	Err  error
}

var (
	errNoChainAttestation = errors.New("chain attestation not present")
	errNoChainSignature   = errors.New("chain signature not present")
)

const (
	verificationModeChainOnly     = "chain_only"
	verificationModeAttestation   = "chain_and_attestation"
	verificationModeSignature     = "chain_and_signature"
	authenticityStatusUnavailable = "unavailable"
	authenticityStatusVerified    = "verified"
)

type authenticityResult struct {
	VerificationMode   string
	AuthenticityStatus string
}

func (e *ChainError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ChainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func classifyError(code ErrorCode, err error) error {
	if err == nil {
		return nil
	}
	return &ChainError{Code: code, Err: err}
}

func ErrorCodeFor(err error) ErrorCode {
	var target *ChainError
	if errors.As(err, &target) {
		return target.Code
	}
	return ErrorCodeUnknown
}

func Chain(path string) (Result, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Result{}, classifyError(ErrorCodeInvalidInput, fmt.Errorf("chain path is required"))
	}
	chain, err := loadChain(trimmed)
	if err != nil {
		return Result{}, err
	}
	result, err := verifyLoadedChain(chain)
	if err != nil {
		return Result{}, err
	}
	return applyAuthenticity(result, authenticityResult{
		VerificationMode:   verificationModeChainOnly,
		AuthenticityStatus: authenticityStatusUnavailable,
	}), nil
}

func ChainWithPublicKey(path string, publicKey proof.PublicKey) (Result, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Result{}, classifyError(ErrorCodeInvalidInput, fmt.Errorf("chain path is required"))
	}
	if auth, err := verifyByAttestation(trimmed, publicKey); err == nil {
		chain, loadErr := loadChain(trimmed)
		if loadErr != nil {
			return Result{}, loadErr
		}
		verified, verifyErr := verifyLoadedChain(chain)
		if verifyErr != nil {
			return Result{}, verifyErr
		}
		return applyAuthenticity(verified, auth), nil
	} else if !errors.Is(err, errNoChainAttestation) {
		chain, loadErr := loadChain(trimmed)
		if loadErr != nil {
			return Result{}, loadErr
		}
		if auth, sigErr := verifyBySignature(chain, publicKey); sigErr == nil {
			verified, verifyErr := verifyLoadedChain(chain)
			if verifyErr != nil {
				return Result{}, verifyErr
			}
			return applyAuthenticity(verified, auth), nil
		} else if !errors.Is(sigErr, errNoChainSignature) {
			return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain signature: %w", sigErr))
		}
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain attestation: %w", err))
	}
	chain, err := loadChain(trimmed)
	if err != nil {
		return Result{}, err
	}
	if auth, err := verifyBySignature(chain, publicKey); err == nil {
		verified, verifyErr := verifyLoadedChain(chain)
		if verifyErr != nil {
			return Result{}, verifyErr
		}
		return applyAuthenticity(verified, auth), nil
	} else if !errors.Is(err, errNoChainSignature) {
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain signature: %w", err))
	}
	verified, verifyErr := verifyLoadedChain(chain)
	if verifyErr != nil {
		return Result{}, verifyErr
	}
	return applyAuthenticity(verified, authenticityResult{
		VerificationMode:   verificationModeChainOnly,
		AuthenticityStatus: authenticityStatusUnavailable,
	}), nil
}

func loadChain(path string) (*proof.Chain, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- verify reads explicit local path provided by CLI flags/state.
	if err != nil {
		return nil, classifyError(ErrorCodeReadChain, fmt.Errorf("read chain: %w", err))
	}
	var chain proof.Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		return nil, classifyError(ErrorCodeParseChain, fmt.Errorf("parse chain: %w", err))
	}
	return &chain, nil
}

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

func verifyByAttestation(path string, publicKey proof.PublicKey) (authenticityResult, error) {
	if len(publicKey.Public) == 0 {
		return authenticityResult{}, errNoChainAttestation
	}
	chainPayload, err := os.ReadFile(path) // #nosec G304 -- attestation binds to the explicit local proof chain path.
	if err != nil {
		return authenticityResult{}, errNoChainAttestation
	}
	attestationPayload, err := os.ReadFile(attestationPath(path)) // #nosec G304 -- attestation file lives beside the explicit local proof chain path.
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return authenticityResult{}, errNoChainAttestation
		}
		return authenticityResult{}, err
	}
	var attestation chainAttestation
	if err := json.Unmarshal(attestationPayload, &attestation); err != nil {
		return authenticityResult{}, err
	}
	if attestation.ChainSHA != digestBytes(chainPayload) || attestation.ChainBytes != int64(len(chainPayload)) {
		return authenticityResult{}, fmt.Errorf("attested chain digest mismatch")
	}
	digest, err := digestAttestationPayload(chainAttestationPayload{
		Version:     attestation.Version,
		ChainSHA:    attestation.ChainSHA,
		ChainBytes:  attestation.ChainBytes,
		RecordCount: attestation.RecordCount,
		HeadHash:    attestation.HeadHash,
	})
	if err != nil {
		return authenticityResult{}, err
	}
	if err := signing.VerifyDigest(attestation.Signature, digest, publicKey); err != nil {
		return authenticityResult{}, err
	}
	return authenticityResult{
		VerificationMode:   verificationModeAttestation,
		AuthenticityStatus: authenticityStatusVerified,
	}, nil
}

func verifyBySignature(chain *proof.Chain, publicKey proof.PublicKey) (authenticityResult, error) {
	if chain == nil || len(chain.Signatures) == 0 || len(publicKey.Public) == 0 {
		return authenticityResult{}, errNoChainSignature
	}
	signature := chain.Signatures[len(chain.Signatures)-1]
	if err := proof.VerifyChainSignature(chain, signature, publicKey); err != nil {
		return authenticityResult{}, err
	}
	return authenticityResult{
		VerificationMode:   verificationModeSignature,
		AuthenticityStatus: authenticityStatusVerified,
	}, nil
}

func verifyLoadedChain(chain *proof.Chain) (Result, error) {
	verified, err := proof.VerifyChain(chain)
	if err != nil {
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain: %w", err))
	}
	return resultFromVerification(verified), nil
}

func attestationPath(path string) string {
	dir := filepath.Dir(strings.TrimSpace(path))
	if dir == "" || dir == "." {
		dir = ".wrkr"
	}
	return filepath.Join(dir, "proof-chain.attestation.json")
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

func resultFromVerification(verified *proof.ChainVerification) Result {
	result := Result{
		Intact:     verified.Intact,
		Count:      verified.Count,
		HeadHash:   verified.HeadHash,
		BreakPoint: verified.BreakPoint,
		BreakIndex: verified.BreakIndex,
		Reason:     "ok",
	}
	if !verified.Intact {
		result.Reason = "chain_integrity_failure"
	}
	return result
}

func applyAuthenticity(result Result, auth authenticityResult) Result {
	result.VerificationMode = strings.TrimSpace(auth.VerificationMode)
	result.AuthenticityStatus = strings.TrimSpace(auth.AuthenticityStatus)
	return result
}
