package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/canon"
	proofrecord "github.com/Clyra-AI/proof/core/record"
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
	parallelHashThreshold         = 128
)

type authenticityResult struct {
	VerificationMode    string
	AuthenticityStatus  string
	AttestedRecordCount int
	AttestedHeadHash    string
}

type loadedChain struct {
	path    string
	payload []byte
	chain   *proof.Chain
}

type loadedChainPayload struct {
	path    string
	payload []byte
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
	loaded, err := loadChain(trimmed)
	if err != nil {
		return Result{}, err
	}
	result, err := verifyLoadedChain(loaded.chain)
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
	loadedPayload, err := loadChainPayload(trimmed)
	if err != nil {
		return Result{}, err
	}
	if auth, err := verifyByAttestationPayload(loadedPayload, publicKey); err == nil {
		verified, verifyErr := verifyAttestedPayloadLinks(loadedPayload.payload, auth.AttestedRecordCount, auth.AttestedHeadHash)
		if verifyErr != nil {
			return Result{}, verifyErr
		}
		return applyAuthenticity(verified, auth), nil
	} else if !errors.Is(err, errNoChainAttestation) {
		loaded, loadErr := parseChainPayload(loadedPayload)
		if loadErr != nil {
			return Result{}, loadErr
		}
		if auth, sigErr := verifyBySignature(loaded.chain, publicKey); sigErr == nil {
			verified, verifyErr := verifyLoadedChain(loaded.chain)
			if verifyErr != nil {
				return Result{}, verifyErr
			}
			return applyAuthenticity(verified, auth), nil
		} else if !errors.Is(sigErr, errNoChainSignature) {
			return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain signature: %w", sigErr))
		}
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain attestation: %w", err))
	}
	loaded, err := parseChainPayload(loadedPayload)
	if err != nil {
		return Result{}, err
	}
	if auth, err := verifyBySignature(loaded.chain, publicKey); err == nil {
		verified, verifyErr := verifyLoadedChain(loaded.chain)
		if verifyErr != nil {
			return Result{}, verifyErr
		}
		return applyAuthenticity(verified, auth), nil
	} else if !errors.Is(err, errNoChainSignature) {
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain signature: %w", err))
	}
	verified, verifyErr := verifyLoadedChain(loaded.chain)
	if verifyErr != nil {
		return Result{}, verifyErr
	}
	return applyAuthenticity(verified, authenticityResult{
		VerificationMode:   verificationModeChainOnly,
		AuthenticityStatus: authenticityStatusUnavailable,
	}), nil
}

func loadChain(path string) (*loadedChain, error) {
	loadedPayload, err := loadChainPayload(path)
	if err != nil {
		return nil, err
	}
	return parseChainPayload(loadedPayload)
}

func loadChainPayload(path string) (*loadedChainPayload, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- verify reads explicit local path provided by CLI flags/state.
	if err != nil {
		return nil, classifyError(ErrorCodeReadChain, fmt.Errorf("read chain: %w", err))
	}
	return &loadedChainPayload{path: path, payload: payload}, nil
}

func parseChainPayload(loaded *loadedChainPayload) (*loadedChain, error) {
	var chain proof.Chain
	if err := json.Unmarshal(loaded.payload, &chain); err != nil {
		return nil, classifyError(ErrorCodeParseChain, fmt.Errorf("parse chain: %w", err))
	}
	return &loadedChain{
		path:    loaded.path,
		payload: loaded.payload,
		chain:   &chain,
	}, nil
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

func verifyByAttestationPayload(loaded *loadedChainPayload, publicKey proof.PublicKey) (authenticityResult, error) {
	if len(publicKey.Public) == 0 {
		return authenticityResult{}, errNoChainAttestation
	}
	if loaded == nil || len(loaded.payload) == 0 {
		return authenticityResult{}, errNoChainAttestation
	}
	attestationPayload, err := os.ReadFile(attestationPath(loaded.path)) // #nosec G304 -- attestation file lives beside the explicit local proof chain path.
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
	if attestation.ChainSHA != digestBytes(loaded.payload) || attestation.ChainBytes != int64(len(loaded.payload)) {
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
		VerificationMode:    verificationModeAttestation,
		AuthenticityStatus:  authenticityStatusVerified,
		AttestedRecordCount: attestation.RecordCount,
		AttestedHeadHash:    attestation.HeadHash,
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
	verified, err := verifyChainStructure(chain)
	if err != nil {
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain: %w", err))
	}
	return resultFromVerification(verified), nil
}

func verifyAttestedPayloadLinks(payload []byte, attestedRecordCount int, attestedHeadHash string) (Result, error) {
	if !json.Valid(payload) {
		return Result{}, classifyError(ErrorCodeParseChain, fmt.Errorf("parse chain: invalid JSON"))
	}
	verified := &proof.ChainVerification{
		Intact:   true,
		Count:    attestedRecordCount,
		HeadHash: strings.TrimSpace(attestedHeadHash),
	}
	prev := ""
	count := 0
	pos := 0
	for {
		integrityKeyIdx := bytes.Index(payload[pos:], []byte(`"integrity"`))
		if integrityKeyIdx < 0 {
			break
		}
		integrityStart := pos + integrityKeyIdx
		objectOpen := bytes.IndexByte(payload[integrityStart:], '{')
		if objectOpen < 0 {
			return Result{}, classifyError(ErrorCodeParseChain, fmt.Errorf("parse chain: missing integrity object"))
		}
		objectStart := integrityStart + objectOpen
		objectEnd := bytes.IndexByte(payload[objectStart:], '}')
		if objectEnd < 0 {
			return Result{}, classifyError(ErrorCodeParseChain, fmt.Errorf("parse chain: unterminated integrity object"))
		}
		integrityObject := payload[objectStart : objectStart+objectEnd+1]
		if !bytes.Contains(integrityObject, []byte(`"record_hash"`)) {
			pos = objectStart + objectEnd + 1
			continue
		}
		recordID := scanRecordID(payload[pos:integrityStart])
		recordHash := scanJSONFieldString(integrityObject, "record_hash")
		previousHash := scanJSONFieldString(integrityObject, "previous_record_hash")
		if previousHash != prev {
			verified.Intact = false
			verified.BreakIndex = count
			verified.BreakPoint = recordID
			return resultFromVerification(verified), nil
		}
		if strings.TrimSpace(recordHash) == "" {
			verified.Intact = false
			verified.BreakIndex = count
			verified.BreakPoint = recordID
			return resultFromVerification(verified), nil
		}
		prev = recordHash
		count++
		pos = objectStart + objectEnd + 1
	}
	verified.Count = count
	if attestedRecordCount != count {
		verified.Intact = false
		verified.BreakIndex = count
		verified.BreakPoint = fmt.Sprintf("record_count mismatch: expected %d got %d", attestedRecordCount, count)
		return resultFromVerification(verified), nil
	}
	if count == 0 {
		if strings.TrimSpace(attestedHeadHash) != "" {
			verified.Intact = false
			verified.BreakIndex = -1
			verified.BreakPoint = "head_hash mismatch: expected empty head for empty chain"
		}
		return resultFromVerification(verified), nil
	}
	if strings.TrimSpace(attestedHeadHash) != prev {
		verified.Intact = false
		verified.BreakIndex = count - 1
		verified.BreakPoint = fmt.Sprintf("head_hash mismatch: expected %s got %s", prev, attestedHeadHash)
		verified.HeadHash = prev
	}
	return resultFromVerification(verified), nil
}

func scanRecordID(payload []byte) string {
	idx := bytes.LastIndex(payload, []byte(`"record_id"`))
	if idx < 0 {
		return ""
	}
	return scanJSONValueAfterKey(payload[idx+len(`"record_id"`):])
}

func scanJSONFieldString(payload []byte, field string) string {
	key := []byte(`"` + field + `"`)
	idx := bytes.Index(payload, key)
	if idx < 0 {
		return ""
	}
	return scanJSONValueAfterKey(payload[idx+len(key):])
}

func scanJSONValueAfterKey(payload []byte) string {
	colon := bytes.IndexByte(payload, ':')
	if colon < 0 {
		return ""
	}
	value := bytes.TrimLeft(payload[colon+1:], " \n\r\t")
	if len(value) == 0 || value[0] != '"' {
		return ""
	}
	end := bytes.IndexByte(value[1:], '"')
	if end < 0 {
		return ""
	}
	return string(value[1 : end+1])
}

func verifyChainStructure(chain *proof.Chain) (*proof.ChainVerification, error) {
	if chain == nil {
		return nil, errors.New("chain is nil")
	}

	verified := &proof.ChainVerification{
		Intact:   true,
		Count:    len(chain.Records),
		HeadHash: chain.HeadHash,
	}

	expectedHashes, err := computeRecordHashes(chain.Records)
	if err != nil {
		return nil, err
	}

	prev := ""
	for i := range chain.Records {
		record := chain.Records[i]
		if record.Integrity.PreviousRecordHash != prev {
			verified.Intact = false
			verified.BreakIndex = i
			verified.BreakPoint = record.RecordID
			return verified, nil
		}
		if expectedHashes[i] != chain.Records[i].Integrity.RecordHash {
			verified.Intact = false
			verified.BreakIndex = i
			verified.BreakPoint = chain.Records[i].RecordID
			return verified, nil
		}
		prev = record.Integrity.RecordHash
	}

	computedHead := ""
	if len(expectedHashes) > 0 {
		computedHead = expectedHashes[len(expectedHashes)-1]
	}
	if chain.HeadHash != computedHead {
		verified.Intact = false
		verified.BreakIndex = len(chain.Records) - 1
		verified.BreakPoint = fmt.Sprintf("head_hash mismatch: expected %s got %s", computedHead, chain.HeadHash)
		verified.HeadHash = computedHead
		return verified, nil
	}
	verified.HeadHash = computedHead
	return verified, nil
}

func computeRecordHashes(records []proofrecord.Record) ([]string, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if len(records) < parallelHashThreshold || runtime.GOMAXPROCS(0) == 1 {
		return computeRecordHashesSequential(records)
	}

	type hashResult struct {
		index int
		hash  string
		err   error
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(records) {
		workers = len(records)
	}
	indexes := make(chan int, workers)
	results := make(chan hashResult, workers)

	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range indexes {
				hash, err := proofrecord.ComputeHash(&records[index])
				results <- hashResult{index: index, hash: hash, err: err}
			}
		}()
	}

	go func() {
		for index := range records {
			indexes <- index
		}
		close(indexes)
		wg.Wait()
		close(results)
	}()

	hashes := make([]string, len(records))
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
			continue
		}
		hashes[result.index] = result.hash
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return hashes, nil
}

func computeRecordHashesSequential(records []proofrecord.Record) ([]string, error) {
	hashes := make([]string, len(records))
	for i := range records {
		hash, err := proofrecord.ComputeHash(&records[i])
		if err != nil {
			return nil, err
		}
		hashes[i] = hash
	}
	return hashes, nil
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
