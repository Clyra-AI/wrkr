package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	proof "github.com/Clyra-AI/proof"
)

type Result struct {
	Intact     bool   `json:"intact"`
	Count      int    `json:"count"`
	HeadHash   string `json:"head_hash,omitempty"`
	BreakPoint string `json:"break_point,omitempty"`
	BreakIndex int    `json:"break_index,omitempty"`
	Reason     string `json:"reason"`
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
	payload, err := os.ReadFile(trimmed) // #nosec G304 -- verify reads explicit local path provided by CLI flags/state.
	if err != nil {
		return Result{}, classifyError(ErrorCodeReadChain, fmt.Errorf("read chain: %w", err))
	}
	var chain proof.Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		return Result{}, classifyError(ErrorCodeParseChain, fmt.Errorf("parse chain: %w", err))
	}
	verified, err := proof.VerifyChain(&chain)
	if err != nil {
		return Result{}, classifyError(ErrorCodeVerifyChainFailure, fmt.Errorf("verify chain: %w", err))
	}
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
	return result, nil
}
