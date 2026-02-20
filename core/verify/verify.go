package verify

import (
	"encoding/json"
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

func Chain(path string) (Result, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return Result{}, fmt.Errorf("chain path is required")
	}
	payload, err := os.ReadFile(trimmed) // #nosec G304 -- verify reads explicit local path provided by CLI flags/state.
	if err != nil {
		return Result{}, fmt.Errorf("read chain: %w", err)
	}
	var chain proof.Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		return Result{}, fmt.Errorf("parse chain: %w", err)
	}
	verified, err := proof.VerifyChain(&chain)
	if err != nil {
		return Result{}, fmt.Errorf("verify chain: %w", err)
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
