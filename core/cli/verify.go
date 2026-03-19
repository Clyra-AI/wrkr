package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/state"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
)

func runVerify(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	verifyChain := fs.Bool("chain", false, "verify proof chain integrity")
	statePathFlag := fs.String("state", "", "state file path override")
	chainPathFlag := fs.String("path", "", "proof chain path override")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if !*verifyChain {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--chain is required", exitInvalidInput)
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "verify does not accept positional arguments", exitInvalidInput)
	}

	chainPath, keyLookupPath := resolveVerifyPaths(*statePathFlag, *chainPathFlag)
	var (
		result verifycore.Result
		err    error
	)
	if publicKey, keyErr := proofemit.LoadVerifierKey(keyLookupPath); keyErr == nil {
		result, err = verifycore.ChainWithPublicKey(chainPath, publicKey)
	} else if errors.Is(keyErr, os.ErrNotExist) {
		result, err = verifycore.Chain(chainPath)
	} else {
		return emitVerificationFailure(stderr, jsonRequested || *jsonOut, "verifier_key_error", -1, "", keyErr.Error())
	}
	if err != nil {
		errorCode := verifycore.ErrorCodeFor(err)
		if errorCode == verifycore.ErrorCodeInvalidInput {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		return emitVerificationFailure(stderr, jsonRequested || *jsonOut, reasonForVerifyError(errorCode), -1, "", err.Error())
	}
	if !result.Intact {
		return emitVerificationFailure(stderr, jsonRequested || *jsonOut, result.Reason, result.BreakIndex, result.BreakPoint, "")
	}

	payload := map[string]any{
		"status": "ok",
		"chain": map[string]any{
			"path":                chainPath,
			"intact":              result.Intact,
			"count":               result.Count,
			"head_hash":           result.HeadHash,
			"reason":              result.Reason,
			"break_index":         result.BreakIndex,
			"break_point":         result.BreakPoint,
			"verification_mode":   result.VerificationMode,
			"authenticity_status": result.AuthenticityStatus,
		},
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr verify chain intact records=%d\n", result.Count)
	return exitSuccess
}

func resolveVerifyPaths(statePathFlag string, chainPathFlag string) (chainPath string, keyLookupPath string) {
	resolvedStatePath := state.ResolvePath(statePathFlag)
	explicitChainPath := strings.TrimSpace(chainPathFlag)
	if explicitChainPath == "" {
		return proofemit.ChainPath(resolvedStatePath), resolvedStatePath
	}
	if strings.TrimSpace(statePathFlag) != "" {
		return explicitChainPath, resolvedStatePath
	}
	return explicitChainPath, explicitChainPath
}

func emitVerificationFailure(stderr io.Writer, jsonOut bool, reason string, breakIndex int, breakPoint, detail string) int {
	if jsonOut {
		errorPayload := map[string]any{
			"code":      "verification_failure",
			"message":   "proof chain verification failed",
			"reason":    reason,
			"exit_code": exitVerification,
		}
		if breakIndex >= 0 {
			errorPayload["break_index"] = breakIndex
		}
		if strings.TrimSpace(breakPoint) != "" {
			errorPayload["break_point"] = breakPoint
		}
		if strings.TrimSpace(detail) != "" {
			errorPayload["detail"] = detail
		}
		_ = json.NewEncoder(stderr).Encode(map[string]any{"error": errorPayload})
		return exitVerification
	}
	if breakIndex >= 0 {
		_, _ = fmt.Fprintf(stderr, "proof chain verification failed at index %d (%s)\n", breakIndex, breakPoint)
		return exitVerification
	}
	_, _ = fmt.Fprintf(stderr, "proof chain verification failed: %s\n", detail)
	return exitVerification
}

func reasonForVerifyError(code verifycore.ErrorCode) string {
	switch code {
	case verifycore.ErrorCodeReadChain:
		return "chain_read_error"
	case verifycore.ErrorCodeParseChain:
		return "chain_parse_error"
	case verifycore.ErrorCodeVerifyChainFailure:
		return "chain_integrity_failure"
	default:
		return "verification_error"
	}
}
