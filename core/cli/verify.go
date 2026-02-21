package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

	chainPath := strings.TrimSpace(*chainPathFlag)
	if chainPath == "" {
		chainPath = proofemit.ChainPath(state.ResolvePath(*statePathFlag))
	}
	result, err := verifycore.Chain(chainPath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if !result.Intact {
		if jsonRequested || *jsonOut {
			_ = json.NewEncoder(stderr).Encode(map[string]any{
				"error": map[string]any{
					"code":        "verification_failure",
					"message":     "proof chain verification failed",
					"reason":      result.Reason,
					"break_index": result.BreakIndex,
					"break_point": result.BreakPoint,
					"exit_code":   exitVerification,
				},
			})
		} else {
			_, _ = fmt.Fprintf(stderr, "proof chain verification failed at index %d (%s)\n", result.BreakIndex, result.BreakPoint)
		}
		return exitVerification
	}

	payload := map[string]any{
		"status": "ok",
		"chain": map[string]any{
			"path":        chainPath,
			"intact":      result.Intact,
			"count":       result.Count,
			"head_hash":   result.HeadHash,
			"reason":      result.Reason,
			"break_index": result.BreakIndex,
			"break_point": result.BreakPoint,
		},
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr verify chain intact records=%d\n", result.Count)
	return exitSuccess
}
