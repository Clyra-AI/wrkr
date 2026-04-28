package cli

import (
	"encoding/json"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runIngest(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("ingest", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	inputPath := fs.String("input", "", "runtime evidence input artifact")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "ingest does not accept positional arguments", exitInvalidInput)
	}
	if strings.TrimSpace(*inputPath) == "" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--input is required", exitInvalidInput)
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	payload, err := os.ReadFile(strings.TrimSpace(*inputPath)) // #nosec G304 -- caller provides explicit local input path.
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	var bundle ingest.Bundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	normalized, err := ingest.Normalize(bundle)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "policy_schema_violation", err.Error(), exitPolicyViolation)
	}

	outputPath, err := normalizeManagedArtifactPath(ingest.DefaultPath(resolvedStatePath))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if err := rejectUnsafeExistingManagedFile(outputPath, "runtime evidence artifact"); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	}
	if err := ingest.Save(outputPath, normalized); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	summary := ingest.Correlate(snapshot, outputPath, normalized)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":            "ok",
			"artifact_path":     outputPath,
			"record_count":      summary.TotalRecords,
			"matched_records":   summary.MatchedRecords,
			"unmatched_records": summary.UnmatchedRecords,
			"runtime_evidence":  summary,
		})
		return exitSuccess
	}
	_, _ = io.WriteString(stdout, "wrkr ingest complete\n")
	return exitSuccess
}
