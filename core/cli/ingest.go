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
	topLevelKeys, err := topLevelJSONKeys(payload)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if _, hasPackets := topLevelKeys["packets"]; hasPackets {
		var bundle ingest.EvidencePacketBundle
		if err := json.Unmarshal(payload, &bundle); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		if err := ingest.ValidateEvidencePacketJSON(payload); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "policy_schema_violation", err.Error(), exitPolicyViolation)
		}
		normalized, err := ingest.NormalizeEvidencePacketBundle(bundle)
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "policy_schema_violation", err.Error(), exitPolicyViolation)
		}
		outputPath, err := normalizeManagedArtifactPath(ingest.DefaultEvidencePacketPath(resolvedStatePath))
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		if err := rejectUnsafeExistingManagedFile(outputPath, "evidence packet artifact"); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
		}
		if err := ingest.SaveEvidencePacketBundle(outputPath, normalized); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}

		summary := ingest.CorrelateEvidencePackets(snapshot, outputPath, normalized)
		if *jsonOut {
			_ = json.NewEncoder(stdout).Encode(map[string]any{
				"status":            "ok",
				"artifact_path":     outputPath,
				"artifact_kind":     "evidence_packets",
				"packet_count":      summary.TotalPackets,
				"matched_packets":   summary.MatchedPackets,
				"unmatched_packets": summary.UnmatchedPackets,
				"evidence_packets":  summary,
			})
			return exitSuccess
		}
		_, _ = io.WriteString(stdout, "wrkr ingest complete\n")
		return exitSuccess
	}
	if _, hasSessions := topLevelKeys["sessions"]; hasSessions || (topLevelKeys["records"] == nil && topLevelKeys["packets"] == nil) {
		bundle, sessionErr := ingest.ParseSessionBundleJSON(payload)
		if sessionErr == nil {
			outputPath, pathErr := normalizeManagedArtifactPath(ingest.DefaultSessionPath(resolvedStatePath))
			if pathErr != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", pathErr.Error(), exitInvalidInput)
			}
			if err := rejectUnsafeExistingManagedFile(outputPath, "runtime sessions artifact"); err != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
			}
			transaction, txErr := beginManagedArtifactTransaction(resolvedStatePath, "ingest_sessions", []managedArtifactFile{
				{label: "runtime sessions artifact", path: outputPath},
			})
			if txErr != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", txErr.Error(), exitUnsafeBlocked)
			}
			if err := ingest.SaveSessionBundle(outputPath, bundle); err != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", transaction.Rollback(err).Error(), exitRuntime)
			}
			if err := transaction.Complete(); err != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", transaction.Rollback(err).Error(), exitRuntime)
			}
			summary := ingest.CorrelateSessions(snapshot, outputPath, bundle)
			runtimeSummary := ingest.Correlate(snapshot, outputPath, ingest.ProjectSessionsToRuntimeBundle(bundle))
			packetSummary := ingest.CorrelateEvidencePackets(snapshot, outputPath, ingest.ProjectSessionsToEvidencePacketBundle(bundle))
			if *jsonOut {
				_ = json.NewEncoder(stdout).Encode(map[string]any{
					"status":             "ok",
					"artifact_path":      outputPath,
					"artifact_kind":      "runtime_sessions",
					"session_count":      summary.TotalSessions,
					"matched_sessions":   summary.MatchedSessions,
					"unmatched_sessions": summary.UnmatchedSessions,
					"runtime_sessions":   summary,
					"runtime_evidence":   runtimeSummary,
					"evidence_packets":   packetSummary,
				})
				return exitSuccess
			}
			_, _ = io.WriteString(stdout, "wrkr ingest complete\n")
			return exitSuccess
		}
		if !ingest.IsUnrecognizedSessionArtifact(sessionErr) {
			return emitError(stderr, jsonRequested || *jsonOut, "policy_schema_violation", sessionErr.Error(), exitPolicyViolation)
		}
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

func topLevelJSONKeys(payload []byte) (map[string]json.RawMessage, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return nil, err
	}
	if top == nil {
		return nil, json.Unmarshal(payload, &top)
	}
	return top, nil
}
