package cli

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/evidence"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	"github.com/Clyra-AI/wrkr/core/state"
)

const (
	evidenceJSONInlineControlEvidenceCap = 25
	evidenceJSONInlineReportArtifactsCap = 12
)

func runEvidence(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	jsonStdoutRaw := fs.String("json-stdout", string(jsonStdoutModeAuto), "stdout JSON mode [auto|full]")
	frameworksRaw := fs.String("frameworks", "", "comma-separated framework ids")
	outputDir := fs.String("output", "wrkr-evidence", "evidence output directory")
	statePathFlag := fs.String("state", "", "state file path override")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "evidence does not accept positional arguments", exitInvalidInput)
	}
	jsonStdoutModeValue, jsonStdoutModeErr := parseJSONStdoutMode(*jsonStdoutRaw)
	if jsonStdoutModeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", jsonStdoutModeErr.Error(), exitInvalidInput)
	}
	frameworks := parseFrameworkFlags(*frameworksRaw)
	if len(frameworks) == 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--frameworks is required", exitInvalidInput)
	}

	result, err := evidence.Build(evidence.BuildInput{
		StatePath:   *statePathFlag,
		Frameworks:  frameworks,
		OutputDir:   strings.TrimSpace(*outputDir),
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		switch evidence.ClassifyBuildError(err) {
		case evidence.ErrorClassInvalidInput:
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		case evidence.ErrorClassUnsafeOperationBlocked:
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
		default:
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
	}
	resolvedStatePath := state.ResolvePath(*statePathFlag)

	if *jsonOut {
		payload := buildEvidenceJSONPayload(result, resolvedStatePath)
		jsonSink, err := newJSONOutputSink(true, "", stdout, jsonStdoutModeValue)
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		var compactPayload any
		if jsonSink.usesCompactStdout() {
			var suppressed any
			if value, ok := payload["suppressed_counts"]; ok {
				suppressed = value
			}
			compactPayload = buildEvidenceCompactJSONSummary(resolvedStatePath, map[string]any{
				"output_dir":             result.OutputDir,
				"frameworks":             result.Frameworks,
				"manifest_path":          result.ManifestPath,
				"artifact_manifest_path": result.ArtifactManifestPath,
				"chain_path":             result.ChainPath,
				"state_path":             resolvedStatePath,
				"control_evidence_json":  filepath.Join(result.OutputDir, "control-evidence.json"),
				"deployment_mode":        result.DeploymentMode,
			}, suppressed)
		}
		if err := jsonSink.writePayloads(compactPayload, payload); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr evidence bundle written to %s\n", result.OutputDir)
	return exitSuccess
}

func buildEvidenceJSONPayload(result evidence.BuildResult, resolvedStatePath string) map[string]any {
	controlEvidence, controlEvidenceOverflow := outputsignal.CapSlice(result.ControlEvidence, evidenceJSONInlineControlEvidenceCap)
	reportArtifacts, reportArtifactsOverflow := outputsignal.CapSlice(result.ReportArtifacts, evidenceJSONInlineReportArtifactsCap)
	payload := map[string]any{
		"status":                 "ok",
		"deployment_mode":        result.DeploymentMode,
		"output_dir":             result.OutputDir,
		"frameworks":             result.Frameworks,
		"manifest_path":          result.ManifestPath,
		"artifact_manifest_path": result.ArtifactManifestPath,
		"chain_path":             result.ChainPath,
		"framework_coverage":     result.FrameworkCoverage,
		"control_evidence":       controlEvidence,
		"coverage_note":          result.CoverageNote,
		"report_artifacts":       reportArtifacts,
		"source_privacy":         result.SourcePrivacy,
		"agent_action_bom":       result.AgentActionBOM,
		"governed_usage_metrics": result.GovernedUsageMetrics,
		"next_steps":             evidenceNextSteps(resolvedStatePath, result.OutputDir, result.ManifestPath, result.ReportArtifacts),
	}
	if result.RuntimeSessions != nil {
		payload["runtime_sessions"] = result.RuntimeSessions
	}
	if result.RuntimeEvidence != nil {
		payload["runtime_evidence"] = result.RuntimeEvidence
	}
	if len(result.CompositionRefs) > 0 {
		payload["composition_refs"] = result.CompositionRefs
	}
	if suppressed := outputsignal.MergeSuppressedCounts(&outputsignal.SuppressedCounts{
		ControlEvidence: controlEvidenceOverflow,
		ReportArtifacts: reportArtifactsOverflow,
	}); suppressed != nil {
		payload["suppressed_counts"] = suppressed
		payload["artifact_paths"] = map[string]any{
			"state":                 resolvedStatePath,
			"control_evidence_json": filepath.Join(result.OutputDir, "control-evidence.json"),
		}
	}
	return payload
}

func parseFrameworkFlags(raw string) []string {
	set := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	// deterministic ordering in output and downstream evidence writes.
	sort.Strings(out)
	return out
}
