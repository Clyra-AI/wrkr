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
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

const (
	evidenceJSONInlineControlEvidenceCap = 25
	evidenceJSONInlineReportArtifactsCap = 12
	evidenceJSONInlineBOMItemsCap        = 5
	evidenceJSONInlineCompositionsCap    = 3
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
	agentActionBOM, agentActionBOMOverflow, compositionOverflow := previewEvidenceAgentActionBOM(result.AgentActionBOM)
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
		"agent_action_bom":       agentActionBOM,
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
		AgentActionBOM:      agentActionBOMOverflow,
		ComposedActionPaths: compositionOverflow,
		ControlEvidence:     controlEvidenceOverflow,
		ReportArtifacts:     reportArtifactsOverflow,
	}); suppressed != nil {
		payload["suppressed_counts"] = suppressed
		payload["artifact_paths"] = map[string]any{
			"state":                        resolvedStatePath,
			"control_evidence_json":        filepath.Join(result.OutputDir, "control-evidence.json"),
			"agent_action_bom_json":        filepath.Join(result.OutputDir, "reports", "agent-action-bom-customer-redacted.json"),
			"agent_action_bom_full_bundle": filepath.Join(result.OutputDir, "reports", "report-evidence-customer-redacted.json"),
		}
	}
	return payload
}

func previewEvidenceAgentActionBOM(in *reportcore.AgentActionBOM) (*reportcore.AgentActionBOM, int, int) {
	if in == nil {
		return nil, 0, 0
	}
	out := *in
	out.Items = append([]reportcore.AgentActionBOMItem(nil), scanPreview(in.Items, evidenceJSONInlineBOMItemsCap)...)
	out.ComposedActionPaths = append([]risk.ComposedActionPath(nil), scanPreview(in.ComposedActionPaths, evidenceJSONInlineCompositionsCap)...)
	if in.Summary.PrimaryView != nil {
		out.Items = preservePrimaryBOMItem(out.Items, in.Items, in.Summary.PrimaryView.PathID)
		out.ComposedActionPaths = preservePrimaryComposition(out.ComposedActionPaths, in.ComposedActionPaths, in.Summary.PrimaryView.CompositionID)
	}
	return &out, positiveOverflow(len(in.Items), len(out.Items)), positiveOverflow(len(in.ComposedActionPaths), len(out.ComposedActionPaths))
}

func preservePrimaryBOMItem(preview []reportcore.AgentActionBOMItem, all []reportcore.AgentActionBOMItem, pathID string) []reportcore.AgentActionBOMItem {
	pathID = strings.TrimSpace(pathID)
	if pathID == "" || containsBOMPath(preview, pathID) {
		return preview
	}
	for _, item := range all {
		if strings.TrimSpace(item.PathID) != pathID {
			continue
		}
		if len(preview) == 0 {
			return []reportcore.AgentActionBOMItem{item}
		}
		preview[len(preview)-1] = item
		return preview
	}
	return preview
}

func containsBOMPath(items []reportcore.AgentActionBOMItem, pathID string) bool {
	for _, item := range items {
		if strings.TrimSpace(item.PathID) == pathID {
			return true
		}
	}
	return false
}

func preservePrimaryComposition(preview []risk.ComposedActionPath, all []risk.ComposedActionPath, compositionID string) []risk.ComposedActionPath {
	compositionID = strings.TrimSpace(compositionID)
	if compositionID == "" {
		return preview
	}
	for _, item := range preview {
		if strings.TrimSpace(item.CompositionID) == compositionID {
			return preview
		}
	}
	for _, item := range all {
		if strings.TrimSpace(item.CompositionID) != compositionID {
			continue
		}
		if len(preview) == 0 {
			return []risk.ComposedActionPath{item}
		}
		preview[len(preview)-1] = item
		return preview
	}
	return preview
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
