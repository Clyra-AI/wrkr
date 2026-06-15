package cli

import (
	"fmt"
	"strings"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
)

func buildCompactJSONSummary(command, message string, artifactPaths map[string]string, suppressed any, nextSteps []nextStep, extras map[string]any) map[string]any {
	payload := map[string]any{
		"status":              "ok",
		"command":             strings.TrimSpace(command),
		"json_stdout":         "compact",
		"compact_reason":      "interactive_tty",
		"full_json_available": true,
		"message":             strings.TrimSpace(message),
	}
	if len(artifactPaths) > 0 {
		payload["artifact_paths"] = artifactPaths
	}
	if suppressed != nil {
		payload["suppressed_counts"] = suppressed
	}
	if len(nextSteps) > 0 {
		payload["next_steps"] = nextSteps
	}
	for key, value := range extras {
		if value == nil {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) == "" {
				continue
			}
		case []string:
			if len(typed) == 0 {
				continue
			}
		}
		payload[key] = value
	}
	return payload
}

func buildScanCompactJSONSummary(statePath string, artifactPaths map[string]string, suppressed *reportcore.SuppressedCounts) map[string]any {
	return buildCompactJSONSummary(
		"scan",
		fmt.Sprintf(
			"Interactive --json stdout is compact for scan. The canonical scan artifact remains at --state (%s). Redirect stdout or use --json-stdout=full for the full command-response JSON.",
			strings.TrimSpace(statePath),
		),
		artifactPaths,
		suppressed,
		scanNextSteps(statePath, artifactPaths),
		map[string]any{
			"state_path":          strings.TrimSpace(statePath),
			"canonical_artifact":  "state_path",
			"command_response_on": "stdout_or_json_path",
		},
	)
}

func buildReportCompactJSONSummary(statePath string, payload reportPayload) map[string]any {
	artifactPaths := copyArtifactPathMap(payload.ArtifactPaths)
	if len(artifactPaths) == 0 && strings.TrimSpace(statePath) != "" {
		artifactPaths = map[string]string{"state": strings.TrimSpace(statePath)}
	}
	return buildCompactJSONSummary(
		"report",
		"Interactive --json stdout is compact for report. Redirect stdout or use --json-stdout=full for the complete machine-readable payload.",
		artifactPaths,
		payload.SuppressedCounts,
		payload.NextSteps,
		map[string]any{
			"generated_at":  payload.GeneratedAt,
			"template":      payload.Summary.Template,
			"share_profile": payload.Summary.ShareProfile,
			"state_path":    strings.TrimSpace(statePath),
		},
	)
}

func buildEvidenceCompactJSONSummary(statePath string, result map[string]any, suppressed any) map[string]any {
	artifactPaths := map[string]string{}
	if stateValue, ok := result["state_path"].(string); ok && strings.TrimSpace(stateValue) != "" {
		artifactPaths["state"] = strings.TrimSpace(stateValue)
	}
	if outputDir, ok := result["output_dir"].(string); ok && strings.TrimSpace(outputDir) != "" {
		artifactPaths["output_dir"] = strings.TrimSpace(outputDir)
	}
	if manifestPath, ok := result["manifest_path"].(string); ok && strings.TrimSpace(manifestPath) != "" {
		artifactPaths["manifest"] = strings.TrimSpace(manifestPath)
	}
	if artifactManifestPath, ok := result["artifact_manifest_path"].(string); ok && strings.TrimSpace(artifactManifestPath) != "" {
		artifactPaths["artifact_manifest"] = strings.TrimSpace(artifactManifestPath)
	}
	if chainPath, ok := result["chain_path"].(string); ok && strings.TrimSpace(chainPath) != "" {
		artifactPaths["proof_chain"] = strings.TrimSpace(chainPath)
	}
	if controlEvidencePath, ok := result["control_evidence_json"].(string); ok && strings.TrimSpace(controlEvidencePath) != "" {
		artifactPaths["control_evidence_json"] = strings.TrimSpace(controlEvidencePath)
	}
	return buildCompactJSONSummary(
		"evidence",
		"Interactive --json stdout is compact for evidence. Redirect stdout or use --json-stdout=full for the complete machine-readable payload.",
		artifactPaths,
		suppressed,
		nil,
		result,
	)
}

func buildAssessCompactJSONSummary(outputDir, manifestPath string, stages assessStages, artifacts assessArtifacts, status string) map[string]any {
	artifactPaths := assessArtifactPathMap(artifacts)
	if strings.TrimSpace(manifestPath) != "" {
		artifactPaths["manifest"] = strings.TrimSpace(manifestPath)
	}
	return buildCompactJSONSummary(
		"assess",
		"Interactive --json stdout is compact for assess. Redirect stdout or use --json-stdout=full for the complete machine-readable payload.",
		artifactPaths,
		nil,
		nil,
		map[string]any{
			"status":        strings.TrimSpace(status),
			"output_dir":    strings.TrimSpace(outputDir),
			"manifest_path": strings.TrimSpace(manifestPath),
			"stages":        stages,
			"artifacts":     artifacts,
		},
	)
}

func scanNextSteps(statePath string, artifactPaths map[string]string) []nextStep {
	stateArg := shellQuoteArg(statePath)
	reviewArtifacts := []string{"state_path"}
	if _, ok := artifactPaths["json"]; ok {
		reviewArtifacts = append(reviewArtifacts, "json_path")
	}
	if _, ok := artifactPaths["report_md"]; ok {
		reviewArtifacts = append(reviewArtifacts, "report_md")
	}
	if _, ok := artifactPaths["sarif"]; ok {
		reviewArtifacts = append(reviewArtifacts, "sarif")
	}
	return []nextStep{
		{
			ID:          "review_saved_scan_artifacts",
			Description: "Review the canonical saved scan artifact and any optional sidecar outputs.",
			Artifacts:   uniqueSortedStrings(reviewArtifacts),
		},
		{
			ID:          "render_focused_report",
			Description: "Render a focused Agent Action BOM report from the same saved scan state.",
			Command:     fmt.Sprintf("wrkr report --state %s --template agent-action-bom --json", stateArg),
		},
		{
			ID:          "generate_evidence_bundle",
			Description: "Generate a portable evidence bundle from the same saved scan state.",
			Command:     fmt.Sprintf("wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state %s --output ./wrkr-evidence --json", stateArg),
		},
	}
}

func copyArtifactPathMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func assessArtifactPathMap(artifacts assessArtifacts) map[string]string {
	paths := map[string]string{}
	addPath := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		paths[key] = strings.TrimSpace(value)
	}
	addPath("state", artifacts.StatePath)
	addPath("identity_manifest", artifacts.IdentityManifestPath)
	addPath("lifecycle_chain", artifacts.LifecycleChainPath)
	addPath("proof_chain", artifacts.ProofChainPath)
	addPath("proof_attestation", artifacts.ProofAttestationPath)
	addPath("runtime_artifact", artifacts.RuntimeArtifactPath)
	addPath("report_markdown", artifacts.ReportMarkdownPath)
	addPath("report_evidence_json", artifacts.ReportEvidenceJSONPath)
	addPath("backlog_csv", artifacts.BacklogCSVPath)
	addPath("private_join_map", artifacts.PrivateJoinMapPath)
	addPath("evidence_output_dir", artifacts.EvidenceOutputDir)
	addPath("evidence_manifest", artifacts.EvidenceManifestPath)
	addPath("evidence_artifact_manifest", artifacts.EvidenceArtifactManifest)
	addPath("evidence_chain", artifacts.EvidenceChainPath)
	addPath("export_inventory", artifacts.ExportInventoryPath)
	addPath("export_appendix", artifacts.ExportAppendixPath)
	addPath("export_pack", artifacts.ExportPackPath)
	addPath("ticket_payload", artifacts.TicketPayloadPath)
	addPath("drift_json", artifacts.DriftJSONPath)
	addPath("drift_summary_md", artifacts.DriftSummaryMDPath)
	for key, value := range artifacts.PairedArtifactPaths {
		addPath(key, value)
	}
	if len(paths) == 0 {
		return nil
	}
	return paths
}
