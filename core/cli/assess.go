package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
)

type assessStageStatus struct {
	Status    string `json:"status"`
	ExitCode  int    `json:"exit_code"`
	Artifact  string `json:"artifact,omitempty"`
	Artifact2 string `json:"artifact_secondary,omitempty"`
	Message   string `json:"message,omitempty"`
}

type assessStages struct {
	Scan     assessStageStatus `json:"scan"`
	Ingest   assessStageStatus `json:"ingest"`
	Report   assessStageStatus `json:"report"`
	Evidence assessStageStatus `json:"evidence"`
	Export   assessStageStatus `json:"export"`
	Tickets  assessStageStatus `json:"tickets"`
	Regress  assessStageStatus `json:"regress"`
}

type assessArtifacts struct {
	StatePath                string            `json:"state_path,omitempty"`
	IdentityManifestPath     string            `json:"identity_manifest_path,omitempty"`
	LifecycleChainPath       string            `json:"lifecycle_chain_path,omitempty"`
	ProofChainPath           string            `json:"proof_chain_path,omitempty"`
	ProofAttestationPath     string            `json:"proof_attestation_path,omitempty"`
	RuntimeArtifactPath      string            `json:"runtime_artifact_path,omitempty"`
	RuntimeArtifactKind      string            `json:"runtime_artifact_kind,omitempty"`
	ReportMarkdownPath       string            `json:"report_markdown_path,omitempty"`
	ReportEvidenceJSONPath   string            `json:"report_evidence_json_path,omitempty"`
	BacklogCSVPath           string            `json:"backlog_csv_path,omitempty"`
	PairedArtifactPaths      map[string]string `json:"paired_artifact_paths,omitempty"`
	PrivateJoinMapPath       string            `json:"private_join_map_path,omitempty"`
	EvidenceOutputDir        string            `json:"evidence_output_dir,omitempty"`
	EvidenceManifestPath     string            `json:"evidence_manifest_path,omitempty"`
	EvidenceArtifactManifest string            `json:"evidence_artifact_manifest_path,omitempty"`
	EvidenceChainPath        string            `json:"evidence_chain_path,omitempty"`
	ExportInventoryPath      string            `json:"export_inventory_path,omitempty"`
	ExportAppendixPath       string            `json:"export_appendix_path,omitempty"`
	ExportPackPath           string            `json:"export_pack_path,omitempty"`
	TicketPayloadPath        string            `json:"ticket_payload_path,omitempty"`
	DriftJSONPath            string            `json:"drift_json_path,omitempty"`
	DriftSummaryMDPath       string            `json:"drift_summary_md_path,omitempty"`
}

type assessCommandMetadata struct {
	Template           string   `json:"template"`
	ShareProfile       string   `json:"share_profile"`
	PairedShareProfile string   `json:"paired_share_profile,omitempty"`
	Focus              string   `json:"focus,omitempty"`
	FocusPath          string   `json:"focus_path,omitempty"`
	Frameworks         []string `json:"frameworks,omitempty"`
	Baseline           string   `json:"baseline,omitempty"`
	RuntimeInput       string   `json:"runtime_input,omitempty"`
	TicketFormat       string   `json:"ticket_format,omitempty"`
	Targets            []string `json:"targets,omitempty"`
	Profile            string   `json:"profile"`
}

type assessManifest struct {
	SchemaVersion   string                `json:"schema_version"`
	GeneratedAt     string                `json:"generated_at"`
	OutputDir       string                `json:"output_dir"`
	CommandMetadata assessCommandMetadata `json:"command_metadata"`
	Stages          assessStages          `json:"stages"`
	Artifacts       assessArtifacts       `json:"artifacts"`
}

type assessExportPack struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Template      string `json:"template"`
	ShareProfile  string `json:"share_profile"`
	Focus         string `json:"focus,omitempty"`
	Inventory     any    `json:"inventory"`
	Appendix      any    `json:"appendix"`
}

func runAssess(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("assess", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	explain := fs.Bool("explain", false, "emit rationale")
	outputDir := fs.String("output-dir", "wrkr-assessment", "assessment output directory")
	statePathFlag := fs.String("state", "", "state file path override")
	templateRaw := fs.String("template", string(reportcore.TemplateAgentActionBOM), "assessment report template [exec|operator|audit|public|ciso|appsec|platform|customer-draft|agent-action-bom|design-partner-summary]")
	shareProfileRaw := fs.String("share-profile", string(reportcore.ShareProfileInternal), "share profile [internal|public|customer-redacted|design-partner|external-redacted|investor-safe]")
	pairedShareProfileRaw := fs.String("paired-share-profile", "", "optional second share profile for paired internal/external artifacts [customer-redacted|design-partner|external-redacted|investor-safe]")
	focusRaw := fs.String("focus", "", "named buyer focus preset ["+reportcore.FocusPresetUsage()+"]")
	focusPathRaw := fs.String("focus-path", "", "explicit agent-action-bom path_id for focused workflow rendering")
	baselinePath := fs.String("baseline", "", "optional regress baseline for drift review")
	runtimeInput := fs.String("runtime-input", "", "optional runtime/session/evidence input artifact")
	frameworksRaw := fs.String("frameworks", "soc2", "comma-separated framework ids")
	ticketFormat := fs.String("ticket-format", "", "optional dry-run ticket payload format [jira|github|servicenow]")
	top := fs.Int("top", 10, "number of top findings and paths to project into report artifacts")
	scanProfile := fs.String("profile", "assessment", "scan profile [baseline|standard|strict|assessment]")
	pathTarget := fs.String("path", "", "local path target")
	mySetup := fs.Bool("my-setup", false, "scan supported local user-home AI setup surfaces")
	var explicitTargets repeatedStringFlag
	fs.Var(&explicitTargets, "target", "repeatable scan target <mode>:<value>")
	fs.Usage = func() {
		writeAssessUsage(fs.Output(), fs)
	}

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "assess does not accept positional arguments", exitInvalidInput)
	}
	if *quiet && *explain && !*jsonOut {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--quiet and --explain cannot be used together", exitInvalidInput)
	}

	template, shareProfile, parseErr := parseReportTemplateShare(*templateRaw, *shareProfileRaw)
	if parseErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", parseErr.Error(), exitInvalidInput)
	}
	pairedShareProfile := reportcore.ShareProfile("")
	if trimmed := strings.TrimSpace(*pairedShareProfileRaw); trimmed != "" {
		parsed, ok := reportcore.ParseShareProfile(trimmed)
		if !ok || parsed == reportcore.ShareProfileInternal || parsed == shareProfile {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--paired-share-profile must be a distinct redacted share profile", exitInvalidInput)
		}
		if shareProfile != reportcore.ShareProfileInternal {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--paired-share-profile requires --share-profile internal", exitInvalidInput)
		}
		pairedShareProfile = parsed
	}
	if trimmed := strings.TrimSpace(*focusRaw); trimmed != "" {
		if _, ok := reportcore.ParseFocusPreset(trimmed); !ok {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--focus must be one of "+reportcore.FocusPresetUsage(), exitInvalidInput)
		}
	}
	if strings.TrimSpace(*focusPathRaw) != "" && template != reportcore.TemplateAgentActionBOM {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--focus-path requires --template agent-action-bom", exitInvalidInput)
	}
	frameworks := parseFrameworkFlags(*frameworksRaw)
	if len(frameworks) == 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--frameworks must include at least one framework id", exitInvalidInput)
	}
	if trimmed := strings.TrimSpace(*ticketFormat); trimmed != "" && trimmed != "jira" && trimmed != "github" && trimmed != "servicenow" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--ticket-format must be one of jira|github|servicenow", exitInvalidInput)
	}
	targetLabels := assessTargetLabels(strings.TrimSpace(*pathTarget), *mySetup, explicitTargets)
	if len(targetLabels) == 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "assess requires at least one local scan target (--path, --my-setup, or --target)", exitInvalidInput)
	}

	resolvedOutputDir, outputDirErr := filepath.Abs(filepath.Clean(strings.TrimSpace(*outputDir)))
	if outputDirErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("resolve --output-dir: %v", outputDirErr), exitInvalidInput)
	}
	if info, err := os.Lstat(resolvedOutputDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", "--output-dir must be a real directory, not a symlink or regular file", exitUnsafeBlocked)
		}
	} else if !os.IsNotExist(err) {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("stat --output-dir: %v", err), exitRuntime)
	}
	if err := os.MkdirAll(resolvedOutputDir, 0o750); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("mkdir --output-dir: %v", err), exitRuntime)
	}

	statePath := strings.TrimSpace(*statePathFlag)
	if statePath == "" {
		statePath = filepath.Join(resolvedOutputDir, "internal", "scan-state.json")
	}
	statePath, parseErr = normalizeManagedArtifactPath(statePath)
	if parseErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", parseErr.Error(), exitInvalidInput)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("mkdir state artifact dir: %v", err), exitRuntime)
	}

	reportMDPath := filepath.Join(resolvedOutputDir, "report", "wrkr-report.md")
	reportEvidenceJSONPath := filepath.Join(resolvedOutputDir, "report", "wrkr-report-evidence.json")
	backlogCSVPath := filepath.Join(resolvedOutputDir, "report", "wrkr-control-backlog.csv")
	evidenceOutputDir := filepath.Join(resolvedOutputDir, "evidence")
	exportInventoryPath := filepath.Join(resolvedOutputDir, "export", "inventory.json")
	exportAppendixPath := filepath.Join(resolvedOutputDir, "export", "appendix.json")
	exportPackPath := filepath.Join(resolvedOutputDir, "export", "export-pack.json")
	driftJSONPath := filepath.Join(resolvedOutputDir, "regress", "drift.json")
	driftSummaryMDPath := filepath.Join(resolvedOutputDir, "regress", "wrkr-regress-summary.md")
	ticketPayloadPath := ""
	if strings.TrimSpace(*ticketFormat) != "" {
		ticketPayloadPath = filepath.Join(resolvedOutputDir, "export", "tickets-"+strings.TrimSpace(*ticketFormat)+".json")
	}

	now := time.Now().UTC().Truncate(time.Second)
	stages := assessStages{}
	artifacts := assessArtifacts{
		StatePath:            relativeAssessPath(resolvedOutputDir, statePath),
		IdentityManifestPath: relativeAssessPath(resolvedOutputDir, manifest.ResolvePath(statePath)),
		LifecycleChainPath:   relativeAssessPath(resolvedOutputDir, lifecycle.ChainPath(statePath)),
		ProofChainPath:       relativeAssessPath(resolvedOutputDir, proofemit.ChainPath(statePath)),
		ProofAttestationPath: relativeAssessPath(resolvedOutputDir, proofemit.ChainAttestationPath(proofemit.ChainPath(statePath))),
	}

	scanArgs := []string{"scan", "--state", statePath, "--profile", *scanProfile, "--json"}
	if strings.TrimSpace(*pathTarget) != "" {
		scanArgs = append(scanArgs, "--path", strings.TrimSpace(*pathTarget))
	}
	if *mySetup {
		scanArgs = append(scanArgs, "--my-setup")
	}
	for _, target := range explicitTargets {
		if strings.TrimSpace(target) == "" {
			continue
		}
		scanArgs = append(scanArgs, "--target", strings.TrimSpace(target))
	}
	scanCode, _, scanStderr := runAssessStage(ctx, scanArgs)
	if scanCode != exitSuccess {
		return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "scan", scanCode, scanStderr)
	}
	stages.Scan = assessStageStatus{
		Status:   "ok",
		ExitCode: scanCode,
		Artifact: artifacts.StatePath,
	}

	if strings.TrimSpace(*runtimeInput) == "" {
		stages.Ingest = assessStageStatus{Status: "skipped", ExitCode: exitSuccess}
	} else {
		ingestArgs := []string{"ingest", "--state", statePath, "--input", strings.TrimSpace(*runtimeInput), "--json"}
		ingestCode, ingestStdout, ingestStderr := runAssessStage(ctx, ingestArgs)
		if ingestCode != exitSuccess {
			return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "ingest", ingestCode, ingestStderr)
		}
		ingestPayload, decodeErr := decodeAssessPayload(ingestStdout)
		if decodeErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode ingest payload: %v", decodeErr), exitRuntime)
		}
		artifactPath, _ := ingestPayload["artifact_path"].(string)
		artifactKind, _ := ingestPayload["artifact_kind"].(string)
		artifacts.RuntimeArtifactPath = relativeAssessPath(resolvedOutputDir, artifactPath)
		artifacts.RuntimeArtifactKind = artifactKind
		stages.Ingest = assessStageStatus{
			Status:   "ok",
			ExitCode: ingestCode,
			Artifact: artifacts.RuntimeArtifactPath,
			Message:  artifactKind,
		}
	}

	reportArgs := []string{
		"report",
		"--state", statePath,
		"--template", string(template),
		"--share-profile", string(shareProfile),
		"--md", "--md-path", reportMDPath,
		"--evidence-json", "--evidence-json-path", reportEvidenceJSONPath,
		"--csv-backlog", "--csv-backlog-path", backlogCSVPath,
		"--top", strconv.Itoa(*top),
		"--json",
	}
	if strings.TrimSpace(string(pairedShareProfile)) != "" {
		reportArgs = append(reportArgs, "--paired-share-profile", string(pairedShareProfile))
	}
	if strings.TrimSpace(*focusRaw) != "" {
		reportArgs = append(reportArgs, "--focus", strings.TrimSpace(*focusRaw))
	}
	if strings.TrimSpace(*focusPathRaw) != "" {
		reportArgs = append(reportArgs, "--focus-path", strings.TrimSpace(*focusPathRaw))
	}
	if strings.TrimSpace(*baselinePath) != "" {
		reportArgs = append(reportArgs, "--baseline", strings.TrimSpace(*baselinePath))
	}
	reportCode, reportStdout, reportStderr := runAssessStage(ctx, reportArgs)
	if reportCode != exitSuccess {
		return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "report", reportCode, reportStderr)
	}
	reportPayload, decodeErr := decodeAssessPayload(reportStdout)
	if decodeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode report payload: %v", decodeErr), exitRuntime)
	}
	if value, _ := reportPayload["md_path"].(string); value != "" {
		artifacts.ReportMarkdownPath = relativeAssessPath(resolvedOutputDir, value)
	}
	if value, _ := reportPayload["evidence_json_path"].(string); value != "" {
		artifacts.ReportEvidenceJSONPath = relativeAssessPath(resolvedOutputDir, value)
	}
	if value, _ := reportPayload["backlog_csv_path"].(string); value != "" {
		artifacts.BacklogCSVPath = relativeAssessPath(resolvedOutputDir, value)
	}
	if rawPaths, ok := reportPayload["artifact_paths"].(map[string]any); ok {
		pairedPaths := map[string]string{}
		for key, raw := range rawPaths {
			value, _ := raw.(string)
			switch key {
			case "private_join_map":
				artifacts.PrivateJoinMapPath = relativeAssessPath(resolvedOutputDir, value)
			case "markdown", "pdf", "evidence_json", "backlog_csv":
				continue
			default:
				pairedPaths[key] = relativeAssessPath(resolvedOutputDir, value)
			}
		}
		if len(pairedPaths) > 0 {
			artifacts.PairedArtifactPaths = pairedPaths
		}
	}
	stages.Report = assessStageStatus{
		Status:    "ok",
		ExitCode:  reportCode,
		Artifact:  artifacts.ReportMarkdownPath,
		Artifact2: artifacts.ReportEvidenceJSONPath,
	}

	evidenceArgs := []string{
		"evidence",
		"--state", statePath,
		"--frameworks", strings.Join(frameworks, ","),
		"--output", evidenceOutputDir,
		"--json",
	}
	evidenceCode, evidenceStdout, evidenceStderr := runAssessStage(ctx, evidenceArgs)
	if evidenceCode != exitSuccess {
		return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "evidence", evidenceCode, evidenceStderr)
	}
	evidencePayload, decodeErr := decodeAssessPayload(evidenceStdout)
	if decodeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode evidence payload: %v", decodeErr), exitRuntime)
	}
	if value, _ := evidencePayload["output_dir"].(string); value != "" {
		artifacts.EvidenceOutputDir = relativeAssessPath(resolvedOutputDir, value)
	}
	if value, _ := evidencePayload["manifest_path"].(string); value != "" {
		artifacts.EvidenceManifestPath = relativeAssessPath(resolvedOutputDir, value)
	}
	if value, _ := evidencePayload["artifact_manifest_path"].(string); value != "" {
		artifacts.EvidenceArtifactManifest = relativeAssessPath(resolvedOutputDir, value)
	}
	if value, _ := evidencePayload["chain_path"].(string); value != "" {
		artifacts.EvidenceChainPath = relativeAssessPath(resolvedOutputDir, value)
	}
	stages.Evidence = assessStageStatus{
		Status:    "ok",
		ExitCode:  evidenceCode,
		Artifact:  artifacts.EvidenceOutputDir,
		Artifact2: artifacts.EvidenceManifestPath,
	}

	inventoryCode, inventoryStdout, inventoryStderr := runAssessStage(ctx, []string{"export", "--format", "inventory", "--state", statePath, "--json"})
	if inventoryCode != exitSuccess {
		return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "export", inventoryCode, inventoryStderr)
	}
	appendixCode, appendixStdout, appendixStderr := runAssessStage(ctx, []string{"export", "--format", "appendix", "--state", statePath, "--json"})
	if appendixCode != exitSuccess {
		return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "export", appendixCode, appendixStderr)
	}
	inventoryPayload, decodeErr := decodeAssessPayload(inventoryStdout)
	if decodeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode inventory export: %v", decodeErr), exitRuntime)
	}
	appendixPayload, decodeErr := decodeAssessPayload(appendixStdout)
	if decodeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode appendix export: %v", decodeErr), exitRuntime)
	}
	if writeErr := writeAssessJSON(exportInventoryPath, inventoryPayload); writeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
	}
	if writeErr := writeAssessJSON(exportAppendixPath, appendixPayload); writeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
	}
	exportPack := assessExportPack{
		SchemaVersion: "v1",
		GeneratedAt:   now.Format(time.RFC3339),
		Template:      string(template),
		ShareProfile:  string(shareProfile),
		Focus:         strings.TrimSpace(*focusRaw),
		Inventory:     inventoryPayload,
		Appendix:      appendixPayload,
	}
	if writeErr := writeAssessJSON(exportPackPath, exportPack); writeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
	}
	artifacts.ExportInventoryPath = relativeAssessPath(resolvedOutputDir, exportInventoryPath)
	artifacts.ExportAppendixPath = relativeAssessPath(resolvedOutputDir, exportAppendixPath)
	artifacts.ExportPackPath = relativeAssessPath(resolvedOutputDir, exportPackPath)
	stages.Export = assessStageStatus{
		Status:    "ok",
		ExitCode:  exitSuccess,
		Artifact:  artifacts.ExportPackPath,
		Artifact2: artifacts.ExportAppendixPath,
	}

	if strings.TrimSpace(*ticketFormat) == "" {
		stages.Tickets = assessStageStatus{Status: "skipped", ExitCode: exitSuccess}
	} else {
		ticketArgs := []string{"export", "tickets", "--format", strings.TrimSpace(*ticketFormat), "--dry-run", "--state", statePath, "--json"}
		ticketCode, ticketStdout, ticketStderr := runAssessStage(ctx, ticketArgs)
		if ticketCode != exitSuccess {
			return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "tickets", ticketCode, ticketStderr)
		}
		ticketPayload, decodeErr := decodeAssessPayload(ticketStdout)
		if decodeErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode ticket export: %v", decodeErr), exitRuntime)
		}
		if writeErr := writeAssessJSON(ticketPayloadPath, ticketPayload); writeErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
		}
		artifacts.TicketPayloadPath = relativeAssessPath(resolvedOutputDir, ticketPayloadPath)
		stages.Tickets = assessStageStatus{
			Status:   "ok",
			ExitCode: ticketCode,
			Artifact: artifacts.TicketPayloadPath,
		}
	}

	finalExit := exitSuccess
	if strings.TrimSpace(*baselinePath) == "" {
		stages.Regress = assessStageStatus{Status: "skipped", ExitCode: exitSuccess}
	} else {
		regressArgs := []string{
			"regress", "run",
			"--baseline", strings.TrimSpace(*baselinePath),
			"--state", statePath,
			"--summary-md", "--summary-md-path", driftSummaryMDPath,
			"--template", string(template),
			"--share-profile", string(shareProfile),
			"--top", strconv.Itoa(*top),
			"--json",
		}
		regressCode, regressStdout, regressStderr := runAssessStage(ctx, regressArgs)
		if regressCode != exitSuccess && regressCode != exitRegressionDrift {
			return emitAssessStageFailure(stderr, jsonRequested || *jsonOut, "regress", regressCode, regressStderr)
		}
		regressPayload, decodeErr := decodeAssessPayload(regressStdout)
		if decodeErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("decode regress payload: %v", decodeErr), exitRuntime)
		}
		if writeErr := writeAssessJSON(driftJSONPath, regressPayload); writeErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
		}
		artifacts.DriftJSONPath = relativeAssessPath(resolvedOutputDir, driftJSONPath)
		if value, _ := regressPayload["summary_md_path"].(string); value != "" {
			artifacts.DriftSummaryMDPath = relativeAssessPath(resolvedOutputDir, value)
		}
		status := "ok"
		message := "no drift detected"
		if regressCode == exitRegressionDrift {
			status = "drift_detected"
			message = "baseline drift detected"
			finalExit = exitRegressionDrift
		}
		stages.Regress = assessStageStatus{
			Status:    status,
			ExitCode:  regressCode,
			Artifact:  artifacts.DriftJSONPath,
			Artifact2: artifacts.DriftSummaryMDPath,
			Message:   message,
		}
	}

	manifestPayload := assessManifest{
		SchemaVersion: "v1",
		GeneratedAt:   now.Format(time.RFC3339),
		OutputDir:     resolvedOutputDir,
		CommandMetadata: assessCommandMetadata{
			Template:           string(template),
			ShareProfile:       string(shareProfile),
			PairedShareProfile: strings.TrimSpace(string(pairedShareProfile)),
			Focus:              strings.TrimSpace(*focusRaw),
			FocusPath:          strings.TrimSpace(*focusPathRaw),
			Frameworks:         frameworks,
			Baseline:           strings.TrimSpace(*baselinePath),
			RuntimeInput:       strings.TrimSpace(*runtimeInput),
			TicketFormat:       strings.TrimSpace(*ticketFormat),
			Targets:            targetLabels,
			Profile:            strings.TrimSpace(*scanProfile),
		},
		Stages:    stages,
		Artifacts: artifacts,
	}
	manifestPath := filepath.Join(resolvedOutputDir, "assessment-manifest.json")
	if writeErr := writeAssessJSON(manifestPath, manifestPayload); writeErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
	}

	if *jsonOut {
		status := "ok"
		if finalExit == exitRegressionDrift {
			status = "drift_detected"
		}
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":        status,
			"output_dir":    resolvedOutputDir,
			"manifest_path": manifestPath,
			"stages":        stages,
			"artifacts":     artifacts,
		})
		return finalExit
	}
	if *quiet {
		return finalExit
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr assess template=%s share_profile=%s output_dir=%s\n", template, shareProfile, resolvedOutputDir)
		_, _ = fmt.Fprintf(stdout, "scan: %s\n", stages.Scan.Artifact)
		_, _ = fmt.Fprintf(stdout, "report: %s\n", artifacts.ReportMarkdownPath)
		_, _ = fmt.Fprintf(stdout, "evidence: %s\n", artifacts.EvidenceOutputDir)
		_, _ = fmt.Fprintf(stdout, "export pack: %s\n", artifacts.ExportPackPath)
		if artifacts.DriftJSONPath != "" {
			_, _ = fmt.Fprintf(stdout, "drift: %s (%s)\n", artifacts.DriftJSONPath, stages.Regress.Status)
		}
		return finalExit
	}
	_, _ = fmt.Fprintln(stdout, "wrkr assess complete")
	return finalExit
}

func writeAssessUsage(out io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprintln(out, "Usage of assess:")
	_, _ = fmt.Fprintln(out, "  wrkr assess [flags]")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Behavior contract:")
	_, _ = fmt.Fprintln(out, "  wrkr assess orchestrates scan, optional ingest, report, evidence, export, and optional regress into one deterministic output directory.")
	_, _ = fmt.Fprintln(out, "  Stage failures return the underlying stage exit code and do not publish an assessment manifest.")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Flags:")
	fs.PrintDefaults()
}

func runAssessStage(ctx context.Context, args []string) (int, []byte, []byte) {
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := RunWithContext(ctx, args, &out, &errOut)
	return code, out.Bytes(), errOut.Bytes()
}

func decodeAssessPayload(payload []byte) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func writeAssessJSON(path string, payload any) error {
	resolvedPath, err := resolveArtifactOutputPath(path)
	if err != nil {
		return fmt.Errorf("resolve artifact %s: %w", path, err)
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal artifact %s: %w", path, err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(resolvedPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write artifact %s: %w", resolvedPath, err)
	}
	return nil
}

func emitAssessStageFailure(stderr io.Writer, jsonOut bool, stage string, exitCode int, stageStderr []byte) int {
	message := strings.TrimSpace(string(stageStderr))
	if decoded, err := decodeAssessPayload(stageStderr); err == nil {
		if errPayload, ok := decoded["error"].(map[string]any); ok {
			if value, _ := errPayload["message"].(string); strings.TrimSpace(value) != "" {
				message = strings.TrimSpace(value)
			}
		}
	}
	if message == "" {
		message = fmt.Sprintf("%s failed", stage)
	}
	return emitError(stderr, jsonOut, "runtime_failure", fmt.Sprintf("assess %s failed: %s", stage, message), exitCode)
}

func relativeAssessPath(root string, path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	absRoot, rootErr := filepath.Abs(root)
	absPath, pathErr := filepath.Abs(trimmed)
	if rootErr == nil && pathErr == nil {
		rel, err := filepath.Rel(absRoot, absPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.Clean(trimmed)
}

func assessTargetLabels(pathTarget string, mySetup bool, explicitTargets []string) []string {
	out := []string{}
	if pathTarget != "" {
		out = append(out, "path:"+pathTarget)
	}
	if mySetup {
		out = append(out, "my-setup")
	}
	for _, target := range explicitTargets {
		trimmed := strings.TrimSpace(target)
		if trimmed == "" {
			continue
		}
		out = append(out, "target:"+trimmed)
	}
	return out
}
