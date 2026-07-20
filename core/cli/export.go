package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	exportactioncontracts "github.com/Clyra-AI/wrkr/core/export/actioncontracts"
	exportappendix "github.com/Clyra-AI/wrkr/core/export/appendix"
	exportinventory "github.com/Clyra-AI/wrkr/core/export/inventory"
	exporttickets "github.com/Clyra-AI/wrkr/core/export/tickets"
	"github.com/Clyra-AI/wrkr/core/manifest"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func runExport(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "action-contracts" {
		return runExportActionContracts(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "tickets" {
		return runExportTickets(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "declarations" {
		return runExportDeclarations(args[1:], stdout, stderr)
	}
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	format := fs.String("format", "inventory", "export format")
	statePathFlag := fs.String("state", "", "state file path override")
	anonymize := fs.Bool("anonymize", false, "anonymize org/repo/identity fields for publication-safe exports")
	csvDir := fs.String("csv-dir", "", "optional csv output directory (appendix format only)")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if code, handled := rejectIncompleteSavedState(stderr, jsonRequested || *jsonOut, resolvedStatePath, snapshot); handled {
		return code
	}
	inv := snapshot.Inventory
	if inv == nil {
		empty := agginventory.Inventory{Org: "local", Tools: []agginventory.Tool{}}
		inv = &empty
	}

	now := reportcore.ResolveGeneratedAtForCLI(snapshot, time.Time{})
	switch *format {
	case "inventory":
		if *csvDir != "" {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--csv-dir is only supported with --format appendix", exitInvalidInput)
		}
		payload := exportinventory.BuildWithOptions(*inv, now, exportinventory.BuildOptions{
			Anonymize: *anonymize,
		})
		if *jsonOut {
			_ = json.NewEncoder(stdout).Encode(payload)
			return exitSuccess
		}
		_, _ = fmt.Fprintln(stdout, "wrkr export complete")
		return exitSuccess
	case "appendix":
		appendixPayload := exportappendix.BuildWithOptions(*inv, now, exportappendix.BuildOptions{
			Anonymize: *anonymize,
		})
		envelope := map[string]any{
			"status":   "ok",
			"appendix": appendixPayload,
		}
		if *csvDir != "" {
			paths, writeErr := exportappendix.WriteCSV(appendixPayload, *csvDir)
			if writeErr != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
			}
			envelope["csv_files"] = paths
		}
		if *jsonOut {
			_ = json.NewEncoder(stdout).Encode(envelope)
			return exitSuccess
		}
		_, _ = fmt.Fprintln(stdout, "wrkr export complete")
		return exitSuccess
	default:
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "unsupported export format", exitInvalidInput)
	}
}

func runExportActionContracts(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("export action-contracts", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable export collection")
	statePathFlag := fs.String("state", "", "state file path override")
	contractID := fs.String("contract-id", "", "proposed Action Contract ID selector")
	outputDir := fs.String("output-dir", "", "optional directory for atomic artifact files")
	shareProfileRaw := fs.String("share-profile", string(reportcore.ShareProfileInternal), "share profile [internal|public|customer-redacted|design-partner|external-redacted|investor-safe]")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "export action-contracts does not accept positional arguments", exitInvalidInput)
	}
	profile, ok := reportcore.ParseShareProfile(strings.TrimSpace(*shareProfileRaw))
	if !ok {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--share-profile must be one of internal|public|customer-redacted|design-partner|external-redacted|investor-safe", exitInvalidInput)
	}
	if !*jsonOut && strings.TrimSpace(*outputDir) == "" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "export action-contracts requires --json or --output-dir", exitInvalidInput)
	}
	resolvedStatePath, err := preflightTrustedStatePath(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	}
	if err := preflightManagedArtifactRead(resolvedStatePath); err != nil {
		if isUnsafeManagedArtifactPathError(err) {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
		}
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if code, handled := rejectIncompleteSavedState(stderr, jsonRequested || *jsonOut, resolvedStatePath, snapshot); handled {
		return code
	}
	collection, err := exportactioncontracts.Build(snapshot, exportactioncontracts.BuildOptions{
		ShareProfile: profile,
		ContractID:   strings.TrimSpace(*contractID),
	})
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	written := []string(nil)
	if strings.TrimSpace(*outputDir) != "" {
		written, err = exportactioncontracts.Write(collection, strings.TrimSpace(*outputDir))
		if err != nil {
			if strings.Contains(err.Error(), "symlink") || strings.Contains(err.Error(), "collision") || strings.Contains(err.Error(), "unsafe") {
				return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
			}
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(struct {
			Status      string                           `json:"status"`
			Collection  exportactioncontracts.Collection `json:"collection"`
			OutputFiles []string                         `json:"output_files,omitempty"`
		}{Status: "ok", Collection: collection, OutputFiles: written})
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr export action-contracts complete (%d artifacts)\n", len(collection.Artifacts))
	return exitSuccess
}

func runExportTickets(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("export tickets", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	format := fs.String("format", "jira", "ticket payload format [jira|github|servicenow]")
	top := fs.Int("top", 10, "number of top backlog items to export")
	dryRun := fs.Bool("dry-run", false, "emit local payloads without network calls")
	statePathFlag := fs.String("state", "", "state file path override")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "export tickets does not accept positional arguments", exitInvalidInput)
	}
	if !*dryRun {
		return emitError(stderr, jsonRequested || *jsonOut, "dependency_missing", "ticket sending is not implemented; use --dry-run for offline payload generation", exitDependencyMissing)
	}
	if !exporttickets.ValidFormat(*format) {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--format must be one of jira|github|servicenow", exitInvalidInput)
	}
	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if code, handled := rejectIncompleteSavedState(stderr, jsonRequested || *jsonOut, resolvedStatePath, snapshot); handled {
		return code
	}
	if snapshot.ControlBacklog == nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "saved state does not contain control_backlog", exitInvalidInput)
	}
	payload := exporttickets.Build(snapshot.ControlBacklog, *format, *top)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, "wrkr export tickets complete")
	return exitSuccess
}

type declarationExportPayload struct {
	Status       string                        `json:"status"`
	ShareProfile string                        `json:"share_profile"`
	Selection    map[string]string             `json:"selection"`
	Snippet      reportcore.DeclarationSnippet `json:"snippet"`
	PatchPath    string                        `json:"patch_path,omitempty"`
}

func runExportDeclarations(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("export declarations", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	shareProfileRaw := fs.String("share-profile", string(reportcore.ShareProfileInternal), "share profile [internal|public|customer-redacted|design-partner|external-redacted|investor-safe]")
	pathID := fs.String("path-id", "", "agent-action-bom path_id selector")
	backlogID := fs.String("backlog-id", "", "control backlog item id selector")
	resolutionKey := fs.String("resolution-key", "", "stable resolution_key selector")
	actionType := fs.String("action", "", "declaration-capable closure action to export")
	mode := fs.String("mode", reportcore.DeclarationExportModeRepoLocal, "declaration target mode [repo_local|governance_repo]")
	patchPath := fs.String("patch-path", "", "optional output path for a declaration patch artifact")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "export declarations does not accept positional arguments", exitInvalidInput)
	}

	selectorCount := 0
	for _, value := range []string{strings.TrimSpace(*pathID), strings.TrimSpace(*backlogID), strings.TrimSpace(*resolutionKey)} {
		if value != "" {
			selectorCount++
		}
	}
	if selectorCount != 1 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "export declarations requires exactly one of --path-id, --backlog-id, or --resolution-key", exitInvalidInput)
	}
	if strings.TrimSpace(*mode) != reportcore.DeclarationExportModeRepoLocal && strings.TrimSpace(*mode) != reportcore.DeclarationExportModeGovernanceRepo {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--mode must be repo_local or governance_repo", exitInvalidInput)
	}
	shareProfile, ok := reportcore.ParseShareProfile(strings.TrimSpace(*shareProfileRaw))
	if !ok {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--share-profile must be one of internal|public|customer-redacted|design-partner|external-redacted|investor-safe", exitInvalidInput)
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	if err := preflightManagedArtifactRead(resolvedStatePath); err != nil {
		if isUnsafeManagedArtifactPathError(err) {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
		}
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	if code, handled := rejectIncompleteSavedState(stderr, jsonRequested || *jsonOut, resolvedStatePath, snapshot); handled {
		return code
	}

	var loadedManifest *manifest.Manifest
	manifestPath := manifest.ResolvePath(resolvedStatePath)
	if m, loadErr := manifest.Load(manifestPath); loadErr == nil {
		loadedManifest = &m
	}

	summary, err := buildExportDeclarationSummary(resolvedStatePath, snapshot, loadedManifest, shareProfile)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	generatedAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(summary.GeneratedAt))
	snippet, selection, err := buildDeclarationSnippetForSelection(summary, shareProfile, strings.TrimSpace(*pathID), strings.TrimSpace(*backlogID), strings.TrimSpace(*resolutionKey), strings.TrimSpace(*actionType), strings.TrimSpace(*mode), generatedAt)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	writtenPatchPath := ""
	if strings.TrimSpace(*patchPath) != "" {
		resolvedPatchPath, pathErr := normalizeManagedArtifactPath(strings.TrimSpace(*patchPath))
		if pathErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", pathErr.Error(), exitInvalidInput)
		}
		if err := rejectUnsafeExistingManagedFile(resolvedPatchPath, "declaration patch"); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
		}
		if err := atomicwrite.WriteFileFunc(resolvedPatchPath, 0o600, func(w io.Writer) error {
			_, writeErr := io.WriteString(w, snippet.Content)
			return writeErr
		}); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
		writtenPatchPath = resolvedPatchPath
	}

	payload := declarationExportPayload{
		Status:       "ok",
		ShareProfile: string(shareProfile),
		Selection:    selection,
		Snippet:      snippet,
		PatchPath:    writtenPatchPath,
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if writtenPatchPath != "" {
		_, _ = fmt.Fprintf(stdout, "wrkr export declarations complete: %s\n", writtenPatchPath)
		return exitSuccess
	}
	_, _ = io.WriteString(stdout, snippet.Content)
	return exitSuccess
}

func buildExportDeclarationSummary(statePath string, snapshot state.Snapshot, loadedManifest *manifest.Manifest, shareProfile reportcore.ShareProfile) (reportcore.Summary, error) {
	summary, err := reportcore.BuildSummary(reportcore.BuildInput{
		StatePath:    statePath,
		Snapshot:     snapshot,
		Manifest:     loadedManifest,
		Top:          10,
		Template:     reportcore.TemplateAgentActionBOM,
		ShareProfile: shareProfile,
	})
	if err != nil {
		return reportcore.Summary{}, err
	}
	summary = reportcore.FinalizeSummaryForSerialization(summary)
	summary, err = reportcore.ApplyShareableResidualRedaction(snapshot, summary)
	if err != nil {
		return reportcore.Summary{}, err
	}
	return summary, nil
}

func buildDeclarationSnippetForSelection(summary reportcore.Summary, shareProfile reportcore.ShareProfile, pathID string, backlogID string, resolutionKey string, actionType string, mode string, generatedAt time.Time) (reportcore.DeclarationSnippet, map[string]string, error) {
	if summary.AgentActionBOM != nil {
		for _, item := range summary.AgentActionBOM.Items {
			if pathID != "" && strings.TrimSpace(item.PathID) == pathID {
				snippet, err := reportcore.BuildDeclarationSnippetFromBOM(item, shareProfile, actionType, mode, generatedAt)
				return snippet, map[string]string{"path_id": pathID}, err
			}
			if resolutionKey != "" && strings.TrimSpace(item.ResolutionKey) == resolutionKey {
				snippet, err := reportcore.BuildDeclarationSnippetFromBOM(item, shareProfile, actionType, mode, generatedAt)
				return snippet, map[string]string{"resolution_key": resolutionKey, "path_id": strings.TrimSpace(item.PathID)}, err
			}
		}
	}
	if summary.ControlBacklog != nil {
		for _, item := range summary.ControlBacklog.Items {
			if backlogID != "" && strings.TrimSpace(item.ID) == backlogID {
				snippet, err := reportcore.BuildDeclarationSnippetFromBacklog(item, shareProfile, actionType, mode, generatedAt)
				return snippet, map[string]string{"backlog_id": backlogID, "resolution_key": strings.TrimSpace(item.ResolutionKey)}, err
			}
			if resolutionKey != "" && strings.TrimSpace(item.ResolutionKey) == resolutionKey {
				snippet, err := reportcore.BuildDeclarationSnippetFromBacklog(item, shareProfile, actionType, mode, generatedAt)
				return snippet, map[string]string{"resolution_key": resolutionKey, "backlog_id": strings.TrimSpace(item.ID)}, err
			}
		}
	}
	if pathID != "" {
		return reportcore.DeclarationSnippet{}, nil, fmt.Errorf("path_id %q was not found in the current agent_action_bom", pathID)
	}
	if backlogID != "" {
		return reportcore.DeclarationSnippet{}, nil, fmt.Errorf("backlog_id %q was not found in the current control_backlog", backlogID)
	}
	return reportcore.DeclarationSnippet{}, nil, fmt.Errorf("resolution_key %q was not found in the current agent_action_bom or control_backlog", resolutionKey)
}
