package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	exportappendix "github.com/Clyra-AI/wrkr/core/export/appendix"
	exportinventory "github.com/Clyra-AI/wrkr/core/export/inventory"
	exporttickets "github.com/Clyra-AI/wrkr/core/export/tickets"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runExport(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "tickets" {
		return runExportTickets(args[1:], stdout, stderr)
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

	snapshot, err := state.Load(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
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
	snapshot, err := state.Load(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
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
