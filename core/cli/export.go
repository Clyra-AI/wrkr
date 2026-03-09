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
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runExport(args []string, stdout io.Writer, stderr io.Writer) int {
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
