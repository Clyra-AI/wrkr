package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	exportinventory "github.com/Clyra-AI/wrkr/core/export/inventory"
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

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if *format != "inventory" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "unsupported export format", exitInvalidInput)
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
	payload := exportinventory.Build(*inv, time.Now().UTC().Truncate(time.Second))

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, "wrkr export complete")
	return exitSuccess
}
