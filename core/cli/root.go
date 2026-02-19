package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

// Run executes the wrkr CLI root command and returns a stable process exit code.
func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("wrkr", flag.ContinueOnError)
	fs.SetOutput(stderr)

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	explain := fs.Bool("explain", false, "emit human-readable rationale")

	if err := fs.Parse(args); err != nil {
		if *jsonOut {
			_ = json.NewEncoder(stderr).Encode(map[string]any{
				"error": map[string]any{
					"code":    "invalid_input",
					"message": err.Error(),
				},
			})
		}
		return 6
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":  "ok",
			"message": "wrkr scaffold ready",
		})
		return 0
	}

	if *quiet {
		return 0
	}

	if *explain {
		_, _ = fmt.Fprintln(stdout, "wrkr scaffold command succeeded")
		return 0
	}

	_, _ = fmt.Fprintln(stdout, "wrkr")
	return 0
}
