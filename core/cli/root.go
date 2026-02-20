package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	exitSuccess           = 0
	exitRuntime           = 1
	exitPolicyViolation   = 3
	exitApprovalRequired  = 4
	exitRegressionDrift   = 5
	exitInvalidInput      = 6
	exitDependencyMissing = 7
	exitUnsafeBlocked     = 8
)

// Run executes the wrkr CLI root command and returns a stable process exit code.
func Run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stdout, "wrkr")
		return exitSuccess
	}

	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "report":
		return runReport(args[1:], stdout, stderr)
	case "export":
		return runExport(args[1:], stdout, stderr)
	case "identity":
		return runIdentity(args[1:], stdout, stderr)
	case "lifecycle":
		return runLifecycle(args[1:], stdout, stderr)
	case "score":
		return runScore(args[1:], stdout, stderr)
	}

	return runRootFlags(args, stdout, stderr)
}

func runRootFlags(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)

	fs := flag.NewFlagSet("wrkr", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	explain := fs.Bool("explain", false, "emit human-readable rationale")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":  "ok",
			"message": "wrkr scaffold ready",
		})
		return exitSuccess
	}

	if *quiet {
		return exitSuccess
	}

	if *explain {
		_, _ = fmt.Fprintln(stdout, "wrkr root command succeeded")
		return exitSuccess
	}

	_, _ = fmt.Fprintln(stdout, "wrkr")
	return exitSuccess
}

func emitError(stderr io.Writer, jsonOut bool, code, message string, exitCode int) int {
	if jsonOut {
		_ = json.NewEncoder(stderr).Encode(map[string]any{
			"error": map[string]any{
				"code":      code,
				"message":   message,
				"exit_code": exitCode,
			},
		})
	} else {
		_, _ = fmt.Fprintln(stderr, message)
	}
	return exitCode
}

func wantsJSONOutput(args []string) bool {
	for _, arg := range args {
		if arg == "--json" {
			return true
		}
		if strings.HasPrefix(arg, "--json=") {
			value := strings.TrimPrefix(arg, "--json=")
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return true
			}
			return parsed
		}
	}
	return false
}
