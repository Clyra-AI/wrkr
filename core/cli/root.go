package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	exitSuccess           = 0
	exitRuntime           = 1
	exitVerification      = 2
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
	case "manifest":
		return runManifest(args[1:], stdout, stderr)
	case "regress":
		return runRegress(args[1:], stdout, stderr)
	case "score":
		return runScore(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "evidence":
		return runEvidence(args[1:], stdout, stderr)
	case "fix":
		return runFix(args[1:], stdout, stderr)
	}

	if !strings.HasPrefix(args[0], "-") {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", fmt.Sprintf("unsupported command %q", args[0]), exitInvalidInput)
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

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("unsupported command %q", fs.Arg(0)), exitInvalidInput)
	}
	if *quiet && *explain && !*jsonOut {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--quiet and --explain cannot be used together", exitInvalidInput)
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

func parseFlags(fs *flag.FlagSet, args []string, stderr io.Writer, jsonOut bool) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSuccess, true
		}
		return emitError(stderr, jsonOut, "invalid_input", err.Error(), exitInvalidInput), true
	}
	return 0, false
}

func isHelpFlag(arg string) bool {
	return arg == "-h" || arg == "--help"
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
