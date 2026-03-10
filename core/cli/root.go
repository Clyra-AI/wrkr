package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
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
	return RunWithContext(context.Background(), args, stdout, stderr)
}

// RunWithContext executes the wrkr CLI root command with a caller-provided context.
func RunWithContext(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stdout, "wrkr")
		return exitSuccess
	}

	if code, handled := runKnownSubcommand(ctx, args[0], args[1:], stdout, stderr); handled {
		return code
	}

	if !strings.HasPrefix(args[0], "-") {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", fmt.Sprintf("unsupported command %q", args[0]), exitInvalidInput)
	}

	return runRootFlags(args, stdout, stderr)
}

func runKnownSubcommand(ctx context.Context, name string, args []string, stdout io.Writer, stderr io.Writer) (int, bool) {
	switch name {
	case "init":
		return runInit(args, stdout, stderr), true
	case "scan":
		return runScanWithContext(ctx, args, stdout, stderr), true
	case "action":
		return runAction(args, stdout, stderr), true
	case "report":
		return runReport(args, stdout, stderr), true
	case "campaign":
		return runCampaign(args, stdout, stderr), true
	case "mcp-list":
		return runMCPList(args, stdout, stderr), true
	case "export":
		return runExport(args, stdout, stderr), true
	case "inventory":
		return runInventory(args, stdout, stderr), true
	case "identity":
		return runIdentity(args, stdout, stderr), true
	case "lifecycle":
		return runLifecycle(args, stdout, stderr), true
	case "manifest":
		return runManifest(args, stdout, stderr), true
	case "regress":
		return runRegress(args, stdout, stderr), true
	case "score":
		return runScore(args, stdout, stderr), true
	case "verify":
		return runVerify(args, stdout, stderr), true
	case "evidence":
		return runEvidence(args, stdout, stderr), true
	case "fix":
		return runFix(args, stdout, stderr), true
	case "version":
		return runVersion(args, stdout, stderr), true
	case "help":
		return runHelp(ctx, args, stdout, stderr), true
	default:
		return 0, false
	}
}

func runHelp(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 || isHelpFlag(args[0]) {
		return runRootFlags([]string{"--help"}, stdout, stderr)
	}

	helpArgs := append(append([]string{}, args[1:]...), "--help")
	if code, handled := runKnownSubcommand(ctx, args[0], helpArgs, stdout, stderr); handled {
		return code
	}

	return emitError(stderr, wantsJSONOutput(args), "invalid_input", fmt.Sprintf("unsupported command %q", args[0]), exitInvalidInput)
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
	version := fs.Bool("version", false, "print wrkr version")
	fs.Usage = func() {
		writeRootUsage(fs.Output(), fs)
	}

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("unsupported command %q", fs.Arg(0)), exitInvalidInput)
	}
	if *quiet && *explain && !*jsonOut {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--quiet and --explain cannot be used together", exitInvalidInput)
	}
	if *version {
		return emitVersion(stdout, jsonRequested || *jsonOut, *jsonOut)
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

func writeRootUsage(out io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprintln(out, "Usage of wrkr:")
	_, _ = fmt.Fprintln(out, "  wrkr <command> [flags]")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Commands:")
	_, _ = fmt.Fprintln(out, "  init       initialize wrkr configuration")
	_, _ = fmt.Fprintln(out, "  scan       discover tools and emit inventory/risk state")
	_, _ = fmt.Fprintln(out, "  action     evaluate and gate automation actions")
	_, _ = fmt.Fprintln(out, "  report     generate posture summaries")
	_, _ = fmt.Fprintln(out, "  campaign   aggregate multi-org posture snapshots")
	_, _ = fmt.Fprintln(out, "  mcp-list   list MCP servers with trust and privilege posture")
	_, _ = fmt.Fprintln(out, "  export     emit inventory/appendix exports")
	_, _ = fmt.Fprintln(out, "  inventory  emit inventory export or deterministic inventory drift")
	_, _ = fmt.Fprintln(out, "  identity   manage deterministic identity lifecycle state")
	_, _ = fmt.Fprintln(out, "  lifecycle  view lifecycle transitions and posture")
	_, _ = fmt.Fprintln(out, "  manifest   generate identity manifest baselines")
	_, _ = fmt.Fprintln(out, "  regress    compare current state to a baseline")
	_, _ = fmt.Fprintln(out, "  score      compute posture score and breakdown")
	_, _ = fmt.Fprintln(out, "  verify     verify proof chain integrity")
	_, _ = fmt.Fprintln(out, "  evidence   build compliance-ready evidence bundles")
	_, _ = fmt.Fprintln(out, "  fix        plan deterministic remediations (repo writes require --open-pr)")
	_, _ = fmt.Fprintln(out, "  version    print wrkr version")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Examples:")
	_, _ = fmt.Fprintln(out, "  wrkr scan --my-setup --json")
	_, _ = fmt.Fprintln(out, "  wrkr mcp-list --state ./.wrkr/last-scan.json --json")
	_, _ = fmt.Fprintln(out, "  wrkr scan --github-org acme --github-api https://api.github.com --json")
	_, _ = fmt.Fprintln(out, "  wrkr inventory --diff --baseline ./.wrkr/inventory-baseline.json --json")
	_, _ = fmt.Fprintln(out, "  wrkr score --json")
	_, _ = fmt.Fprintln(out, "  wrkr evidence --frameworks soc2 --json")
	_, _ = fmt.Fprintln(out, "  wrkr verify --chain --json")
	_, _ = fmt.Fprintln(out, "  wrkr regress run --baseline baseline.json --json")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Global flags:")
	fs.PrintDefaults()
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
