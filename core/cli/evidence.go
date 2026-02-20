package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/evidence"
)

func runEvidence(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("evidence", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	frameworksRaw := fs.String("frameworks", "", "comma-separated framework ids")
	outputDir := fs.String("output", "wrkr-evidence", "evidence output directory")
	statePathFlag := fs.String("state", "", "state file path override")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "evidence does not accept positional arguments", exitInvalidInput)
	}
	frameworks := parseFrameworkFlags(*frameworksRaw)
	if len(frameworks) == 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--frameworks is required", exitInvalidInput)
	}

	result, err := evidence.Build(evidence.BuildInput{
		StatePath:   *statePathFlag,
		Frameworks:  frameworks,
		OutputDir:   strings.TrimSpace(*outputDir),
		GeneratedAt: time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":             "ok",
			"output_dir":         result.OutputDir,
			"frameworks":         result.Frameworks,
			"manifest_path":      result.ManifestPath,
			"chain_path":         result.ChainPath,
			"framework_coverage": result.FrameworkCoverage,
		})
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr evidence bundle written to %s\n", result.OutputDir)
	return exitSuccess
}

func parseFrameworkFlags(raw string) []string {
	set := map[string]struct{}{}
	for _, part := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	// deterministic ordering in output and downstream evidence writes.
	sort.Strings(out)
	return out
}
