package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/manifestgen"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runManifest(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "manifest subcommand is required", exitInvalidInput)
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stderr, "Usage of wrkr manifest: manifest <generate> [flags]")
		return exitSuccess
	}

	switch args[0] {
	case "generate":
		return runManifestGenerate(args[1:], stdout, stderr)
	default:
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "unsupported manifest subcommand", exitInvalidInput)
	}
}

func runManifestGenerate(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("manifest generate", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	outputPath := fs.String("output", "", "manifest output path override")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "manifest generate does not accept positional arguments", exitInvalidInput)
	}

	statePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(statePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	now := time.Now().UTC().Truncate(time.Second)
	generated, err := manifestgen.GenerateUnderReview(snapshot, now)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	path := strings.TrimSpace(*outputPath)
	if path == "" {
		path = manifest.ResolvePath(statePath)
	}
	if err := manifest.Save(path, generated); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	resolvedPath := filepath.Clean(path)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":         "ok",
			"manifest_path":  resolvedPath,
			"identity_count": len(generated.Identities),
		})
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr manifest generated %s (%d identities)\n", resolvedPath, len(generated.Identities))
	return exitSuccess
}
