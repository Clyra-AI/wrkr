package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"runtime/debug"
	"strings"
)

func runVersion(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)

	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("unsupported argument %q", fs.Arg(0)), exitInvalidInput)
	}
	return emitVersion(stdout, jsonRequested || *jsonOut, *jsonOut)
}

func emitVersion(stdout io.Writer, jsonRequested bool, jsonOut bool) int {
	version := wrkrVersion()
	if jsonRequested || jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":  "ok",
			"version": version,
		})
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr %s\n", version)
	return exitSuccess
}

func wrkrVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	version := strings.TrimSpace(info.Main.Version)
	if version == "" || version == "(devel)" {
		return "devel"
	}
	return version
}
