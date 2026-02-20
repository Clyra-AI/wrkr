package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runLifecycle(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	orgFilter := fs.String("org", "", "filter by org")
	statePathFlag := fs.String("state", "", "state file path override")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	loaded, err := manifest.Load(manifest.ResolvePath(state.ResolvePath(*statePathFlag)))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	identities := make([]manifest.IdentityRecord, 0, len(loaded.Identities))
	for _, item := range loaded.Identities {
		if strings.TrimSpace(*orgFilter) != "" && item.Org != strings.TrimSpace(*orgFilter) {
			continue
		}
		identities = append(identities, item)
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].AgentID < identities[j].AgentID })

	payload := map[string]any{
		"status":     "ok",
		"updated_at": loaded.UpdatedAt,
		"org":        strings.TrimSpace(*orgFilter),
		"identities": identities,
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr lifecycle identities=%d\n", len(identities))
	return exitSuccess
}
