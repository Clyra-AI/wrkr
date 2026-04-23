package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	exportinventory "github.com/Clyra-AI/wrkr/core/export/inventory"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runInventory(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "approve", "attach-evidence", "accept-risk", "deprecate", "exclude":
			return runInventoryMutation(strings.ReplaceAll(args[0], "-", "_"), args[1:], stdout, stderr)
		}
	}
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	diffMode := fs.Bool("diff", false, "compare current scan state against a baseline scan state")
	baselinePath := fs.String("baseline", "", "baseline scan state path (default .wrkr/inventory-baseline.json beside --state)")
	statePathFlag := fs.String("state", "", "state file path override")
	anonymize := fs.Bool("anonymize", false, "anonymize org/repo/identity fields in inventory export output")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "inventory does not accept positional arguments", exitInvalidInput)
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	if *diffMode {
		resolvedBaseline := resolveInventoryBaselinePath(strings.TrimSpace(*baselinePath), resolvedStatePath)
		baseline, loadErr := loadInventoryBaseline(resolvedBaseline)
		if loadErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", loadErr.Error(), exitInvalidInput)
		}
		result := regress.CompareInventory(baseline, snapshot)
		result.BaselinePath = filepath.Clean(resolvedBaseline)
		if *jsonOut {
			_ = json.NewEncoder(stdout).Encode(result)
			if result.Drift {
				return exitRegressionDrift
			}
			return exitSuccess
		}
		if result.Drift {
			_, _ = fmt.Fprintf(stdout, "wrkr inventory drift added=%d removed=%d changed=%d\n", result.AddedCount, result.RemovedCount, result.ChangedCount)
			return exitRegressionDrift
		}
		_, _ = fmt.Fprintln(stdout, "wrkr inventory no drift")
		return exitSuccess
	}

	inv := snapshot.Inventory
	if inv == nil {
		empty := agginventory.Inventory{Org: "local", Tools: []agginventory.Tool{}}
		inv = &empty
	}
	payload := exportinventory.BuildWithOptions(*inv, report.ResolveGeneratedAtForCLI(snapshot, time.Time{}), exportinventory.BuildOptions{
		Anonymize: *anonymize,
	})
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr inventory %d tools %d agents\n", len(payload.Tools), len(payload.Agents))
	return exitSuccess
}

func resolveInventoryBaselinePath(rawBaseline, resolvedStatePath string) string {
	if strings.TrimSpace(rawBaseline) != "" {
		return strings.TrimSpace(rawBaseline)
	}
	return filepath.Join(filepath.Dir(resolvedStatePath), "inventory-baseline.json")
}

func loadInventoryBaseline(path string) (state.Snapshot, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return state.Snapshot{}, fmt.Errorf("inventory baseline not found: %s", filepath.Clean(path))
		}
		return state.Snapshot{}, fmt.Errorf("inventory baseline unreadable: %s", filepath.Clean(path))
	}
	snapshot, err := state.Load(path)
	if err != nil {
		return state.Snapshot{}, fmt.Errorf("inventory baseline must be a wrkr scan state snapshot: %v", err)
	}
	return snapshot, nil
}
