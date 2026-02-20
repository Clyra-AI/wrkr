package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	profilemodel "github.com/Clyra-AI/wrkr/core/policy/profile"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runScore(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("score", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	snapshot, err := state.Load(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	result := snapshot.PostureScore
	if result == nil {
		profileDef, profileErr := profilemodel.Builtin("standard")
		if profileErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", profileErr.Error(), exitRuntime)
		}
		profileResult := profileeval.Evaluate(profileDef, snapshot.Findings, nil)
		computed := score.Compute(score.Input{
			Findings:        snapshot.Findings,
			Identities:      snapshot.Identities,
			ProfileResult:   profileResult,
			TransitionCount: len(snapshot.Transitions),
			Weights:         scoremodel.DefaultWeights(),
		})
		result = &computed
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr score %.2f (%s)\n", result.Score, result.Grade)
	return exitSuccess
}
