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
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	explain := fs.Bool("explain", false, "emit rationale details")
	statePathFlag := fs.String("state", "", "state file path override")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if *quiet && *explain && !*jsonOut {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--quiet and --explain cannot be used together", exitInvalidInput)
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
	if *quiet {
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr score %.2f (%s) trend=%+.2f\n", result.Score, result.Grade, result.TrendDelta)
		_, _ = fmt.Fprintf(stdout, "policy_pass_rate=%.2f approval_coverage=%.2f severity_distribution=%.2f profile_compliance=%.2f drift_rate=%.2f\n",
			result.Breakdown.PolicyPassRate,
			result.Breakdown.ApprovalCoverage,
			result.Breakdown.SeverityDistribution,
			result.Breakdown.ProfileCompliance,
			result.Breakdown.DriftRate,
		)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr score %.2f (%s)\n", result.Score, result.Grade)
	return exitSuccess
}
