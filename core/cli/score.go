package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/Clyra-AI/wrkr/core/model"
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

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.LoadScoreView(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	result := snapshot.PostureScore
	var attackPaths any
	var topAttackPaths any
	if len(snapshot.AttackPaths) != 0 {
		attackPaths = snapshot.AttackPaths
	}
	if len(snapshot.TopAttackPaths) != 0 {
		topAttackPaths = snapshot.TopAttackPaths
	}
	if result == nil {
		profileDef, profileErr := profilemodel.Builtin("standard")
		if profileErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", profileErr.Error(), exitRuntime)
		}
		profileResult := profileeval.Evaluate(profileDef, snapshot.Findings, nil)
		identities := model.FilterLegacyArtifactIdentityRecords(snapshot.Identities)
		computed := score.Compute(score.Input{
			Findings:        snapshot.Findings,
			Identities:      identities,
			ProfileResult:   profileResult,
			TransitionCount: snapshot.TransitionCount,
			Weights:         scoremodel.DefaultWeights(),
		})
		result = &computed
	}

	if *jsonOut {
		payload := map[string]any{
			"score":              result.Score,
			"grade":              result.Grade,
			"breakdown":          result.Breakdown,
			"weighted_breakdown": result.WeightedBreakdown,
			"weights":            result.Weights,
			"trend_delta":        result.TrendDelta,
		}
		if snapshot.HasRiskReport || attackPaths != nil || topAttackPaths != nil {
			payload["attack_paths"] = attackPaths
			payload["top_attack_paths"] = topAttackPaths
		}
		_ = json.NewEncoder(stdout).Encode(payload)
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
