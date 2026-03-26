package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	coreaction "github.com/Clyra-AI/wrkr/core/action"
	"github.com/Clyra-AI/wrkr/core/github/pr"
)

const (
	actionBehaviorContractSentenceOne = "wrkr action is the current shipped CLI-first automation surface for PR relevance and PR comment workflows."
	actionBehaviorContractSentenceTwo = "Any packaged GitHub Action surface must wrap these CLI contracts rather than duplicating business logic."
)

func runAction(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "action subcommand is required", exitInvalidInput)
	}
	if isHelpFlag(args[0]) {
		writeActionUsage(stderr)
		return exitSuccess
	}

	switch args[0] {
	case "pr-mode":
		return runActionPRMode(args[1:], stdout, stderr)
	case "pr-comment":
		return runActionPRComment(args[1:], stdout, stderr)
	default:
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "unsupported action subcommand", exitInvalidInput)
	}
}

func runActionPRMode(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("action pr-mode", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	changedPaths := fs.String("changed-paths", "", "comma or newline separated changed paths")
	riskDelta := fs.Float64("risk-delta", 0, "risk delta")
	complianceDelta := fs.Float64("compliance-delta", 0, "compliance delta")
	blockThreshold := fs.Float64("block-threshold", 0, "block threshold")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "action pr-mode does not accept positional arguments", exitInvalidInput)
	}

	result := coreaction.RunPRMode(coreaction.PRModeInput{
		ChangedPaths:    parseChangedPaths(*changedPaths),
		RiskDelta:       *riskDelta,
		ComplianceDelta: *complianceDelta,
		BlockThreshold:  *blockThreshold,
	})
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, result.Comment)
	return exitSuccess
}

func runActionPRComment(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("action pr-comment", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	changedPaths := fs.String("changed-paths", "", "comma or newline separated changed paths")
	riskDelta := fs.Float64("risk-delta", 0, "risk delta")
	complianceDelta := fs.Float64("compliance-delta", 0, "compliance delta")
	blockThreshold := fs.Float64("block-threshold", 0, "block threshold")
	owner := fs.String("owner", "", "repository owner")
	repo := fs.String("repo", "", "repository name")
	prNumber := fs.Int("pr-number", 0, "pull request number")
	githubBaseURL := fs.String("github-api", strings.TrimSpace(os.Getenv("GITHUB_API_URL")), "GitHub API base URL")
	githubToken := fs.String("github-token", "", "GitHub API token")
	fingerprint := fs.String("fingerprint", "wrkr-action-pr-mode-v1", "deterministic comment fingerprint marker")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "action pr-comment does not accept positional arguments", exitInvalidInput)
	}

	modeResult := coreaction.RunPRMode(coreaction.PRModeInput{
		ChangedPaths:    parseChangedPaths(*changedPaths),
		RiskDelta:       *riskDelta,
		ComplianceDelta: *complianceDelta,
		BlockThreshold:  *blockThreshold,
	})

	payload := map[string]any{
		"status":          "ok",
		"pr_mode":         modeResult,
		"published":       false,
		"comment_action":  "skipped",
		"comment_id":      0,
		"should_comment":  modeResult.ShouldComment,
		"relevant_paths":  modeResult.RelevantPaths,
		"block_merge":     modeResult.BlockMerge,
		"fingerprint":     strings.TrimSpace(*fingerprint),
		"target_pull_num": *prNumber,
	}

	if !modeResult.ShouldComment {
		if *jsonOut {
			_ = json.NewEncoder(stdout).Encode(payload)
			return exitSuccess
		}
		_, _ = fmt.Fprintln(stdout, "wrkr action pr-comment skipped (no relevant paths)")
		return exitSuccess
	}

	if strings.TrimSpace(*owner) == "" || strings.TrimSpace(*repo) == "" || *prNumber <= 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--owner, --repo, and --pr-number are required when comment publishing is needed", exitInvalidInput)
	}
	token := strings.TrimSpace(*githubToken)
	if token == "" {
		token = strings.TrimSpace(os.Getenv("WRKR_GITHUB_TOKEN"))
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	}
	if token == "" {
		return emitError(stderr, jsonRequested || *jsonOut, "dependency_missing", "github token is required for PR comment publishing", exitDependencyMissing)
	}

	client := pr.NewGitHubClient(strings.TrimSpace(*githubBaseURL), token, nil)
	commentResult, err := pr.UpsertIssueComment(context.Background(), client, pr.UpsertIssueCommentInput{
		Owner:       strings.TrimSpace(*owner),
		Repo:        strings.TrimSpace(*repo),
		IssueNumber: *prNumber,
		Body:        modeResult.Comment,
		Fingerprint: strings.TrimSpace(*fingerprint),
	})
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	payload["published"] = true
	payload["comment_action"] = commentResult.Action
	payload["comment_id"] = commentResult.Comment.ID
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr action pr-comment %s id=%d\n", commentResult.Action, commentResult.Comment.ID)
	return exitSuccess
}

func parseChangedPaths(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, item := range parts {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func writeActionUsage(out io.Writer) {
	_, _ = fmt.Fprintln(out, "Usage of wrkr action:")
	_, _ = fmt.Fprintln(out, "  wrkr action <pr-mode|pr-comment> [flags]")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Behavior contract:")
	_, _ = fmt.Fprintln(out, "  "+actionBehaviorContractSentenceOne)
	_, _ = fmt.Fprintln(out, "  "+actionBehaviorContractSentenceTwo)
}
