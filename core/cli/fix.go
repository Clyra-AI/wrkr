package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/auth"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/fix"
	githubpr "github.com/Clyra-AI/wrkr/core/github/pr"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

var newGitHubPRClient = func(baseURL, token string) githubpr.API {
	return githubpr.NewGitHubClient(baseURL, token, nil)
}

func runFix(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	explain := fs.Bool("explain", false, "emit rationale details")
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	top := fs.Int("top", 3, "number of fix candidates to plan")
	statePathFlag := fs.String("state", "", "state file path override")
	configPathFlag := fs.String("config", "", "config file path override")
	openPR := fs.Bool("open-pr", false, "open or update a remediation pull request")
	repoTarget := fs.String("repo", "", "owner/repo target for PR operations")
	baseBranch := fs.String("base", "main", "base branch for PR operations")
	botIdentity := fs.String("bot", "wrkr-bot", "bot identity for deterministic branch metadata")
	scheduleKey := fs.String("schedule-key", "adhoc", "schedule key for idempotent branch naming")
	prTitle := fs.String("pr-title", "", "optional deterministic PR title override")
	githubAPI := fs.String("github-api", strings.TrimSpace(os.Getenv("WRKR_GITHUB_API_BASE")), "github api base url")
	fixToken := fs.String("fix-token", "", "fix profile token override")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "fix does not accept positional arguments", exitInvalidInput)
	}
	if *top <= 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--top must be greater than zero", exitInvalidInput)
	}
	if *quiet && *explain && !*jsonOut {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--quiet and --explain cannot be used together", exitInvalidInput)
	}

	snapshot, err := state.Load(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	plan, err := fix.BuildPlan(loadRankedFindings(snapshot, *top), *top)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	payload := map[string]any{
		"status":               "ok",
		"requested_top":        plan.RequestedTop,
		"fingerprint":          plan.Fingerprint,
		"remediation_count":    len(plan.Remediations),
		"non_fixable_count":    len(plan.Skipped),
		"remediations":         plan.Remediations,
		"unsupported_findings": plan.Skipped,
	}

	if *openPR {
		if len(plan.Remediations) == 0 {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", "no fixable findings available for PR generation", exitUnsafeBlocked)
		}
		repoValue, err := resolvePRRepo(*repoTarget, snapshot)
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		owner, repo, err := splitRepo(repoValue)
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}

		cfg, cfgErr := loadOptionalConfig(*configPathFlag)
		if cfgErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", cfgErr.Error(), exitRuntime)
		}
		token, tokenErr := auth.ResolveFixToken(cfg.Auth.Scan.Token, cfg.Auth.Fix.Token, *fixToken)
		if tokenErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "approval_required", tokenErr.Error(), exitApprovalRequired)
		}

		title := strings.TrimSpace(*prTitle)
		if title == "" {
			title = fmt.Sprintf("wrkr remediation: %s (%s)", repoValue, plan.Fingerprint[:8])
		}
		branch := githubpr.BranchName(*botIdentity, repoValue, *scheduleKey, plan.Fingerprint)
		artifacts, artifactErr := fix.BuildPRArtifacts(plan)
		if artifactErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", artifactErr.Error(), exitRuntime)
		}
		if len(artifacts) == 0 {
			return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", "no remediation artifacts generated for PR operation", exitUnsafeBlocked)
		}
		body := remediationPRBody(repoValue, plan)
		prClient := newGitHubPRClient(*githubAPI, token)

		if err := prClient.EnsureHeadRef(context.Background(), owner, repo, branch, strings.TrimSpace(*baseBranch)); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
		changedCount := 0
		artifactPaths := make([]string, 0, len(artifacts))
		for _, artifact := range artifacts {
			changed, writeErr := prClient.EnsureFileContent(
				context.Background(),
				owner,
				repo,
				branch,
				artifact.Path,
				artifact.CommitMessage,
				artifact.Content,
			)
			if writeErr != nil {
				return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", writeErr.Error(), exitRuntime)
			}
			if changed {
				changedCount++
			}
			artifactPaths = append(artifactPaths, artifact.Path)
		}

		result, prErr := githubpr.Upsert(context.Background(), prClient, githubpr.UpsertInput{
			Owner:       owner,
			Repo:        repo,
			HeadBranch:  branch,
			BaseBranch:  strings.TrimSpace(*baseBranch),
			Title:       title,
			Body:        body,
			Fingerprint: plan.Fingerprint,
		})
		if prErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", prErr.Error(), exitRuntime)
		}

		payload["pull_request"] = map[string]any{
			"action":      result.Action,
			"number":      result.PullRequest.Number,
			"url":         result.PullRequest.URL,
			"head_branch": result.PullRequest.Head,
			"base_branch": result.PullRequest.Base,
		}
		payload["remediation_artifacts"] = map[string]any{
			"count":         len(artifacts),
			"changed_count": changedCount,
			"paths":         artifactPaths,
		}
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if *quiet {
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr fix planned %d remediation(s), skipped %d non-fixable finding(s)\n", len(plan.Remediations), len(plan.Skipped))
		if prPayload, ok := payload["pull_request"].(map[string]any); ok {
			_, _ = fmt.Fprintf(stdout, "PR %v (%v)\n", prPayload["number"], prPayload["url"])
		}
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, "wrkr fix complete")
	return exitSuccess
}

func loadRankedFindings(snapshot state.Snapshot, top int) []risk.ScoredFinding {
	if snapshot.RiskReport != nil && len(snapshot.RiskReport.Ranked) > 0 {
		return append([]risk.ScoredFinding(nil), snapshot.RiskReport.Ranked...)
	}
	computed := risk.Score(snapshot.Findings, top, time.Now().UTC().Truncate(time.Second))
	return computed.Ranked
}

func resolvePRRepo(flagRepo string, snapshot state.Snapshot) (string, error) {
	if trimmed := strings.TrimSpace(flagRepo); trimmed != "" {
		return trimmed, nil
	}
	if snapshot.Target.Mode == "repo" && strings.Contains(strings.TrimSpace(snapshot.Target.Value), "/") {
		return strings.TrimSpace(snapshot.Target.Value), nil
	}
	return "", errors.New("--repo is required for PR operations when state target is not owner/repo")
}

func splitRepo(repo string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return "", "", fmt.Errorf("repo target must be owner/repo, got %q", repo)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

func loadOptionalConfig(explicitPath string) (config.Config, error) {
	resolvedPath, err := config.ResolvePath(explicitPath)
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := config.Load(resolvedPath)
	if err != nil {
		if os.IsNotExist(err) && strings.TrimSpace(explicitPath) == "" {
			return config.Default(), nil
		}
		return config.Config{}, err
	}
	return cfg, nil
}

func remediationPRBody(repo string, plan fix.Plan) string {
	lines := []string{
		"## Wrkr Remediation Plan",
		"",
		"Repository: `" + repo + "`",
		"Fingerprint: `" + plan.Fingerprint + "`",
		"",
		"### Planned Remediations",
	}
	for i, item := range plan.Remediations {
		lines = append(lines, fmt.Sprintf("%d. `%s` %s", i+1, item.TemplateID, item.Title))
		lines = append(lines, "   - Location: `"+strings.TrimSpace(item.Finding.Location)+"`")
		lines = append(lines, "   - Commit message: `"+item.CommitMessage+"`")
	}
	if len(plan.Skipped) > 0 {
		lines = append(lines, "", "### Non-fixable Findings")
		for i, item := range plan.Skipped {
			lines = append(lines, fmt.Sprintf("%d. `%s` `%s` %s", i+1, item.FindingType, item.ReasonCode, item.Message))
		}
	}
	lines = append(lines, "", "<!-- wrkr-fingerprint:"+plan.Fingerprint+" -->")
	return strings.Join(lines, "\n")
}
