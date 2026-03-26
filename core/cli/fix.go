package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
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

const (
	fixBehaviorContractSentenceOne = "wrkr fix computes a deterministic remediation plan from existing scan state and emits plan metadata; preview mode does not mutate repository files."
	fixBehaviorContractSentenceTwo = "When --open-pr is set, wrkr fix publishes deterministic preview PRs for the target repo; add --apply to write supported repo files instead of preview artifacts only."
)

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
	applyMode := fs.Bool("apply", false, "write supported repo files in PRs instead of preview artifacts only")
	maxPRs := fs.Int("max-prs", 1, "maximum number of remediation PRs to create or update")
	repoTarget := fs.String("repo", "", "owner/repo target for PR operations")
	baseBranch := fs.String("base", "main", "base branch for PR operations")
	botIdentity := fs.String("bot", "wrkr-bot", "bot identity for deterministic branch metadata")
	scheduleKey := fs.String("schedule-key", "adhoc", "schedule key for idempotent branch naming")
	prTitle := fs.String("pr-title", "", "optional deterministic PR title override")
	githubAPI := fs.String("github-api", strings.TrimSpace(os.Getenv("WRKR_GITHUB_API_BASE")), "github api base url")
	fixToken := fs.String("fix-token", "", "fix profile token override")
	fs.Usage = func() {
		writeFixUsage(fs.Output(), fs)
	}

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "fix does not accept positional arguments", exitInvalidInput)
	}
	if *top <= 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--top must be greater than zero", exitInvalidInput)
	}
	if *maxPRs <= 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--max-prs must be greater than zero", exitInvalidInput)
	}
	if *applyMode && !*openPR {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--apply requires --open-pr", exitInvalidInput)
	}
	if *maxPRs > 1 && !*openPR {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--max-prs requires --open-pr", exitInvalidInput)
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
		"mode":                 "preview",
		"requested_top":        plan.RequestedTop,
		"fingerprint":          plan.Fingerprint,
		"remediation_count":    len(plan.Remediations),
		"non_fixable_count":    len(plan.Skipped),
		"remediations":         plan.Remediations,
		"unsupported_findings": plan.Skipped,
	}
	if *applyMode {
		payload["mode"] = "apply"
		payload["apply_supported_count"] = len(fix.ApplyCapablePlan(plan).Remediations)
	}

	if *openPR {
		publicationPlan := plan
		if *applyMode {
			publicationPlan = fix.ApplyCapablePlan(plan)
		}
		if len(publicationPlan.Remediations) == 0 {
			if *applyMode {
				return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", fix.ErrNoApplyCapableRemediations.Error(), exitUnsafeBlocked)
			}
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
		prClient := newGitHubPRClient(*githubAPI, token)
		publications, artifactCount, changedCount, artifactPaths, publishErr := publishRemediationPRs(
			context.Background(),
			prClient,
			snapshot,
			owner,
			repo,
			repoValue,
			strings.TrimSpace(*baseBranch),
			title,
			*botIdentity,
			*scheduleKey,
			fix.SplitPlanForPRs(publicationPlan, *maxPRs),
			*applyMode,
		)
		if publishErr != nil {
			if errors.Is(publishErr, fix.ErrNoApplyCapableRemediations) {
				return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", publishErr.Error(), exitUnsafeBlocked)
			}
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", publishErr.Error(), exitRuntime)
		}
		if len(publications) == 1 {
			payload["pull_request"] = publications[0]
		}
		payload["pull_requests"] = publications
		payload["remediation_artifacts"] = map[string]any{
			"count":         artifactCount,
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

func writeFixUsage(out io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprintln(out, "Usage of fix:")
	_, _ = fmt.Fprintln(out, "  wrkr fix [flags]")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Behavior contract:")
	_, _ = fmt.Fprintln(out, "  "+fixBehaviorContractSentenceOne)
	_, _ = fmt.Fprintln(out, "  "+fixBehaviorContractSentenceTwo)
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "PR prerequisites:")
	_, _ = fmt.Fprintln(out, "  - --repo owner/repo (or repo-target state)")
	_, _ = fmt.Fprintln(out, "  - writable fix profile token via config or --fix-token")
	_, _ = fmt.Fprintln(out, "  - add --apply to publish supported repo-file changes instead of preview artifacts only")
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Flags:")
	fs.PrintDefaults()
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

func publishRemediationPRs(
	ctx context.Context,
	prClient githubpr.API,
	snapshot state.Snapshot,
	owner string,
	repo string,
	repoValue string,
	baseBranch string,
	title string,
	botIdentity string,
	scheduleKey string,
	groups []fix.PRGroup,
	applyMode bool,
) ([]map[string]any, int, int, []string, error) {
	publications := make([]map[string]any, 0, len(groups))
	totalArtifacts := 0
	totalChanged := 0
	allPaths := make([]string, 0)

	for _, group := range groups {
		artifacts, err := remediationArtifactsForGroup(snapshot, group, applyMode)
		if err != nil {
			return nil, 0, 0, nil, err
		}
		branch := githubpr.BranchName(botIdentity, repoValue, groupScheduleKey(scheduleKey, group), group.Plan.Fingerprint)
		if err := prClient.EnsureHeadRef(ctx, owner, repo, branch, baseBranch); err != nil {
			return nil, 0, 0, nil, err
		}
		changedCount := 0
		groupPaths := make([]string, 0, len(artifacts))
		for _, artifact := range artifacts {
			changed, writeErr := prClient.EnsureFileContent(ctx, owner, repo, branch, artifact.Path, artifact.CommitMessage, artifact.Content)
			if writeErr != nil {
				return nil, 0, 0, nil, writeErr
			}
			if changed {
				changedCount++
			}
			groupPaths = append(groupPaths, artifact.Path)
			allPaths = append(allPaths, artifact.Path)
		}
		result, err := githubpr.Upsert(ctx, prClient, githubpr.UpsertInput{
			Owner:       owner,
			Repo:        repo,
			HeadBranch:  branch,
			BaseBranch:  baseBranch,
			Title:       remediationPRTitle(title, repoValue, group),
			Body:        remediationPRBody(repoValue, group.Plan),
			Fingerprint: group.Plan.Fingerprint,
		})
		if err != nil {
			return nil, 0, 0, nil, err
		}

		publications = append(publications, map[string]any{
			"action":         result.Action,
			"number":         result.PullRequest.Number,
			"url":            result.PullRequest.URL,
			"head_branch":    result.PullRequest.Head,
			"base_branch":    result.PullRequest.Base,
			"group_index":    group.Index + 1,
			"group_total":    group.Total,
			"mode":           publicationModeValue(applyMode),
			"artifact_count": len(artifacts),
			"changed_count":  changedCount,
			"paths":          groupPaths,
		})
		totalArtifacts += len(artifacts)
		totalChanged += changedCount
	}
	sort.Strings(allPaths)
	return publications, totalArtifacts, totalChanged, allPaths, nil
}

func remediationArtifactsForGroup(snapshot state.Snapshot, group fix.PRGroup, applyMode bool) ([]fix.PRArtifact, error) {
	previewArtifacts, err := fix.BuildPRArtifacts(group.Plan)
	if err != nil {
		return nil, err
	}
	if !applyMode {
		return previewArtifacts, nil
	}
	applyArtifacts, err := fix.BuildApplyArtifacts(snapshot, group.Plan)
	if err != nil {
		return nil, err
	}
	artifacts := append(applyArtifacts, previewArtifacts...)
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return artifacts, nil
}

func remediationPRTitle(rawTitle string, repoValue string, group fix.PRGroup) string {
	title := strings.TrimSpace(rawTitle)
	if title == "" {
		title = fmt.Sprintf("wrkr remediation: %s (%s)", repoValue, group.Plan.Fingerprint[:8])
	}
	if group.Total <= 1 {
		return title
	}
	return fmt.Sprintf("%s [%d/%d]", title, group.Index+1, group.Total)
}

func groupScheduleKey(scheduleKey string, group fix.PRGroup) string {
	if group.Total <= 1 {
		return scheduleKey
	}
	return fmt.Sprintf("%s-g%02dof%02d", strings.TrimSpace(scheduleKey), group.Index+1, group.Total)
}

func publicationModeValue(applyMode bool) string {
	if applyMode {
		return "apply"
	}
	return "preview"
}
