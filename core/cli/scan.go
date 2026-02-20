package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aggexposure "github.com/Clyra-AI/wrkr/core/aggregate/exposure"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/detect"
	detectdefaults "github.com/Clyra-AI/wrkr/core/detect/defaults"
	"github.com/Clyra-AI/wrkr/core/diff"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/policy"
	policyeval "github.com/Clyra-AI/wrkr/core/policy/eval"
	profilemodel "github.com/Clyra-AI/wrkr/core/policy/profile"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/source/github"
	"github.com/Clyra-AI/wrkr/core/source/local"
	"github.com/Clyra-AI/wrkr/core/source/org"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runScan(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	explain := fs.Bool("explain", false, "emit rationale details")
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	repo := fs.String("repo", "", "scan one repo owner/repo")
	orgTarget := fs.String("org", "", "scan an organization")
	pathTarget := fs.String("path", "", "scan local pre-cloned repositories")
	diffMode := fs.Bool("diff", false, "show only changes since previous scan")
	enrich := fs.Bool("enrich", false, "enable non-deterministic enrichment lookups (network required)")
	baselinePath := fs.String("baseline", "", "optional fallback baseline when local state is absent")
	configPathFlag := fs.String("config", "", "config file path override")
	statePathFlag := fs.String("state", "", "state file path override")
	policyPath := fs.String("policy", "", "optional custom policy rule file")
	profileName := fs.String("profile", "standard", "posture profile [baseline|standard|strict]")
	githubBaseURL := fs.String("github-api", strings.TrimSpace(os.Getenv("WRKR_GITHUB_API_BASE")), "github api base url")
	githubToken := fs.String("github-token", "", "github token override")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	targetMode, targetValue, cfg, err := resolveScanTarget(*repo, *orgTarget, *pathTarget, *configPathFlag)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if cfg.Auth.Scan.Token != "" && strings.TrimSpace(*githubToken) == "" {
		*githubToken = cfg.Auth.Scan.Token
	}
	if *enrich && strings.TrimSpace(*githubBaseURL) == "" {
		return emitError(
			stderr,
			jsonRequested || *jsonOut,
			"dependency_missing",
			"--enrich requires a reachable network source; set --github-api or WRKR_GITHUB_API_BASE",
			exitDependencyMissing,
		)
	}

	ctx := context.Background()
	manifestOut, findings, err := acquireSources(ctx, targetMode, targetValue, *githubBaseURL, *githubToken)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	scopes := detectorScopes(manifestOut)
	if len(scopes) > 0 {
		registry, regErr := detectdefaults.Registry()
		if regErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", regErr.Error(), exitRuntime)
		}
		detected, runErr := registry.Run(ctx, scopes, detect.Options{Enrich: *enrich})
		if runErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", runErr.Error(), exitRuntime)
		}
		findings = append(findings, detected...)

		policyFindings, policyErr := evaluatePolicies(scopes, findings, strings.TrimSpace(*policyPath))
		if policyErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "policy_schema_violation", policyErr.Error(), exitPolicyViolation)
		}
		findings = append(findings, policyFindings...)
	}
	source.SortFindings(findings)

	statePath := state.ResolvePath(*statePathFlag)
	previousSnapshot, loadPreviousErr := loadPreviousSnapshot(statePath, strings.TrimSpace(*baselinePath))
	if loadPreviousErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", loadPreviousErr.Error(), exitRuntime)
	}

	now := time.Now().UTC().Truncate(time.Second)
	riskReport := risk.Score(findings, 5, now)
	repoRisk := map[string]float64{}
	for _, repo := range riskReport.Repos {
		repoRisk[repo.Org+"::"+repo.Repo] = repo.Score
	}

	manifestPath := manifest.ResolvePath(statePath)
	previousManifest, manifestErr := loadManifest(manifestPath)
	if manifestErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", manifestErr.Error(), exitRuntime)
	}

	baseContexts := buildFindingContexts(riskReport)
	observed := observedTools(findings, baseContexts)
	nextManifest, transitions := lifecycle.Reconcile(previousManifest, observed, now)
	if err := manifest.Save(manifestPath, nextManifest); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	chainPath := lifecycle.ChainPath(statePath)
	chain, chainErr := lifecycle.LoadChain(chainPath)
	if chainErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", chainErr.Error(), exitRuntime)
	}
	for _, transition := range transitions {
		if err := lifecycle.AppendTransitionRecord(chain, transition, "lifecycle_transition"); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
	}
	if err := lifecycle.SaveChain(chainPath, chain); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	identityByAgent := map[string]manifest.IdentityRecord{}
	for _, record := range nextManifest.Identities {
		identityByAgent[record.AgentID] = record
	}
	contexts := enrichFindingContexts(findings, baseContexts, identityByAgent)

	repoExposure := aggexposure.Build(findings, repoRisk)
	inventoryOut := agginventory.Build(agginventory.BuildInput{
		Manifest:              manifestOut,
		Findings:              findings,
		Contexts:              contexts,
		RepoExposureSummaries: repoExposure,
		GeneratedAt:           now,
	})

	profileDef, profileErr := profilemodel.Builtin(*profileName)
	if profileErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", profileErr.Error(), exitUnsafeBlocked)
	}
	profileDef, profileErr = profilemodel.WithOverrides(profileDef, strings.TrimSpace(*policyPath), repoRootFromScopes(scopes))
	if profileErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", profileErr.Error(), exitUnsafeBlocked)
	}
	var previousProfile *profileeval.Result
	if previousSnapshot != nil && previousSnapshot.Profile != nil {
		copyResult := *previousSnapshot.Profile
		previousProfile = &copyResult
	}
	profileResult := profileeval.Evaluate(profileDef, findings, previousProfile)

	weights, weightErr := score.LoadWeights(strings.TrimSpace(*policyPath), repoRootFromScopes(scopes))
	if weightErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "unsafe_operation_blocked", weightErr.Error(), exitUnsafeBlocked)
	}
	var previousScore *score.Result
	if previousSnapshot != nil && previousSnapshot.PostureScore != nil {
		copyResult := *previousSnapshot.PostureScore
		previousScore = &copyResult
	}
	postureScore := score.Compute(score.Input{
		Findings:        findings,
		Identities:      nextManifest.Identities,
		ProfileResult:   profileResult,
		TransitionCount: driftTransitionCount(transitions),
		Weights:         weights,
		Previous:        previousScore,
	})

	snapshot := state.Snapshot{
		Version:      state.SnapshotVersion,
		Target:       manifestOut.Target,
		Findings:     findings,
		Inventory:    &inventoryOut,
		RiskReport:   &riskReport,
		Profile:      &profileResult,
		PostureScore: &postureScore,
		Identities:   nextManifest.Identities,
		Transitions:  transitions,
	}
	if err := state.Save(statePath, snapshot); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	payload := map[string]any{
		"status":          "ok",
		"target":          manifestOut.Target,
		"source_manifest": manifestOut,
	}

	if *diffMode {
		previousFindings := []source.Finding{}
		if previousSnapshot != nil {
			previousFindings = previousSnapshot.Findings
		}
		result := diff.Compute(previousFindings, findings)
		payload["diff"] = result
		payload["diff_empty"] = diff.Empty(result)
	} else {
		payload["findings"] = findings
		payload["ranked_findings"] = riskReport.Ranked
		payload["top_findings"] = riskReport.TopN
		payload["inventory"] = inventoryOut
		payload["repo_exposure_summaries"] = repoExposure
		payload["profile"] = profileResult
		payload["posture_score"] = postureScore
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if *quiet {
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr scan completed for %s:%s (profile=%s score=%.2f grade=%s)\n", targetMode, targetValue, profileResult.ProfileName, postureScore.Score, postureScore.Grade)
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, "wrkr scan complete")
	return exitSuccess
}

func resolveScanTarget(repo, orgInput, pathInput, configPath string) (config.TargetMode, string, config.Config, error) {
	mode, value, err := resolveTarget(repo, orgInput, pathInput)
	if err == nil {
		return mode, value, config.Default(), nil
	}
	if strings.TrimSpace(repo) != "" || strings.TrimSpace(orgInput) != "" || strings.TrimSpace(pathInput) != "" {
		return "", "", config.Config{}, err
	}

	resolvedPath, pathErr := config.ResolvePath(configPath)
	if pathErr != nil {
		return "", "", config.Config{}, pathErr
	}
	cfg, loadErr := config.Load(resolvedPath)
	if loadErr != nil {
		return "", "", config.Config{}, fmt.Errorf("no target provided and no usable config default target (%v)", loadErr)
	}
	return cfg.DefaultTarget.Mode, cfg.DefaultTarget.Value, cfg, nil
}

func acquireSources(ctx context.Context, mode config.TargetMode, value, githubBaseURL, githubToken string) (source.Manifest, []source.Finding, error) {
	connector := github.NewConnector(githubBaseURL, githubToken, nil)

	manifestOut := source.Manifest{Target: source.Target{Mode: string(mode), Value: value}}
	var findings []source.Finding

	sourceFinding := func(repoManifest source.RepoManifest, orgName, permission string) source.Finding {
		return source.Finding{
			FindingType: "source_discovery",
			Severity:    "low",
			ToolType:    "source_repo",
			Location:    repoManifest.Location,
			Repo:        repoManifest.Repo,
			Org:         orgName,
			Permissions: []string{permission},
			Detector:    "source",
		}
	}

	switch mode {
	case config.TargetRepo:
		repoManifest, err := connector.AcquireRepo(ctx, value)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifestOut.Repos = []source.RepoManifest{repoManifest}
		owner := strings.Split(value, "/")[0]
		findings = append(findings, sourceFinding(repoManifest, owner, "repo.contents.read"))
	case config.TargetOrg:
		repos, failures, err := org.Acquire(ctx, value, connector, connector)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifestOut.Repos = repos
		manifestOut.Failures = failures
		for _, repoManifest := range repos {
			findings = append(findings, sourceFinding(repoManifest, value, "repo.contents.read"))
		}
	case config.TargetPath:
		repos, err := local.Acquire(value)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifestOut.Repos = repos
		for _, repoManifest := range repos {
			repoManifest.Location = filepath.ToSlash(repoManifest.Location)
			findings = append(findings, sourceFinding(repoManifest, "local", "filesystem.read"))
		}
	default:
		return source.Manifest{}, nil, fmt.Errorf("unsupported target mode %q", mode)
	}

	manifestOut = source.SortManifest(manifestOut)
	source.SortFindings(findings)
	return manifestOut, findings, nil
}

func evaluatePolicies(scopes []detect.Scope, findings []source.Finding, customPolicyPath string) ([]source.Finding, error) {
	byRepo := map[string][]source.Finding{}
	for _, finding := range findings {
		key := finding.Org + "::" + finding.Repo
		byRepo[key] = append(byRepo[key], finding)
	}

	out := make([]source.Finding, 0)
	for _, scope := range scopes {
		rules, err := policy.LoadRules(customPolicyPath, scope.Root)
		if err != nil {
			return nil, err
		}
		key := scope.Org + "::" + scope.Repo
		policyFindings := policyeval.Evaluate(scope.Repo, scope.Org, byRepo[key], rules)
		out = append(out, policyFindings...)
	}
	source.SortFindings(out)
	return out, nil
}

func detectorScopes(manifestOut source.Manifest) []detect.Scope {
	scopes := make([]detect.Scope, 0, len(manifestOut.Repos))
	for _, repo := range manifestOut.Repos {
		info, err := os.Stat(repo.Location)
		if err != nil || !info.IsDir() {
			continue
		}
		orgName := deriveOrg(manifestOut.Target, repo)
		scopes = append(scopes, detect.Scope{Org: orgName, Repo: repo.Repo, Root: repo.Location})
	}
	return scopes
}

func deriveOrg(target source.Target, repo source.RepoManifest) string {
	switch target.Mode {
	case string(config.TargetOrg):
		if strings.TrimSpace(target.Value) == "" {
			return "local"
		}
		return target.Value
	case string(config.TargetRepo):
		parts := strings.Split(repo.Repo, "/")
		if len(parts) > 1 && strings.TrimSpace(parts[0]) != "" {
			return parts[0]
		}
		parts = strings.Split(target.Value, "/")
		if len(parts) > 1 {
			return parts[0]
		}
	default:
		return "local"
	}
	return "local"
}

func loadPreviousSnapshot(statePath, baselinePath string) (*state.Snapshot, error) {
	previous, err := state.Load(statePath)
	if err == nil {
		return &previous, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(strings.ToLower(err.Error()), "no such file") {
		return nil, err
	}
	if strings.TrimSpace(baselinePath) != "" {
		fallback, fallbackErr := state.Load(baselinePath)
		if fallbackErr == nil {
			return &fallback, nil
		}
		if !errors.Is(fallbackErr, os.ErrNotExist) && !strings.Contains(strings.ToLower(fallbackErr.Error()), "no such file") {
			return nil, fallbackErr
		}
	}
	return nil, nil
}

func loadManifest(path string) (manifest.Manifest, error) {
	loaded, err := manifest.Load(path)
	if err == nil {
		return loaded, nil
	}
	if errors.Is(err, os.ErrNotExist) || strings.Contains(strings.ToLower(err.Error()), "no such file") {
		return manifest.Manifest{Version: manifest.Version, Identities: []manifest.IdentityRecord{}}, nil
	}
	return manifest.Manifest{}, err
}

func buildFindingContexts(report risk.Report) map[string]agginventory.ToolContext {
	out := map[string]agginventory.ToolContext{}
	for _, item := range report.Ranked {
		key := agginventory.KeyForFinding(item.Finding)
		existing := out[key]
		if item.Score > existing.RiskScore {
			existing = agginventory.ToolContext{
				EndpointClass: item.EndpointClass,
				DataClass:     item.DataClass,
				AutonomyLevel: item.AutonomyLevel,
				RiskScore:     item.Score,
			}
		}
		out[key] = existing
	}
	return out
}

func observedTools(findings []source.Finding, contexts map[string]agginventory.ToolContext) []lifecycle.ObservedTool {
	byAgent := map[string]lifecycle.ObservedTool{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.ToolType) == "" {
			continue
		}
		if finding.FindingType == "policy_check" || finding.FindingType == "policy_violation" || finding.FindingType == "parse_error" {
			continue
		}
		org := strings.TrimSpace(finding.Org)
		if org == "" {
			org = "local"
		}
		toolID := identity.ToolID(finding.ToolType, finding.Location)
		agentID := identity.AgentID(toolID, org)
		ctx := contexts[agginventory.KeyForFinding(finding)]
		candidate := lifecycle.ObservedTool{
			AgentID:       agentID,
			ToolID:        toolID,
			ToolType:      finding.ToolType,
			Org:           org,
			Repo:          finding.Repo,
			Location:      finding.Location,
			DataClass:     ctx.DataClass,
			EndpointClass: ctx.EndpointClass,
			AutonomyLevel: ctx.AutonomyLevel,
			RiskScore:     ctx.RiskScore,
		}
		existing, ok := byAgent[agentID]
		if !ok || candidate.RiskScore >= existing.RiskScore {
			byAgent[agentID] = candidate
		}
	}
	out := make([]lifecycle.ObservedTool, 0, len(byAgent))
	for _, item := range byAgent {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

func enrichFindingContexts(findings []source.Finding, base map[string]agginventory.ToolContext, identities map[string]manifest.IdentityRecord) map[string]agginventory.ToolContext {
	out := map[string]agginventory.ToolContext{}
	for key, value := range base {
		out[key] = value
	}
	for _, finding := range findings {
		org := strings.TrimSpace(finding.Org)
		if org == "" {
			org = "local"
		}
		toolID := identity.ToolID(finding.ToolType, finding.Location)
		agentID := identity.AgentID(toolID, org)
		record, exists := identities[agentID]
		if !exists {
			continue
		}
		key := agginventory.KeyForFinding(finding)
		ctx := out[key]
		ctx.ApprovalStatus = fallback(record.ApprovalState, "missing")
		ctx.LifecycleState = fallback(record.Status, identity.StateDiscovered)
		if ctx.DataClass == "" {
			ctx.DataClass = record.DataClass
		}
		if ctx.EndpointClass == "" {
			ctx.EndpointClass = record.EndpointClass
		}
		if ctx.AutonomyLevel == "" {
			ctx.AutonomyLevel = record.AutonomyLevel
		}
		if record.RiskScore > ctx.RiskScore {
			ctx.RiskScore = record.RiskScore
		}
		out[key] = ctx
	}
	return out
}

func repoRootFromScopes(scopes []detect.Scope) string {
	if len(scopes) == 0 {
		return ""
	}
	sort.Slice(scopes, func(i, j int) bool {
		if scopes[i].Org != scopes[j].Org {
			return scopes[i].Org < scopes[j].Org
		}
		if scopes[i].Repo != scopes[j].Repo {
			return scopes[i].Repo < scopes[j].Repo
		}
		return scopes[i].Root < scopes[j].Root
	})
	return scopes[0].Root
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func driftTransitionCount(transitions []lifecycle.Transition) int {
	count := 0
	for _, transition := range transitions {
		switch strings.TrimSpace(transition.Trigger) {
		case "removed", "reappeared", "modified":
			count++
		}
	}
	return count
}
