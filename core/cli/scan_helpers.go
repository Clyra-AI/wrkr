package cli

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy"
	policyeval "github.com/Clyra-AI/wrkr/core/policy/eval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/source/github"
	"github.com/Clyra-AI/wrkr/core/source/local"
	"github.com/Clyra-AI/wrkr/core/source/org"
	"github.com/Clyra-AI/wrkr/core/state"
)

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

func acquireSources(ctx context.Context, mode config.TargetMode, value, githubBaseURL, githubToken, statePath string) (source.Manifest, []source.Finding, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return source.Manifest{}, nil, ctxErr
	}

	connector := github.NewConnector(githubBaseURL, githubToken, nil)

	manifestOut := source.Manifest{Target: source.Target{Mode: string(mode), Value: value}}
	var findings []source.Finding
	materializeRoot := ""
	if mode == config.TargetRepo || mode == config.TargetOrg {
		root, err := prepareMaterializedRoot(statePath)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		materializeRoot = root
	}

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
		if ctxErr := ctx.Err(); ctxErr != nil {
			return source.Manifest{}, nil, ctxErr
		}
		repoManifest, err := connector.AcquireRepo(ctx, value)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		materialized, materializeErr := connector.MaterializeRepo(ctx, repoManifest.Repo, materializeRoot)
		if materializeErr != nil {
			return source.Manifest{}, nil, fmt.Errorf("materialize repo %s: %w", repoManifest.Repo, materializeErr)
		}
		manifestOut.Repos = []source.RepoManifest{materialized}
		owner := strings.Split(value, "/")[0]
		findings = append(findings, sourceFinding(materialized, owner, "repo.contents.read"))
	case config.TargetOrg:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return source.Manifest{}, nil, ctxErr
		}
		repos, failures, err := org.Acquire(ctx, value, connector, connector)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return source.Manifest{}, nil, ctxErr
		}
		materializedRepos := make([]source.RepoManifest, 0, len(repos))
		for _, repoManifest := range repos {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return source.Manifest{}, nil, ctxErr
			}
			materialized, materializeErr := connector.MaterializeRepo(ctx, repoManifest.Repo, materializeRoot)
			if materializeErr != nil {
				reason := materializeErr.Error()
				if github.IsDegradedError(materializeErr) {
					reason = "connector_degraded: " + reason
				}
				failures = append(failures, source.RepoFailure{
					Repo:   repoManifest.Repo,
					Reason: reason,
				})
				continue
			}
			materializedRepos = append(materializedRepos, materialized)
		}
		manifestOut.Repos = materializedRepos
		manifestOut.Failures = failures
		for _, repoManifest := range materializedRepos {
			findings = append(findings, sourceFinding(repoManifest, value, "repo.contents.read"))
		}
	case config.TargetPath:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return source.Manifest{}, nil, ctxErr
		}
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

func prepareMaterializedRoot(statePath string) (string, error) {
	cleanState := filepath.Clean(strings.TrimSpace(statePath))
	if cleanState == "" || cleanState == "." {
		return "", fmt.Errorf("state path is required for materialized source acquisition")
	}
	root := filepath.Join(filepath.Dir(cleanState), "materialized-sources")
	if err := os.RemoveAll(root); err != nil {
		return "", fmt.Errorf("reset materialized source root: %w", err)
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return "", fmt.Errorf("create materialized source root: %w", err)
	}
	return root, nil
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
		location := strings.TrimSpace(repo.Location)
		if location == "" {
			continue
		}
		orgName := deriveOrg(manifestOut.Target, repo)
		scopes = append(scopes, detect.Scope{Org: orgName, Repo: repo.Repo, Root: location})
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
		if !model.IsIdentityBearingFinding(finding) {
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

func buildScanMethodology(manifestOut source.Manifest, findings []source.Finding, startedAt, completedAt time.Time) agginventory.MethodologySummary {
	fileSet := map[string]struct{}{}
	detectorCounts := map[string]int{}
	for _, finding := range findings {
		repo := strings.TrimSpace(finding.Repo)
		location := strings.TrimSpace(finding.Location)
		if repo != "" && location != "" {
			fileSet[repo+"::"+location] = struct{}{}
		}
		detector := strings.TrimSpace(finding.Detector)
		if detector == "" {
			detector = "unknown"
		}
		detectorCounts[detector]++
	}

	detectors := make([]agginventory.MethodologyDetector, 0, len(detectorCounts))
	for detectorID, count := range detectorCounts {
		detectors = append(detectors, agginventory.MethodologyDetector{
			ID:           detectorID,
			Version:      "v1",
			FindingCount: count,
		})
	}
	sort.Slice(detectors, func(i, j int) bool {
		return detectors[i].ID < detectors[j].ID
	})

	started := startedAt.UTC().Truncate(time.Second)
	completed := completedAt.UTC().Truncate(time.Second)
	if completed.Before(started) {
		completed = started
	}
	durationSeconds := math.Round(completed.Sub(started).Seconds()*100) / 100

	return agginventory.MethodologySummary{
		WrkrVersion:         wrkrVersion(),
		ScanStartedAt:       started.Format(time.RFC3339),
		ScanCompletedAt:     completed.Format(time.RFC3339),
		ScanDurationSeconds: durationSeconds,
		RepoCount:           len(manifestOut.Repos),
		FileCountProcessed:  len(fileSet),
		Detectors:           detectors,
	}
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

func hasDegradedFailures(failures []source.RepoFailure) bool {
	for _, failure := range failures {
		if strings.Contains(strings.ToLower(strings.TrimSpace(failure.Reason)), "degraded") {
			return true
		}
	}
	return false
}
