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
	"github.com/Clyra-AI/wrkr/core/source/localsetup"
	"github.com/Clyra-AI/wrkr/core/source/org"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/managedmarker"
)

const materializedRootMarkerFile = ".wrkr-materialized-sources-managed"
const materializedRootMarkerContent = "managed by wrkr scan materialized sources\n"
const materializedRootMarkerKind = "scan_materialized_root"

type materializedRootSafetyError struct {
	message string
}

type acquireOptions struct {
	StatePath string
	Progress  *scanProgressReporter
	Resume    bool
}

func (e *materializedRootSafetyError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func newMaterializedRootSafetyError(format string, args ...any) error {
	return &materializedRootSafetyError{message: fmt.Sprintf(format, args...)}
}

func isMaterializedRootSafetyError(err error) bool {
	var target *materializedRootSafetyError
	return errors.As(err, &target)
}

func resolveScanTarget(repo, orgInput, githubOrgInput, pathInput string, mySetup bool, configPath string) (config.TargetMode, string, config.Config, error) {
	mode, value, err := resolveScanTargetInput(repo, orgInput, githubOrgInput, pathInput, mySetup)
	if err == nil {
		return mode, value, config.Default(), nil
	}
	if strings.TrimSpace(repo) != "" || strings.TrimSpace(orgInput) != "" || strings.TrimSpace(githubOrgInput) != "" || strings.TrimSpace(pathInput) != "" || mySetup {
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

func resolveScanTargetInput(repo, orgInput, githubOrgInput, pathInput string, mySetup bool) (config.TargetMode, string, error) {
	targets := make([]config.Target, 0, 4)
	if strings.TrimSpace(repo) != "" {
		targets = append(targets, config.Target{Mode: config.TargetRepo, Value: strings.TrimSpace(repo)})
	}
	if strings.TrimSpace(orgInput) != "" {
		targets = append(targets, config.Target{Mode: config.TargetOrg, Value: strings.TrimSpace(orgInput)})
	}
	if strings.TrimSpace(githubOrgInput) != "" {
		targets = append(targets, config.Target{Mode: config.TargetOrg, Value: strings.TrimSpace(githubOrgInput)})
	}
	if strings.TrimSpace(pathInput) != "" {
		targets = append(targets, config.Target{Mode: config.TargetPath, Value: strings.TrimSpace(pathInput)})
	}
	if mySetup {
		targets = append(targets, config.Target{Mode: config.TargetMySetup, Value: localsetup.TargetValue})
	}

	if len(targets) != 1 {
		return "", "", fmt.Errorf("exactly one target source is required: use one of --repo, --org, --github-org, --path, --my-setup")
	}
	if err := config.ValidateTarget(targets[0].Mode, targets[0].Value); err != nil {
		return "", "", err
	}
	return targets[0].Mode, targets[0].Value, nil
}

func acquireSources(ctx context.Context, mode config.TargetMode, value, githubBaseURL, githubToken string, opts acquireOptions) (source.Manifest, []source.Finding, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return source.Manifest{}, nil, ctxErr
	}

	connector := github.NewConnector(githubBaseURL, githubToken, nil)
	connector.SetRetryHandler(func(event github.RetryEvent) {
		if opts.Progress == nil {
			return
		}
		opts.Progress.Retry(event.Attempt, event.Delay, event.StatusCode)
	})
	connector.SetCooldownHandler(func(event github.CooldownEvent) {
		if opts.Progress == nil {
			return
		}
		opts.Progress.Cooldown(event.Delay, event.Until)
	})

	manifestOut := source.Manifest{Target: source.Target{Mode: string(mode), Value: value}}
	var findings []source.Finding
	materializeRoot := ""
	if mode == config.TargetRepo || mode == config.TargetOrg {
		var (
			root string
			err  error
		)
		if mode == config.TargetOrg && opts.Resume {
			root, err = prepareMaterializedRootForResume(opts.StatePath)
		} else {
			root, err = prepareMaterializedRoot(opts.StatePath)
		}
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
		repos, failures, err := org.AcquireMaterialized(ctx, value, connector, connector, org.AcquireMaterializedOptions{
			StatePath:        opts.StatePath,
			MaterializedRoot: materializeRoot,
			Resume:           opts.Resume,
			Progress:         opts.Progress,
		})
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifestOut.Repos = repos
		manifestOut.Failures = failures
		for _, repoManifest := range repos {
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
	case config.TargetMySetup:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return source.Manifest{}, nil, ctxErr
		}
		repos, err := localsetup.Acquire()
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifestOut.Repos = repos
		for _, repoManifest := range repos {
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
	if err := prepareManagedMaterializedRoot(root, cleanState, true); err != nil {
		return "", err
	}
	return root, nil
}

func prepareMaterializedRootForResume(statePath string) (string, error) {
	cleanState := filepath.Clean(strings.TrimSpace(statePath))
	if cleanState == "" || cleanState == "." {
		return "", fmt.Errorf("state path is required for materialized source acquisition")
	}
	root := filepath.Join(filepath.Dir(cleanState), "materialized-sources")
	if err := prepareManagedMaterializedRoot(root, cleanState, false); err != nil {
		return "", err
	}
	return root, nil
}

func prepareManagedMaterializedRoot(root string, statePath string, reset bool) error {
	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(root, 0o750); err != nil {
				return fmt.Errorf("create materialized source root: %w", err)
			}
			return writeMaterializedRootMarker(statePath, root)
		}
		return fmt.Errorf("lstat materialized source root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return newMaterializedRootSafetyError("materialized source root must not be a symlink: %s", root)
	}
	if !info.IsDir() {
		return newMaterializedRootSafetyError("materialized source root is not a directory: %s", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return fmt.Errorf("read materialized source root: %w", err)
	}
	if len(entries) == 0 {
		return writeMaterializedRootMarker(statePath, root)
	}

	markerPath := filepath.Join(root, materializedRootMarkerFile)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return newMaterializedRootSafetyError("materialized source root is not empty and not managed by wrkr scan: %s", root)
		}
		return fmt.Errorf("stat materialized source root marker: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return newMaterializedRootSafetyError("materialized source root marker is not a regular file: %s", markerPath)
	}
	markerPayload, err := os.ReadFile(markerPath) // #nosec G304 -- marker path is deterministic under the selected local materialized source root.
	if err != nil {
		return fmt.Errorf("read materialized source root marker: %w", err)
	}
	if err := managedmarker.ValidatePayload(statePath, root, materializedRootMarkerKind, markerPayload); err != nil {
		return newMaterializedRootSafetyError("materialized source root marker content is invalid: %s", markerPath)
	}
	if !reset {
		return nil
	}

	for _, entry := range entries {
		if entry.Name() == materializedRootMarkerFile {
			continue
		}
		entryPath := filepath.Join(root, entry.Name())
		if err := os.RemoveAll(entryPath); err != nil {
			return fmt.Errorf("clear materialized source root entry %s: %w", entryPath, err)
		}
	}
	return nil
}

func writeMaterializedRootMarker(statePath string, root string) error {
	markerPath := filepath.Join(root, materializedRootMarkerFile)
	payload, err := managedmarker.BuildPayload(statePath, root, materializedRootMarkerKind)
	if err != nil {
		return fmt.Errorf("build materialized source root marker: %w", err)
	}
	if err := os.WriteFile(markerPath, payload, 0o600); err != nil {
		return fmt.Errorf("write materialized source root marker: %w", err)
	}
	return nil
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
		scopes = append(scopes, detect.Scope{
			Org:        orgName,
			Repo:       repo.Repo,
			Root:       location,
			TargetMode: strings.TrimSpace(manifestOut.Target.Mode),
		})
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

func buildSecurityVisibilityReference(previousSnapshot *state.Snapshot, statePath, baselinePath string) agginventory.SecurityVisibilityReference {
	ref := agginventory.SecurityVisibilityReference{
		ReferenceBasis:        "initial_scan",
		KnownToolIDs:          map[string]struct{}{},
		KnownAgentInstanceIDs: map[string]struct{}{},
	}
	if previousSnapshot == nil {
		return ref
	}
	if _, err := os.Stat(statePath); err == nil {
		ref.ReferenceBasis = "state_snapshot"
		ref.ReferencePath = strings.TrimSpace(statePath)
	} else if strings.TrimSpace(baselinePath) != "" {
		ref.ReferenceBasis = "baseline_snapshot"
		ref.ReferencePath = strings.TrimSpace(baselinePath)
	}
	if previousSnapshot.Inventory != nil {
		for _, tool := range previousSnapshot.Inventory.Tools {
			if strings.TrimSpace(tool.ToolID) != "" {
				ref.KnownToolIDs[strings.TrimSpace(tool.ToolID)] = struct{}{}
			}
		}
		for _, agent := range previousSnapshot.Inventory.Agents {
			if strings.TrimSpace(agent.AgentInstanceID) != "" {
				ref.KnownAgentInstanceIDs[strings.TrimSpace(agent.AgentInstanceID)] = struct{}{}
			}
			if toolID := identity.ToolID(agent.Framework, agent.Location); strings.TrimSpace(toolID) != "" {
				ref.KnownToolIDs[toolID] = struct{}{}
			}
		}
	}
	for _, finding := range previousSnapshot.Findings {
		if !model.IsIdentityBearingFinding(finding) {
			continue
		}
		toolID := identity.ToolID(finding.ToolType, finding.Location)
		if strings.TrimSpace(toolID) != "" {
			ref.KnownToolIDs[toolID] = struct{}{}
		}
		symbol := findingAgentSymbol(finding)
		startLine, endLine := findingRangeLines(finding)
		instanceID := identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
		if strings.TrimSpace(instanceID) != "" {
			ref.KnownAgentInstanceIDs[instanceID] = struct{}{}
		}
	}
	return ref
}

func loadManifest(path string) (manifest.Manifest, error) {
	loaded, err := manifest.Load(path)
	if err == nil {
		loaded.Identities = filterLegacyArtifactIdentities(loaded.Identities)
		return loaded, nil
	}
	if errors.Is(err, os.ErrNotExist) || strings.Contains(strings.ToLower(err.Error()), "no such file") {
		return manifest.Manifest{Version: manifest.Version, Identities: []manifest.IdentityRecord{}}, nil
	}
	return manifest.Manifest{}, err
}

func loadLifecycleManifest(manifestPath, statePath string, previousSnapshot *state.Snapshot) (manifest.Manifest, error) {
	loaded, err := loadManifest(manifestPath)
	if err != nil {
		return manifest.Manifest{}, err
	}
	if previousSnapshot == nil {
		return loaded, nil
	}

	stateInfo, err := os.Stat(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return loaded, nil
		}
		return manifest.Manifest{}, fmt.Errorf("stat state for lifecycle manifest: %w", err)
	}

	manifestInfo, err := os.Stat(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return manifestFromSnapshot(*previousSnapshot, stateInfo.ModTime()), nil
		}
		return manifest.Manifest{}, fmt.Errorf("stat lifecycle manifest: %w", err)
	}

	if stateInfo.ModTime().After(manifestInfo.ModTime()) {
		return manifestFromSnapshot(*previousSnapshot, stateInfo.ModTime()), nil
	}
	return loaded, nil
}

func manifestFromSnapshot(snapshot state.Snapshot, updatedAt time.Time) manifest.Manifest {
	identities := filterLegacyArtifactIdentities(snapshot.Identities)
	manifestOut := manifest.Manifest{
		Version:    manifest.Version,
		Identities: identities,
	}
	if !updatedAt.IsZero() {
		manifestOut.UpdatedAt = updatedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	return manifestOut
}

func filterLegacyArtifactIdentities(records []manifest.IdentityRecord) []manifest.IdentityRecord {
	filtered := model.FilterLegacyArtifactIdentityRecords(records)
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].AgentID != filtered[j].AgentID {
			return filtered[i].AgentID < filtered[j].AgentID
		}
		if filtered[i].Repo != filtered[j].Repo {
			return filtered[i].Repo < filtered[j].Repo
		}
		return filtered[i].Location < filtered[j].Location
	})
	return filtered
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
		symbol := findingAgentSymbol(finding)
		startLine, endLine := findingRangeLines(finding)
		toolID := identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
		agentID := identity.AgentID(toolID, org)
		legacyAgentID := identity.LegacyAgentID(finding.ToolType, finding.Location, org)
		ctx := contexts[agginventory.KeyForFinding(finding)]
		candidate := lifecycle.ObservedTool{
			AgentID:       agentID,
			LegacyAgentID: legacyAgentID,
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
		symbol := findingAgentSymbol(finding)
		startLine, endLine := findingRangeLines(finding)
		instanceToolID := identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
		agentID := identity.AgentID(instanceToolID, org)
		record, exists := identities[agentID]
		if !exists {
			record, exists = identities[identity.LegacyAgentID(finding.ToolType, finding.Location, org)]
		}
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

func findingAgentSymbol(finding source.Finding) string {
	index := map[string]string{}
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "" {
			continue
		}
		index[key] = strings.TrimSpace(evidence.Value)
	}
	for _, key := range []string{
		"symbol",
		"name",
		"agent_name",
		"agent.symbol",
		"agent.name",
		"function",
		"class",
	} {
		if value := strings.TrimSpace(index[key]); value != "" {
			return value
		}
	}
	return ""
}

func findingRangeLines(finding source.Finding) (int, int) {
	if finding.LocationRange == nil {
		return 0, 0
	}
	return finding.LocationRange.StartLine, finding.LocationRange.EndLine
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
