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

type repeatedStringFlag []string

func (f *repeatedStringFlag) String() string {
	if f == nil || len(*f) == 0 {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *repeatedStringFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
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

func resolveScanTargets(repo, orgInput, githubOrgInput, pathInput string, mySetup bool, explicitTargets []string, configPath string) ([]config.Target, config.Config, error) {
	hasLegacyInputs := strings.TrimSpace(repo) != "" || strings.TrimSpace(orgInput) != "" || strings.TrimSpace(githubOrgInput) != "" || strings.TrimSpace(pathInput) != "" || mySetup
	legacyTargets, legacyErr := resolveLegacyScanTargets(repo, orgInput, githubOrgInput, pathInput, mySetup)
	if len(explicitTargets) > 0 {
		if len(legacyTargets) > 0 {
			return nil, config.Config{}, fmt.Errorf("cannot combine legacy scan target flags with --target; use one style per command")
		}
		if legacyErr != nil && hasLegacyInputs {
			return nil, config.Config{}, legacyErr
		}
		targets, err := parseExplicitScanTargets(explicitTargets)
		if err != nil {
			return nil, config.Config{}, err
		}
		return targets, config.Default(), nil
	}
	if legacyErr != nil && hasLegacyInputs {
		return nil, config.Config{}, legacyErr
	}
	if len(legacyTargets) > 0 {
		return legacyTargets, config.Default(), nil
	}

	resolvedPath, pathErr := config.ResolvePath(configPath)
	if pathErr != nil {
		return nil, config.Config{}, pathErr
	}
	cfg, loadErr := config.Load(resolvedPath)
	if loadErr != nil {
		return nil, config.Config{}, fmt.Errorf("no target provided and no usable config default target (%v)", loadErr)
	}
	return []config.Target{cfg.DefaultTarget}, cfg, nil
}

func resolveLegacyScanTargets(repo, orgInput, githubOrgInput, pathInput string, mySetup bool) ([]config.Target, error) {
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

	if len(targets) == 0 {
		return nil, nil
	}
	if len(targets) != 1 {
		return nil, fmt.Errorf("exactly one target source is required: use one of --repo, --org, --github-org, --path, --my-setup")
	}
	if err := config.ValidateTarget(targets[0].Mode, targets[0].Value); err != nil {
		return nil, err
	}
	return targets, nil
}

func parseExplicitScanTargets(rawTargets []string) ([]config.Target, error) {
	targets := make([]config.Target, 0, len(rawTargets))
	for _, raw := range rawTargets {
		target, err := parseExplicitScanTarget(raw)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}
	return normalizeScanTargets(targets), nil
}

func parseExplicitScanTarget(raw string) (config.Target, error) {
	modeRaw, valueRaw, ok := strings.Cut(strings.TrimSpace(raw), ":")
	if !ok {
		return config.Target{}, fmt.Errorf("--target values must use <mode>:<value>")
	}
	mode := config.TargetMode(strings.TrimSpace(modeRaw))
	value := strings.TrimSpace(valueRaw)
	if mode == config.TargetMySetup {
		if value != localsetup.TargetValue {
			return config.Target{}, fmt.Errorf("--target my_setup must use value %q", localsetup.TargetValue)
		}
	}
	if err := config.ValidateTarget(mode, value); err != nil {
		return config.Target{}, err
	}
	return config.Target{Mode: mode, Value: value}, nil
}

func normalizeScanTargets(targets []config.Target) []config.Target {
	if len(targets) == 0 {
		return nil
	}
	normalized := append([]config.Target(nil), targets...)
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Mode == normalized[j].Mode {
			return normalized[i].Value < normalized[j].Value
		}
		return normalized[i].Mode < normalized[j].Mode
	})
	deduped := make([]config.Target, 0, len(normalized))
	for _, target := range normalized {
		if len(deduped) > 0 && deduped[len(deduped)-1] == target {
			continue
		}
		deduped = append(deduped, target)
	}
	return deduped
}

func acquireSources(ctx context.Context, targets []config.Target, githubBaseURL, githubToken string, opts acquireOptions) (source.Manifest, []source.Finding, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return source.Manifest{}, nil, ctxErr
	}
	targets = normalizeScanTargets(targets)
	if len(targets) == 0 {
		return source.Manifest{}, nil, fmt.Errorf("at least one scan target is required")
	}

	connector := github.NewConnector(githubBaseURL, githubToken, nil)
	manifestOut := source.Manifest{
		Target:  manifestTargetFromTargets(targets),
		Targets: manifestTargets(targets),
	}
	materializeRoot := ""
	if targetsNeedMaterializedRoot(targets) {
		var (
			root string
			err  error
		)
		if opts.Resume {
			root, err = prepareMaterializedRootForResume(opts.StatePath)
		} else {
			root, err = prepareMaterializedRoot(opts.StatePath)
		}
		if err != nil {
			return source.Manifest{}, nil, err
		}
		materializeRoot = root
	}
	if opts.Resume {
		if !allTargetsAreOrg(targets) {
			return source.Manifest{}, nil, fmt.Errorf("--resume is only supported when every requested target is an org target")
		}
		targetSet := make([]string, 0, len(targets))
		for _, target := range targets {
			targetSet = append(targetSet, target.Value)
		}
		if err := org.ValidateTargetSet(opts.StatePath, targetSet, materializeRoot); err != nil {
			return source.Manifest{}, nil, err
		}
	} else if allTargetsAreOrg(targets) {
		targetSet := make([]string, 0, len(targets))
		for _, target := range targets {
			targetSet = append(targetSet, target.Value)
		}
		if err := org.SaveTargetSet(opts.StatePath, targetSet, materializeRoot); err != nil {
			return source.Manifest{}, nil, err
		}
	}

	seenRepos := map[string]struct{}{}
	for _, target := range targets {
		targetManifest, err := acquireTarget(ctx, connector, target, githubBaseURL, githubToken, materializeRoot, opts)
		if err != nil {
			if shouldRetryOrgTargetWithoutResume(targets, target, opts.Resume, err) {
				retryOpts := opts
				retryOpts.Resume = false
				targetManifest, err = acquireTarget(ctx, connector, target, githubBaseURL, githubToken, materializeRoot, retryOpts)
			}
			if err != nil {
				if len(targets) == 1 || isTargetAcquisitionFatal(err) {
					return source.Manifest{}, nil, err
				}
				manifestOut.Failures = append(manifestOut.Failures, source.RepoFailure{
					Repo:   renderScanTarget(target),
					Reason: err.Error(),
				})
				continue
			}
		}
		manifestOut.Failures = append(manifestOut.Failures, targetManifest.Failures...)
		for _, repoManifest := range targetManifest.Repos {
			key := repoIdentityKey(repoManifest)
			if _, ok := seenRepos[key]; ok {
				continue
			}
			seenRepos[key] = struct{}{}
			manifestOut.Repos = append(manifestOut.Repos, repoManifest)
		}
	}

	manifestOut = source.SortManifest(manifestOut)
	findings := buildSourceFindings(manifestOut.Repos)
	source.SortFindings(findings)
	return manifestOut, findings, nil
}

func acquireTarget(ctx context.Context, connector *github.Connector, target config.Target, githubBaseURL, githubToken, materializeRoot string, opts acquireOptions) (source.Manifest, error) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return source.Manifest{}, ctxErr
	}
	manifestOut := source.Manifest{Target: source.Target{Mode: string(target.Mode), Value: target.Value}}
	switch target.Mode {
	case config.TargetRepo:
		repoManifest, err := connector.AcquireRepo(ctx, target.Value)
		if err != nil {
			return source.Manifest{}, err
		}
		materialized, materializeErr := connector.MaterializeRepo(ctx, repoManifest.Repo, materializeRoot)
		if materializeErr != nil {
			return source.Manifest{}, fmt.Errorf("materialize repo %s: %w", repoManifest.Repo, materializeErr)
		}
		manifestOut.Repos = []source.RepoManifest{materialized}
	case config.TargetOrg:
		connector.SetRetryHandler(func(event github.RetryEvent) {
			if opts.Progress == nil {
				return
			}
			opts.Progress.Retry(target.Value, event.Attempt, event.Delay, event.StatusCode)
		})
		connector.SetCooldownHandler(func(event github.CooldownEvent) {
			if opts.Progress == nil {
				return
			}
			opts.Progress.Cooldown(target.Value, event.Delay, event.Until)
		})
		repos, failures, err := org.AcquireMaterialized(ctx, target.Value, connector, connector, org.AcquireMaterializedOptions{
			StatePath:        opts.StatePath,
			MaterializedRoot: materializeRoot,
			Resume:           opts.Resume,
			Progress:         opts.Progress,
		})
		if err != nil {
			return source.Manifest{}, err
		}
		manifestOut.Repos = repos
		manifestOut.Failures = failures
	case config.TargetPath:
		repos, err := local.Acquire(target.Value)
		if err != nil {
			return source.Manifest{}, err
		}
		manifestOut.Repos = repos
	case config.TargetMySetup:
		repos, err := localsetup.Acquire()
		if err != nil {
			return source.Manifest{}, err
		}
		manifestOut.Repos = repos
	default:
		return source.Manifest{}, fmt.Errorf("unsupported target mode %q", target.Mode)
	}
	return source.SortManifest(manifestOut), nil
}

func manifestTargetFromTargets(targets []config.Target) source.Target {
	if len(targets) == 1 {
		return source.Target{Mode: string(targets[0].Mode), Value: targets[0].Value}
	}
	return source.Target{Mode: source.TargetModeMulti}
}

func manifestTargets(targets []config.Target) []source.Target {
	if len(targets) <= 1 {
		return nil
	}
	out := make([]source.Target, 0, len(targets))
	for _, target := range targets {
		out = append(out, source.Target{Mode: string(target.Mode), Value: target.Value})
	}
	return source.SortTargets(out)
}

func targetsNeedMaterializedRoot(targets []config.Target) bool {
	for _, target := range targets {
		if target.Mode == config.TargetRepo || target.Mode == config.TargetOrg {
			return true
		}
	}
	return false
}

func allTargetsAreOrg(targets []config.Target) bool {
	if len(targets) == 0 {
		return false
	}
	for _, target := range targets {
		if target.Mode != config.TargetOrg {
			return false
		}
	}
	return true
}

func anyTargetIsOrg(targets []config.Target) bool {
	for _, target := range targets {
		if target.Mode == config.TargetOrg {
			return true
		}
	}
	return false
}

func anyTargetIsMySetup(targets []config.Target) bool {
	for _, target := range targets {
		if target.Mode == config.TargetMySetup {
			return true
		}
	}
	return false
}

func anyTargetNeedsGitHub(targets []config.Target) bool {
	for _, target := range targets {
		if target.Mode == config.TargetRepo || target.Mode == config.TargetOrg {
			return true
		}
	}
	return false
}

func renderScanTarget(target config.Target) string {
	return fmt.Sprintf("%s:%s", target.Mode, target.Value)
}

func renderScanTargetSet(targets []config.Target) string {
	rendered := make([]string, 0, len(targets))
	for _, target := range targets {
		rendered = append(rendered, renderScanTarget(target))
	}
	return strings.Join(rendered, ",")
}

func shouldRetryOrgTargetWithoutResume(targets []config.Target, target config.Target, resume bool, err error) bool {
	return resume && len(targets) > 1 && target.Mode == config.TargetOrg && org.IsCheckpointMissingError(err)
}

func isTargetAcquisitionFatal(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return true
	case isMaterializedRootSafetyError(err):
		return true
	case org.IsCheckpointSafetyError(err), org.IsCheckpointInputError(err):
		return true
	default:
		return false
	}
}

func repoIdentityKey(repo source.RepoManifest) string {
	if strings.HasPrefix(strings.TrimSpace(repo.Source), "github_") {
		return "github:" + strings.ToLower(strings.TrimSpace(repo.Repo))
	}
	location := filepath.Clean(filepath.FromSlash(strings.TrimSpace(repo.Location)))
	if abs, err := filepath.Abs(location); err == nil {
		location = abs
	}
	if resolved, err := filepath.EvalSymlinks(location); err == nil {
		location = resolved
	}
	return strings.TrimSpace(repo.Source) + ":" + filepath.ToSlash(location)
}

func buildSourceFindings(repos []source.RepoManifest) []source.Finding {
	findings := make([]source.Finding, 0, len(repos))
	for _, repoManifest := range repos {
		orgName := "local"
		permission := "filesystem.read"
		if strings.HasPrefix(strings.TrimSpace(repoManifest.Source), "github_") {
			orgName = repoOwner(repoManifest.Repo)
			permission = "repo.contents.read"
		}
		findings = append(findings, source.Finding{
			FindingType: "source_discovery",
			Severity:    "low",
			ToolType:    "source_repo",
			Location:    repoManifest.Location,
			Repo:        repoManifest.Repo,
			Org:         orgName,
			Permissions: []string{permission},
			Detector:    "source",
		})
	}
	return findings
}

func repoOwner(repo string) string {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) > 1 && strings.TrimSpace(parts[0]) != "" {
		return parts[0]
	}
	return "local"
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
		orgName := deriveOrg(repo)
		scopes = append(scopes, detect.Scope{
			Org:        orgName,
			Repo:       repo.Repo,
			Root:       location,
			TargetMode: scopeTargetMode(manifestOut.Target, repo),
		})
	}
	return scopes
}

func deriveOrg(repo source.RepoManifest) string {
	if strings.HasPrefix(strings.TrimSpace(repo.Source), "github_") {
		return repoOwner(repo.Repo)
	}
	return "local"
}

func scopeTargetMode(target source.Target, repo source.RepoManifest) string {
	if strings.TrimSpace(repo.Source) == "local_machine" {
		return string(config.TargetMySetup)
	}
	if strings.TrimSpace(repo.Source) == "local_path" {
		return string(config.TargetPath)
	}
	return strings.TrimSpace(target.Mode)
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
