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
	"strings"

	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/detect"
	detectdefaults "github.com/Clyra-AI/wrkr/core/detect/defaults"
	"github.com/Clyra-AI/wrkr/core/diff"
	"github.com/Clyra-AI/wrkr/core/policy"
	policyeval "github.com/Clyra-AI/wrkr/core/policy/eval"
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
			7,
		)
	}

	ctx := context.Background()
	manifest, findings, err := acquireSources(ctx, targetMode, targetValue, *githubBaseURL, *githubToken)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	scopes := detectorScopes(manifest)
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
			return emitError(stderr, jsonRequested || *jsonOut, "policy_schema_violation", policyErr.Error(), 3)
		}
		findings = append(findings, policyFindings...)
	}

	source.SortFindings(findings)

	statePath := state.ResolvePath(*statePathFlag)
	snapshot := state.Snapshot{Version: state.SnapshotVersion, Target: manifest.Target, Findings: findings}

	payload := map[string]any{
		"status":          "ok",
		"target":          manifest.Target,
		"source_manifest": manifest,
	}

	if *diffMode {
		previous, loadErr := state.Load(statePath)
		if loadErr != nil {
			if strings.TrimSpace(*baselinePath) != "" {
				previous, loadErr = state.Load(*baselinePath)
			}
		}
		if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
			if !errors.Is(loadErr, os.ErrNotExist) && !strings.Contains(loadErr.Error(), "no such file") {
				return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", loadErr.Error(), exitRuntime)
			}
		}
		result := diff.Compute(previous.Findings, findings)
		payload["diff"] = result
		payload["diff_empty"] = diff.Empty(result)
	} else {
		payload["findings"] = findings
		payload["top_findings"] = topFindings(findings, 5)
	}

	if err := state.Save(statePath, snapshot); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if *quiet {
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr scan completed for %s:%s\n", targetMode, targetValue)
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

	manifest := source.Manifest{Target: source.Target{Mode: string(mode), Value: value}}
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
		manifest.Repos = []source.RepoManifest{repoManifest}
		owner := strings.Split(value, "/")[0]
		findings = append(findings, sourceFinding(repoManifest, owner, "repo.contents.read"))
	case config.TargetOrg:
		repos, failures, err := org.Acquire(ctx, value, connector, connector)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifest.Repos = repos
		manifest.Failures = failures
		for _, repoManifest := range repos {
			findings = append(findings, sourceFinding(repoManifest, value, "repo.contents.read"))
		}
	case config.TargetPath:
		repos, err := local.Acquire(value)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifest.Repos = repos
		for _, repoManifest := range repos {
			repoManifest.Location = filepath.ToSlash(repoManifest.Location)
			findings = append(findings, sourceFinding(repoManifest, "local", "filesystem.read"))
		}
	default:
		return source.Manifest{}, nil, fmt.Errorf("unsupported target mode %q", mode)
	}

	manifest = source.SortManifest(manifest)
	source.SortFindings(findings)
	return manifest, findings, nil
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

func detectorScopes(manifest source.Manifest) []detect.Scope {
	scopes := make([]detect.Scope, 0, len(manifest.Repos))
	for _, repo := range manifest.Repos {
		info, err := os.Stat(repo.Location)
		if err != nil || !info.IsDir() {
			continue
		}
		orgName := deriveOrg(manifest.Target, repo)
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

func topFindings(findings []source.Finding, limit int) []source.Finding {
	if limit <= 0 || len(findings) == 0 {
		return []source.Finding{}
	}
	if len(findings) <= limit {
		out := make([]source.Finding, len(findings))
		copy(out, findings)
		return out
	}
	out := make([]source.Finding, limit)
	copy(out, findings[:limit])
	return out
}
