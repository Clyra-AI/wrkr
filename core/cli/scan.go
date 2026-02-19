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
	"github.com/Clyra-AI/wrkr/core/diff"
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

	switch mode {
	case config.TargetRepo:
		repoManifest, err := connector.AcquireRepo(ctx, value)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifest.Repos = []source.RepoManifest{repoManifest}
		owner := strings.Split(value, "/")[0]
		findings = append(findings, source.Finding{ToolType: "source_repo", Location: repoManifest.Location, Org: owner, Permissions: []string{"repo.contents.read"}})
	case config.TargetOrg:
		repos, failures, err := org.Acquire(ctx, value, connector, connector)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifest.Repos = repos
		manifest.Failures = failures
		for _, repo := range repos {
			findings = append(findings, source.Finding{ToolType: "source_repo", Location: repo.Location, Org: value, Permissions: []string{"repo.contents.read"}})
		}
	case config.TargetPath:
		repos, err := local.Acquire(value)
		if err != nil {
			return source.Manifest{}, nil, err
		}
		manifest.Repos = repos
		for _, repo := range repos {
			findings = append(findings, source.Finding{ToolType: "source_repo", Location: filepath.ToSlash(repo.Location), Org: "local", Permissions: []string{"filesystem.read"}})
		}
	default:
		return source.Manifest{}, nil, fmt.Errorf("unsupported target mode %q", mode)
	}

	manifest = source.SortManifest(manifest)
	source.SortFindings(findings)
	return manifest, findings, nil
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
