package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentdeploy"
	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggexposure "github.com/Clyra-AI/wrkr/core/aggregate/exposure"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/privilegebudget"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/detect"
	detectdefaults "github.com/Clyra-AI/wrkr/core/detect/defaults"
	"github.com/Clyra-AI/wrkr/core/diff"
	exportsarif "github.com/Clyra-AI/wrkr/core/export/sarif"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/policy/approvedtools"
	"github.com/Clyra-AI/wrkr/core/policy/productiontargets"
	profilemodel "github.com/Clyra-AI/wrkr/core/policy/profile"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	sourceorg "github.com/Clyra-AI/wrkr/core/source/org"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runScanWithContext(parentCtx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	if parentCtx == nil {
		parentCtx = context.Background()
	}

	jsonRequested := wantsJSONOutput(args)

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	jsonPath := fs.String("json-path", "", "write final machine-readable output to a file path")
	resume := fs.Bool("resume", false, "resume a prior interrupted org scan from checkpoint state")
	explain := fs.Bool("explain", false, "emit rationale details")
	quiet := fs.Bool("quiet", false, "suppress non-error output")
	repo := fs.String("repo", "", "scan one repo owner/repo")
	orgTarget := fs.String("org", "", "scan an organization")
	githubOrgTarget := fs.String("github-org", "", "scan an organization (alias for --org)")
	mySetup := fs.Bool("my-setup", false, "scan the local machine setup for AI tool posture")
	pathTarget := fs.String("path", "", "scan local pre-cloned repositories")
	timeout := fs.Duration("timeout", 0, "optional scan timeout (0 disables)")
	diffMode := fs.Bool("diff", false, "show only changes since previous scan")
	enrich := fs.Bool("enrich", false, "enable non-deterministic enrichment lookups (network required)")
	baselinePath := fs.String("baseline", "", "optional fallback baseline when local state is absent")
	configPathFlag := fs.String("config", "", "config file path override")
	statePathFlag := fs.String("state", "", "state file path override")
	policyPath := fs.String("policy", "", "optional custom policy rule file")
	approvedToolsPath := fs.String("approved-tools", "", "optional approved tools policy file")
	productionTargetsPath := fs.String("production-targets", "", "optional production target rules file")
	productionTargetsStrict := fs.Bool("production-targets-strict", false, "fail scan when production target rules cannot be loaded")
	profileName := fs.String("profile", "standard", "posture profile [baseline|standard|strict]")
	githubBaseURL := fs.String("github-api", strings.TrimSpace(os.Getenv("WRKR_GITHUB_API_BASE")), "github api base url")
	githubToken := fs.String("github-token", "", "github token override")
	reportMD := fs.Bool("report-md", false, "emit deterministic markdown summary artifact after scan")
	reportMDPath := fs.String("report-md-path", "wrkr-scan-summary.md", "scan summary markdown output path")
	reportTemplate := fs.String("report-template", string(reportcore.TemplateOperator), "scan summary template [exec|operator|audit|public]")
	reportShareProfile := fs.String("report-share-profile", string(reportcore.ShareProfileInternal), "scan summary share profile [internal|public]")
	reportTop := fs.Int("report-top", 5, "number of top findings included in scan summary artifact")
	sarifOut := fs.Bool("sarif", false, "emit SARIF artifact")
	sarifPath := fs.String("sarif-path", "wrkr.sarif", "SARIF output path")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if *timeout < 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--timeout must be >= 0", exitInvalidInput)
	}
	jsonSink, jsonSinkErr := newJSONOutputSink(*jsonOut, *jsonPath, stdout)
	if jsonSinkErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", jsonSinkErr.Error(), exitInvalidInput)
	}
	productionTargetsFile := strings.TrimSpace(*productionTargetsPath)
	if *productionTargetsStrict && productionTargetsFile == "" {
		return emitError(
			stderr,
			jsonRequested || *jsonOut,
			"invalid_input",
			"--production-targets-strict requires --production-targets <path>",
			exitInvalidInput,
		)
	}

	hasExplicitTarget := strings.TrimSpace(*repo) != "" || strings.TrimSpace(*orgTarget) != "" || strings.TrimSpace(*githubOrgTarget) != "" || strings.TrimSpace(*pathTarget) != "" || *mySetup
	loadedCfg, hasLoadedCfg, cfgLoadErr := loadOptionalScanConfig(*configPathFlag, hasExplicitTarget)
	if cfgLoadErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", cfgLoadErr.Error(), exitRuntime)
	}
	targetMode, targetValue, cfg, err := resolveScanTarget(*repo, *orgTarget, *githubOrgTarget, *pathTarget, *mySetup, *configPathFlag)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if *resume && targetMode != config.TargetOrg {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--resume is only supported with --org or --github-org scans", exitInvalidInput)
	}
	if hasLoadedCfg {
		cfg.Auth = loadedCfg.Auth
	}
	*githubToken = resolveScanGitHubToken(*githubToken, cfg)
	if *enrich && strings.TrimSpace(*githubBaseURL) == "" {
		return emitError(
			stderr,
			jsonRequested || *jsonOut,
			"dependency_missing",
			"--enrich requires a reachable network source; set --github-api or WRKR_GITHUB_API_BASE",
			exitDependencyMissing,
		)
	}
	if (targetMode == config.TargetRepo || targetMode == config.TargetOrg) && strings.TrimSpace(*githubBaseURL) == "" {
		return emitError(
			stderr,
			jsonRequested || *jsonOut,
			"dependency_missing",
			"--repo and --org scans require --github-api or WRKR_GITHUB_API_BASE",
			exitDependencyMissing,
		)
	}
	statePath := state.ResolvePath(*statePathFlag)

	ctx := parentCtx
	cancel := func() {}
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(parentCtx, *timeout)
	}
	defer cancel()
	scanStartedAt := time.Now().UTC().Truncate(time.Second)
	progress := newScanProgressReporter(*jsonOut && !*quiet && targetMode == config.TargetOrg, stderr)
	emitScanFailure := func(err error) int {
		progress.Flush()
		return emitScanRuntimeError(stderr, jsonRequested || *jsonOut, err)
	}
	emitScanError := func(code, message string, exitCode int) int {
		progress.Flush()
		return emitError(stderr, jsonRequested || *jsonOut, code, message, exitCode)
	}
	manifestOut, findings, err := acquireSources(ctx, targetMode, targetValue, *githubBaseURL, *githubToken, acquireOptions{
		StatePath: statePath,
		Progress:  progress,
		Resume:    *resume,
	})
	if err != nil {
		return emitScanFailure(err)
	}

	scopes := detectorScopes(manifestOut)
	detectorErrors := []detect.DetectorError{}
	if len(scopes) > 0 {
		registry, regErr := detectdefaults.Registry()
		if regErr != nil {
			return emitScanFailure(regErr)
		}
		detected, runErr := registry.Run(ctx, scopes, detect.Options{Enrich: *enrich})
		if runErr != nil {
			return emitScanFailure(runErr)
		}
		findings = append(findings, detected.Findings...)
		detectorErrors = append(detectorErrors, detected.DetectorErrors...)

		policyFindings, policyErr := evaluatePolicies(scopes, findings, strings.TrimSpace(*policyPath))
		if policyErr != nil {
			return emitScanError("policy_schema_violation", policyErr.Error(), exitPolicyViolation)
		}
		findings = append(findings, policyFindings...)
	}
	source.SortFindings(findings)

	previousSnapshot, loadPreviousErr := loadPreviousSnapshot(statePath, strings.TrimSpace(*baselinePath))
	if loadPreviousErr != nil {
		return emitScanFailure(loadPreviousErr)
	}

	now := time.Now().UTC().Truncate(time.Second)
	scanMethodology := buildScanMethodology(manifestOut, findings, scanStartedAt, now)
	riskReport := risk.Score(findings, 5, now)
	repoRisk := map[string]float64{}
	for _, repo := range riskReport.Repos {
		repoRisk[repo.Org+"::"+repo.Repo] = repo.Score
	}

	manifestPath := manifest.ResolvePath(statePath)
	previousManifest, manifestErr := loadLifecycleManifest(manifestPath, statePath, previousSnapshot)
	if manifestErr != nil {
		return emitScanFailure(manifestErr)
	}

	baseContexts := buildFindingContexts(riskReport)
	observed := observedTools(findings, baseContexts)
	nextManifest, transitions := lifecycle.Reconcile(previousManifest, observed, now)

	identityByAgent := map[string]manifest.IdentityRecord{}
	for _, record := range nextManifest.Identities {
		identityByAgent[record.AgentID] = record
	}
	contexts := enrichFindingContexts(findings, baseContexts, identityByAgent)

	repoExposure := aggexposure.Build(findings, repoRisk)
	agentBindings := agentresolver.Resolve(findings)
	agentDeployments := agentdeploy.Resolve(findings)
	inventoryOut := agginventory.Build(agginventory.BuildInput{
		Manifest:              manifestOut,
		Findings:              findings,
		Contexts:              contexts,
		AgentBindings:         agentBindings,
		AgentDeployments:      agentDeployments,
		Methodology:           scanMethodology,
		RepoExposureSummaries: repoExposure,
		GeneratedAt:           now,
	})
	if approvedToolsPolicyPath := strings.TrimSpace(*approvedToolsPath); approvedToolsPolicyPath != "" {
		approvedCfg, approvedErr := approvedtools.Load(approvedToolsPolicyPath)
		if approvedErr != nil {
			return emitScanError("invalid_input", approvedErr.Error(), exitInvalidInput)
		}
		if approvedCfg.HasRules() {
			agginventory.ReclassifyApprovalWithMatcher(&inventoryOut, func(tool agginventory.Tool) bool {
				return approvedCfg.Match(approvedtools.ToolCandidate{
					ToolID:   tool.ToolID,
					AgentID:  tool.AgentID,
					ToolType: tool.ToolType,
					Org:      tool.Org,
					Repos:    tool.Repos,
				})
			})
		}
	}
	agginventory.ApplySecurityVisibility(&inventoryOut, buildSecurityVisibilityReference(previousSnapshot, statePath, strings.TrimSpace(*baselinePath)))
	var productionTargets *productiontargets.Config
	productionTargetWarnings := []string{}
	productionWriteStatus := agginventory.ProductionTargetsStatusNotConfigured
	if productionTargetsFile != "" {
		cfg, cfgErr := productiontargets.Load(productionTargetsFile)
		if cfgErr != nil {
			if *productionTargetsStrict {
				return emitScanError("invalid_input", cfgErr.Error(), exitInvalidInput)
			}
			productionWriteStatus = agginventory.ProductionTargetsStatusInvalid
			productionTargetWarnings = append(productionTargetWarnings, fmt.Sprintf("production targets not applied: %v", cfgErr))
		} else if cfg.HasTargets() {
			productionTargets = &cfg
			productionWriteStatus = agginventory.ProductionTargetsStatusConfigured
		} else {
			productionTargetWarnings = append(productionTargetWarnings, fmt.Sprintf("production targets file %s has no configured targets; production_write budget is not configured", productionTargetsFile))
		}
	}
	inventoryOut.PrivilegeBudget, inventoryOut.AgentPrivilegeMap = privilegebudget.Build(inventoryOut.Tools, inventoryOut.Agents, findings, productionTargets)
	inventoryOut.PrivilegeBudget.ProductionWrite.Status = productionWriteStatus
	inventoryOut.PrivilegeBudget.ProductionWrite.Configured = productionWriteStatus == agginventory.ProductionTargetsStatusConfigured
	if !inventoryOut.PrivilegeBudget.ProductionWrite.Configured {
		inventoryOut.PrivilegeBudget.ProductionWrite.Count = nil
	}
	for idx := range inventoryOut.AgentPrivilegeMap {
		inventoryOut.AgentPrivilegeMap[idx].ProductionTargetStatus = productionWriteStatus
	}
	agginventory.ApplySecurityVisibilityToPrivilegeMap(&inventoryOut)
	riskReport.ActionPaths, riskReport.ActionPathToControlFirst = risk.BuildActionPaths(riskReport.AttackPaths, &inventoryOut)

	profileDef, profileErr := profilemodel.Builtin(*profileName)
	if profileErr != nil {
		return emitScanError("unsafe_operation_blocked", profileErr.Error(), exitUnsafeBlocked)
	}
	profileDef, profileErr = profilemodel.WithOverrides(profileDef, strings.TrimSpace(*policyPath), repoRootFromScopes(scopes))
	if profileErr != nil {
		return emitScanError("policy_schema_violation", profileErr.Error(), exitPolicyViolation)
	}
	var previousProfile *profileeval.Result
	if previousSnapshot != nil && previousSnapshot.Profile != nil {
		copyResult := *previousSnapshot.Profile
		previousProfile = &copyResult
	}
	profileResult := profileeval.Evaluate(profileDef, findings, previousProfile)

	weights, weightErr := score.LoadWeights(strings.TrimSpace(*policyPath), repoRootFromScopes(scopes))
	if weightErr != nil {
		return emitScanError("policy_schema_violation", weightErr.Error(), exitPolicyViolation)
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
		return emitScanFailure(err)
	}
	chainPath := lifecycle.ChainPath(statePath)
	chain, chainErr := lifecycle.LoadChain(chainPath)
	if chainErr != nil {
		return emitScanFailure(chainErr)
	}
	for _, transition := range transitions {
		if err := lifecycle.AppendTransitionRecord(chain, transition, "lifecycle_transition"); err != nil {
			return emitScanFailure(err)
		}
	}
	if err := lifecycle.SaveChain(chainPath, chain); err != nil {
		return emitScanFailure(err)
	}
	if _, err := proofemit.EmitScan(statePath, now, findings, &inventoryOut, riskReport, profileResult, postureScore, transitions); err != nil {
		return emitScanFailure(err)
	}
	proofChain, err := proofemit.LoadChain(proofemit.ChainPath(statePath))
	if err != nil {
		return emitScanFailure(err)
	}
	complianceSummary, err := compliance.BuildRollupSummary(findings, proofChain)
	if err != nil {
		return emitScanError("policy_schema_violation", err.Error(), exitPolicyViolation)
	}
	if err := manifest.Save(manifestPath, nextManifest); err != nil {
		return emitScanFailure(err)
	}

	payload := map[string]any{
		"status":          "ok",
		"target":          manifestOut.Target,
		"source_manifest": manifestOut,
	}
	if len(manifestOut.Failures) > 0 {
		payload["partial_result"] = true
		payload["source_errors"] = manifestOut.Failures
		payload["source_degraded"] = hasDegradedFailures(manifestOut.Failures)
	}
	if len(detectorErrors) > 0 {
		payload["detector_errors"] = detectorErrors
	}
	if warnings := reportcore.MCPVisibilityWarnings(findings); len(warnings) > 0 {
		payload["warnings"] = warnings
	}
	if len(productionTargetWarnings) > 0 {
		payload["policy_warnings"] = append([]string(nil), productionTargetWarnings...)
	}
	scanReportPath := ""
	scanSARIFPath := ""

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
		payload["attack_paths"] = riskReport.AttackPaths
		payload["top_attack_paths"] = riskReport.TopAttackPaths
		if len(riskReport.ActionPaths) > 0 {
			payload["action_paths"] = riskReport.ActionPaths
		}
		if riskReport.ActionPathToControlFirst != nil {
			payload["action_path_to_control_first"] = riskReport.ActionPathToControlFirst
		}
		payload["inventory"] = inventoryOut
		payload["privilege_budget"] = inventoryOut.PrivilegeBudget
		payload["agent_privilege_map"] = inventoryOut.AgentPrivilegeMap
		payload["repo_exposure_summaries"] = repoExposure
		payload["profile"] = profileResult
		payload["posture_score"] = postureScore
		payload["compliance_summary"] = complianceSummary
		if activation := reportcore.BuildActivation(manifestOut.Target.Mode, riskReport.Ranked, &inventoryOut, 5); activation != nil {
			payload["activation"] = activation
		}
	}
	if *reportMD {
		template, shareProfile, parseErr := parseReportTemplateShare(*reportTemplate, *reportShareProfile)
		if parseErr != nil {
			return emitScanError("invalid_input", parseErr.Error(), exitInvalidInput)
		}
		manifestCopy := nextManifest
		_, mdOutPath, _, reportErr := generateReportArtifacts(reportArtifactOptions{
			StatePath:        statePath,
			Snapshot:         snapshot,
			PreviousSnapshot: previousSnapshot,
			Manifest:         &manifestCopy,
			Top:              *reportTop,
			Template:         template,
			ShareProfile:     shareProfile,
			WriteMarkdown:    true,
			MarkdownPath:     *reportMDPath,
		})
		if reportErr != nil {
			if isArtifactPathError(reportErr) {
				return emitScanError("invalid_input", reportErr.Error(), exitInvalidInput)
			}
			return emitScanFailure(reportErr)
		}
		scanReportPath = mdOutPath
		payload["report"] = map[string]any{
			"md_path":       mdOutPath,
			"template":      string(template),
			"share_profile": string(shareProfile),
		}
	}
	if *sarifOut {
		path, pathErr := resolveArtifactOutputPath(*sarifPath)
		if pathErr != nil {
			return emitScanError("invalid_input", pathErr.Error(), exitInvalidInput)
		}
		report := exportsarif.Build(findings, wrkrVersion())
		if writeErr := exportsarif.Write(path, report); writeErr != nil {
			return emitScanFailure(writeErr)
		}
		scanSARIFPath = path
		payload["sarif"] = map[string]any{
			"path": path,
		}
	}

	if jsonSink.enabled() {
		if err := jsonSink.writePayload(payload); err != nil {
			return emitScanError("runtime_failure", err.Error(), exitRuntime)
		}
		progress.Flush()
		if *jsonOut {
			return exitSuccess
		}
	}
	if !*quiet {
		for _, sourceFailure := range manifestOut.Failures {
			_, _ = fmt.Fprintf(stderr, "warning: source repo=%s reason=%s\n", sourceFailure.Repo, sourceFailure.Reason)
		}
		for _, detectorErr := range detectorErrors {
			_, _ = fmt.Fprintf(stderr, "warning: detector=%s repo=%s org=%s code=%s class=%s message=%s\n", detectorErr.Detector, detectorErr.Repo, detectorErr.Org, detectorErr.Code, detectorErr.Class, detectorErr.Message)
		}
		for _, warning := range productionTargetWarnings {
			_, _ = fmt.Fprintf(stderr, "warning: %s\n", warning)
		}
	}
	if *quiet {
		progress.Flush()
		return exitSuccess
	}
	if *explain {
		progress.Flush()
		_, _ = fmt.Fprintf(stdout, "wrkr scan completed for %s:%s (profile=%s score=%.2f grade=%s)\n", targetMode, targetValue, profileResult.ProfileName, postureScore.Score, postureScore.Grade)
		if hasIncompleteFilesystemVisibility(detectorErrors, manifestOut.Failures) {
			_, _ = fmt.Fprintln(stdout, "scan completeness: some files or directories could not be read; review detector_errors/source_errors for permission or stat failures.")
		}
		for _, line := range compliance.ExplainRollupSummary(complianceSummary, 3) {
			_, _ = fmt.Fprintf(stdout, "compliance: %s\n", line)
		}
		if scanReportPath != "" {
			_, _ = fmt.Fprintf(stdout, "scan report: %s\n", scanReportPath)
		}
		if scanSARIFPath != "" {
			_, _ = fmt.Fprintf(stdout, "scan sarif: %s\n", scanSARIFPath)
		}
		return exitSuccess
	}
	progress.Flush()
	_, _ = fmt.Fprintln(stdout, "wrkr scan complete")
	return exitSuccess
}

func emitScanRuntimeError(stderr io.Writer, jsonOut bool, err error) int {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return emitError(stderr, jsonOut, "scan_timeout", "scan exceeded configured timeout", exitRuntime)
	case errors.Is(err, context.Canceled):
		return emitError(stderr, jsonOut, "scan_canceled", "scan canceled by signal or parent context", exitRuntime)
	case isMaterializedRootSafetyError(err):
		return emitError(stderr, jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	case sourceorg.IsCheckpointSafetyError(err):
		return emitError(stderr, jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	case sourceorg.IsCheckpointInputError(err):
		return emitError(stderr, jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	default:
		return emitError(stderr, jsonOut, "runtime_failure", scanRuntimeErrorMessage(err), exitRuntime)
	}
}

func resolveScanGitHubToken(explicit string, cfg config.Config) string {
	for _, candidate := range []string{
		strings.TrimSpace(explicit),
		strings.TrimSpace(cfg.Auth.Scan.Token),
		strings.TrimSpace(os.Getenv("WRKR_GITHUB_TOKEN")),
		strings.TrimSpace(os.Getenv("GITHUB_TOKEN")),
	} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func loadOptionalScanConfig(configPath string, hasExplicitTarget bool) (config.Config, bool, error) {
	resolvedPath, err := config.ResolvePath(configPath)
	if err != nil {
		return config.Config{}, false, err
	}
	cfg, err := config.Load(resolvedPath)
	if err == nil {
		return cfg, true, nil
	}
	if hasExplicitTarget && strings.TrimSpace(configPath) == "" {
		return config.Config{}, false, nil
	}
	if errors.Is(err, os.ErrNotExist) && strings.TrimSpace(configPath) == "" && strings.TrimSpace(os.Getenv("WRKR_CONFIG_PATH")) == "" {
		return config.Config{}, false, nil
	}
	return config.Config{}, false, err
}

func scanRuntimeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	lower := strings.ToLower(message)
	if strings.Contains(message, "github API status 403") && strings.Contains(lower, "rate limit") {
		return message + "; authenticate hosted scans with --github-token, config auth.scan.token, WRKR_GITHUB_TOKEN, or GITHUB_TOKEN"
	}
	return message
}

func hasIncompleteFilesystemVisibility(detectorErrors []detect.DetectorError, sourceFailures []source.RepoFailure) bool {
	for _, detectorErr := range detectorErrors {
		if detectorErr.Code == "permission_denied" || detectorErr.Code == "path_not_found" {
			return true
		}
	}
	for _, failure := range sourceFailures {
		lower := strings.ToLower(strings.TrimSpace(failure.Reason))
		if strings.Contains(lower, "permission denied") || strings.Contains(lower, "no such file") || strings.Contains(lower, "not found") {
			return true
		}
	}
	return false
}
