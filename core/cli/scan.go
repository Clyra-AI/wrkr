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
	sourcegithub "github.com/Clyra-AI/wrkr/core/source/github"
	"github.com/Clyra-AI/wrkr/core/source/localsetup"
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
	var explicitTargets repeatedStringFlag
	fs.Var(&explicitTargets, "target", "repeatable scan target <mode>:<value>")
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
	profileName := fs.String("profile", "standard", "posture profile [baseline|standard|strict|assessment]")
	githubBaseURL := fs.String("github-api", "", "github api base url")
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

	hasExplicitTarget := strings.TrimSpace(*repo) != "" || strings.TrimSpace(*orgTarget) != "" || strings.TrimSpace(*githubOrgTarget) != "" || strings.TrimSpace(*pathTarget) != "" || *mySetup || len(explicitTargets) > 0
	loadedCfg, hasLoadedCfg, cfgLoadErr := loadOptionalScanConfig(*configPathFlag, hasExplicitTarget)
	if cfgLoadErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", cfgLoadErr.Error(), exitRuntime)
	}
	targets, cfg, err := resolveScanTargets(*repo, *orgTarget, *githubOrgTarget, *pathTarget, *mySetup, explicitTargets, *configPathFlag)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if *resume && !allTargetsAreOrg(targets) {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--resume is only supported when every requested target is an org target", exitInvalidInput)
	}
	if hasLoadedCfg {
		cfg.Auth = loadedCfg.Auth
		cfg.GitHubAPIBase = loadedCfg.GitHubAPIBase
	}
	*githubBaseURL = resolveScanGitHubAPIBase(*githubBaseURL, cfg)
	*githubToken = resolveScanGitHubToken(*githubToken, cfg)
	if *enrich && strings.TrimSpace(*githubBaseURL) == "" {
		return emitError(
			stderr,
			jsonRequested || *jsonOut,
			"dependency_missing",
			"--enrich requires a reachable network source; set --github-api, configure github_api_base in wrkr init config, or set WRKR_GITHUB_API_BASE",
			exitDependencyMissing,
		)
	}
	if anyTargetNeedsGitHub(targets) && strings.TrimSpace(*githubBaseURL) == "" {
		return emitError(
			stderr,
			jsonRequested || *jsonOut,
			"dependency_missing",
			"--repo and --org scans require --github-api, config github_api_base, or WRKR_GITHUB_API_BASE",
			exitDependencyMissing,
		)
	}
	artifactPreflight, preflightErr := preflightScanArtifacts(
		state.ResolvePath(*statePathFlag),
		*jsonPath,
		*reportMD,
		*reportMDPath,
		*reportTemplate,
		*reportShareProfile,
		*sarifOut,
		*sarifPath,
	)
	if preflightErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", preflightErr.Error(), exitInvalidInput)
	}
	jsonSink, jsonSinkErr := newJSONOutputSink(*jsonOut, artifactPreflight.JSONPath, stdout)
	if jsonSinkErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", jsonSinkErr.Error(), exitInvalidInput)
	}
	statePath := artifactPreflight.StatePath

	ctx := parentCtx
	cancel := func() {}
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(parentCtx, *timeout)
	}
	defer cancel()
	scanStartedAt := time.Now().UTC().Truncate(time.Second)
	progress := newScanProgressReporter(*jsonOut && !*quiet && anyTargetIsOrg(targets), stderr)
	emitScanFailure := func(err error) int {
		progress.Flush()
		return emitScanRuntimeError(stderr, jsonRequested || *jsonOut, err)
	}
	emitScanError := func(code, message string, exitCode int) int {
		progress.Flush()
		return emitError(stderr, jsonRequested || *jsonOut, code, message, exitCode)
	}
	manifestOut, findings, err := acquireSources(ctx, targets, *githubBaseURL, *githubToken, acquireOptions{
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

	manifestPath := artifactPreflight.ManifestPath
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
	approvedConfigured := false
	if approvedToolsPolicyPath := strings.TrimSpace(*approvedToolsPath); approvedToolsPolicyPath != "" {
		approvedCfg, approvedErr := approvedtools.Load(approvedToolsPolicyPath)
		if approvedErr != nil {
			return emitScanError("invalid_input", approvedErr.Error(), exitInvalidInput)
		}
		if approvedCfg.HasRules() {
			approvedConfigured = true
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
	if anyTargetIsMySetup(targets) {
		localInventory := inventoryLocalMachineSlice(inventoryOut)
		findings = append(findings, approvedtools.CompareLocalInventory(&localInventory, approvedConfigured, strings.TrimSpace(*approvedToolsPath))...)
		inventoryOut.LocalGovernance = localInventory.LocalGovernance
		source.SortFindings(findings)
		riskReport = risk.Score(findings, 5, now)
		repoRisk = map[string]float64{}
		for _, repo := range riskReport.Repos {
			repoRisk[repo.Org+"::"+repo.Repo] = repo.Score
		}
		repoExposure = aggexposure.Build(findings, repoRisk)
		inventoryOut.RepoExposureSummaries = append([]aggexposure.RepoExposureSummary(nil), repoExposure...)
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
	riskReport.ActionPaths, riskReport.ActionPathToControlFirst = risk.ApplyGovernFirstProfile(profileResult.ProfileName, riskReport.ActionPaths)

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
		Targets:      manifestOut.Targets,
		Findings:     findings,
		Inventory:    &inventoryOut,
		RiskReport:   &riskReport,
		Profile:      &profileResult,
		PostureScore: &postureScore,
		Identities:   nextManifest.Identities,
		Transitions:  transitions,
	}
	chainPath := artifactPreflight.LifecyclePath
	proofChainPath := artifactPreflight.ProofChainPath
	managedSnapshots, snapshotErr := captureManagedArtifacts(
		statePath,
		manifestPath,
		chainPath,
		proofChainPath,
		artifactPreflight.ProofAttestationPath,
		artifactPreflight.SigningKeyPath,
		artifactPreflight.ReportPath,
		artifactPreflight.SARIFPath,
		jsonSink.outputPath,
	)
	if snapshotErr != nil {
		return emitScanFailure(snapshotErr)
	}
	emitRolledBackScanFailure := func(err error) int {
		progress.Flush()
		return emitRolledBackRuntimeFailure(stderr, jsonRequested || *jsonOut, err, managedSnapshots)
	}
	emitRolledBackScanError := func(code, message string, exitCode int) int {
		progress.Flush()
		if restoreErr := restoreManagedArtifacts(managedSnapshots); restoreErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("%s (rollback restore failed: %v)", message, restoreErr), exitRuntime)
		}
		return emitError(stderr, jsonRequested || *jsonOut, code, message, exitCode)
	}

	if err := state.Save(statePath, snapshot); err != nil {
		return emitRolledBackScanFailure(err)
	}
	chain, chainErr := lifecycle.LoadChain(chainPath)
	if chainErr != nil {
		return emitRolledBackScanFailure(chainErr)
	}
	for _, transition := range transitions {
		if err := lifecycle.AppendTransitionRecord(chain, transition, "lifecycle_transition"); err != nil {
			return emitRolledBackScanFailure(err)
		}
	}
	if err := lifecycle.SaveChain(chainPath, chain); err != nil {
		return emitRolledBackScanFailure(err)
	}
	if _, err := proofemit.EmitScan(statePath, now, findings, &inventoryOut, riskReport, profileResult, postureScore, transitions); err != nil {
		return emitRolledBackScanFailure(err)
	}
	proofChain, err := proofemit.LoadChain(proofChainPath)
	if err != nil {
		return emitRolledBackScanFailure(err)
	}
	complianceSummary, err := compliance.BuildRollupSummary(findings, proofChain)
	if err != nil {
		return emitRolledBackScanError("policy_schema_violation", err.Error(), exitPolicyViolation)
	}
	if err := manifest.Save(manifestPath, nextManifest); err != nil {
		return emitRolledBackScanFailure(err)
	}

	payload := map[string]any{
		"status":          "ok",
		"target":          manifestOut.Target,
		"source_manifest": manifestOut,
	}
	if len(manifestOut.Targets) > 0 {
		payload["targets"] = manifestOut.Targets
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
		if activation := reportcore.BuildActivation(manifestOut.Target.Mode, riskReport.Ranked, &inventoryOut, riskReport.ActionPaths, 5); activation != nil {
			payload["activation"] = activation
		}
	}
	if *reportMD {
		manifestCopy := nextManifest
		_, mdOutPath, _, reportErr := generateReportArtifacts(reportArtifactOptions{
			StatePath:        statePath,
			Snapshot:         snapshot,
			PreviousSnapshot: previousSnapshot,
			Manifest:         &manifestCopy,
			Top:              *reportTop,
			Template:         artifactPreflight.ReportTemplate,
			ShareProfile:     artifactPreflight.ReportShareProfile,
			WriteMarkdown:    true,
			MarkdownPath:     artifactPreflight.ReportPath,
		})
		if reportErr != nil {
			if isArtifactPathError(reportErr) {
				return emitRolledBackScanError("invalid_input", reportErr.Error(), exitInvalidInput)
			}
			return emitRolledBackScanFailure(reportErr)
		}
		scanReportPath = mdOutPath
		payload["report"] = map[string]any{
			"md_path":       mdOutPath,
			"template":      string(artifactPreflight.ReportTemplate),
			"share_profile": string(artifactPreflight.ReportShareProfile),
		}
	}
	if *sarifOut {
		report := exportsarif.Build(findings, wrkrVersion())
		if writeErr := exportsarif.Write(artifactPreflight.SARIFPath, report); writeErr != nil {
			return emitRolledBackScanFailure(writeErr)
		}
		scanSARIFPath = artifactPreflight.SARIFPath
		payload["sarif"] = map[string]any{
			"path": artifactPreflight.SARIFPath,
		}
	}

	if jsonSink.enabled() {
		if err := jsonSink.writePayload(payload); err != nil {
			return emitRolledBackScanError("runtime_failure", err.Error(), exitRuntime)
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
		_, _ = fmt.Fprintf(stdout, "wrkr scan completed for %s (profile=%s score=%.2f grade=%s)\n", renderScanTargetSet(targets), profileResult.ProfileName, postureScore.Score, postureScore.Grade)
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

func inventoryLocalMachineSlice(inv agginventory.Inventory) agginventory.Inventory {
	local := inv
	local.Tools = make([]agginventory.Tool, 0, len(inv.Tools))
	for _, tool := range inv.Tools {
		if toolTouchesLocalMachine(tool) {
			local.Tools = append(local.Tools, tool)
		}
	}
	return local
}

func toolTouchesLocalMachine(tool agginventory.Tool) bool {
	for _, repo := range tool.Repos {
		if strings.TrimSpace(repo) == localsetup.RepoName {
			return true
		}
	}
	for _, location := range tool.Locations {
		if strings.TrimSpace(location.Repo) == localsetup.RepoName {
			return true
		}
	}
	return false
}

type scanArtifactPreflight struct {
	StatePath            string
	ManifestPath         string
	LifecyclePath        string
	ProofChainPath       string
	ProofAttestationPath string
	SigningKeyPath       string
	JSONPath             string
	ReportTemplate       reportcore.Template
	ReportShareProfile   reportcore.ShareProfile
	ReportPath           string
	SARIFPath            string
}

func preflightScanArtifacts(statePathRaw, jsonPath string, reportEnabled bool, reportPath, reportTemplateRaw, reportShareProfileRaw string, sarifEnabled bool, sarifPath string) (scanArtifactPreflight, error) {
	preflight := scanArtifactPreflight{}
	statePath, err := normalizeManagedArtifactPath(statePathRaw)
	if err != nil {
		return scanArtifactPreflight{}, err
	}
	manifestPath, err := normalizeManagedArtifactPath(manifest.ResolvePath(statePath))
	if err != nil {
		return scanArtifactPreflight{}, err
	}
	lifecyclePath, err := normalizeManagedArtifactPath(lifecycle.ChainPath(statePath))
	if err != nil {
		return scanArtifactPreflight{}, err
	}
	proofChainPath, err := normalizeManagedArtifactPath(proofemit.ChainPath(statePath))
	if err != nil {
		return scanArtifactPreflight{}, err
	}
	proofAttestationPath, err := normalizeManagedArtifactPath(proofemit.ChainAttestationPath(proofChainPath))
	if err != nil {
		return scanArtifactPreflight{}, err
	}
	signingKeyPath, err := normalizeManagedArtifactPath(proofemit.SigningKeyPath(statePath))
	if err != nil {
		return scanArtifactPreflight{}, err
	}

	preflight.StatePath = statePath
	preflight.ManifestPath = manifestPath
	preflight.LifecyclePath = lifecyclePath
	preflight.ProofChainPath = proofChainPath
	preflight.ProofAttestationPath = proofAttestationPath
	preflight.SigningKeyPath = signingKeyPath

	entries := make([]scanArtifactPathEntry, 0, 9)
	for _, item := range []struct {
		label string
		path  string
	}{
		{label: "--state", path: preflight.StatePath},
		{label: "manifest", path: preflight.ManifestPath},
		{label: "lifecycle chain", path: preflight.LifecyclePath},
		{label: "proof chain", path: preflight.ProofChainPath},
		{label: "proof attestation", path: preflight.ProofAttestationPath},
		{label: "proof signing key", path: preflight.SigningKeyPath},
	} {
		entry, entryErr := newScanArtifactPathEntry(item.label, item.path)
		if entryErr != nil {
			return scanArtifactPreflight{}, entryErr
		}
		entries = append(entries, entry)
	}

	if strings.TrimSpace(jsonPath) != "" {
		path, err := resolveArtifactOutputPath(jsonPath)
		if err != nil {
			return scanArtifactPreflight{}, err
		}
		preflight.JSONPath = path
		entry, entryErr := newScanArtifactPathEntry("--json-path", path)
		if entryErr != nil {
			return scanArtifactPreflight{}, entryErr
		}
		entries = append(entries, entry)
	}
	if reportEnabled {
		template, shareProfile, err := parseReportTemplateShare(reportTemplateRaw, reportShareProfileRaw)
		if err != nil {
			return scanArtifactPreflight{}, err
		}
		path, err := resolveArtifactOutputPath(reportPath)
		if err != nil {
			return scanArtifactPreflight{}, err
		}
		preflight.ReportTemplate = template
		preflight.ReportShareProfile = shareProfile
		preflight.ReportPath = path
		entry, entryErr := newScanArtifactPathEntry("--report-md-path", path)
		if entryErr != nil {
			return scanArtifactPreflight{}, entryErr
		}
		entries = append(entries, entry)
	}
	if sarifEnabled {
		path, err := resolveArtifactOutputPath(sarifPath)
		if err != nil {
			return scanArtifactPreflight{}, err
		}
		preflight.SARIFPath = path
		entry, entryErr := newScanArtifactPathEntry("--sarif-path", path)
		if entryErr != nil {
			return scanArtifactPreflight{}, entryErr
		}
		entries = append(entries, entry)
	}
	if err := detectScanArtifactPathCollisions(entries); err != nil {
		return scanArtifactPreflight{}, err
	}
	return preflight, nil
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
	case sourcegithub.IsRateLimitedError(err):
		return emitError(stderr, jsonOut, "rate_limited", scanRateLimitedMessage(err), exitRuntime)
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

func resolveScanGitHubAPIBase(explicit string, cfg config.Config) string {
	for _, candidate := range []string{
		strings.TrimSpace(explicit),
		strings.TrimSpace(cfg.GitHubAPIBase),
		strings.TrimSpace(os.Getenv("WRKR_GITHUB_API_BASE")),
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
	return err.Error()
}

func scanRateLimitedMessage(err error) string {
	if err == nil {
		return ""
	}
	return err.Error() + "; authenticate hosted scans with --github-token, config auth.scan.token, WRKR_GITHUB_TOKEN, or GITHUB_TOKEN; wait for the reported GitHub reset window before retrying"
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
