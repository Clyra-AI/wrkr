package scanquality

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const ReportVersion = "2"

const (
	SurfaceMCPServer                      = "mcp_server"
	AbsenceStatusNotFoundCompleteCoverage = "not_found_with_complete_coverage"
	AbsenceStatusNotFoundReducedCoverage  = "not_found_with_reduced_coverage"
	AbsenceStatusNotScanned               = "not_scanned"
	AbsenceStatusUnsupportedSurface       = "unsupported_surface"
	AbsenceStatusCandidateParseFailed     = "candidate_parse_failed"

	CoverageConfidenceComplete = "complete"
	CoverageConfidenceReduced  = "reduced"
	CoverageConfidenceUnknown  = "unknown"

	HostedCoverageAuthenticatedOrg  = "authenticated_org"
	HostedCoverageAuthenticatedRepo = "authenticated_repo"
	HostedCoveragePublicOnly        = "public_only"
	HostedCoverageNotApplicable     = "not_applicable"
	HostedCoverageComplete          = "complete"
	HostedCoverageReduced           = "reduced"
)

type Report struct {
	ScanQualityVersion   string                   `json:"scan_quality_version"`
	Mode                 string                   `json:"mode"`
	CompactSummary       *CompactCoverageSummary  `json:"compact_summary,omitempty"`
	Detectors            []DetectorHealth         `json:"detectors,omitempty"`
	SuppressedPaths      []SuppressedPath         `json:"suppressed_paths,omitempty"`
	ParseErrors          []ParseIssue             `json:"parse_errors,omitempty"`
	DetectorErrors       []detect.DetectorError   `json:"detector_errors,omitempty"`
	AbsenceClaims        []AbsenceClaim           `json:"absence_claims,omitempty"`
	HostedCoverage       *HostedCoverage          `json:"hosted_coverage,omitempty"`
	SurfaceCoverage      []detect.SurfaceCoverage `json:"surface_coverage,omitempty"`
	ReconciliationLedger *ReconciliationLedger    `json:"reconciliation_ledger,omitempty"`
}

type ReconciliationStage struct {
	StageID string `json:"stage_id"`
	Unit    string `json:"unit"`
	Count   int    `json:"count"`
}

type ReconciliationLedger struct {
	Version string                `json:"version"`
	Stages  []ReconciliationStage `json:"stages"`
	Valid   bool                  `json:"valid"`
	Errors  []string              `json:"errors,omitempty"`
}

type HostedCoverage struct {
	Scope              string   `json:"scope"`
	Authenticated      bool     `json:"authenticated"`
	Completeness       string   `json:"completeness"`
	RequestedRepos     int      `json:"requested_repos,omitempty"`
	CompletedRepos     int      `json:"completed_repos,omitempty"`
	FailedRepos        int      `json:"failed_repos,omitempty"`
	AcquisitionMode    string   `json:"acquisition_mode,omitempty"`
	Requests           int      `json:"requests,omitempty"`
	EstimatedRequests  int      `json:"estimated_requests,omitempty"`
	RateLimitLimit     int      `json:"rate_limit_limit,omitempty"`
	RateLimitRemaining int      `json:"rate_limit_remaining,omitempty"`
	RateLimitReset     string   `json:"rate_limit_reset,omitempty"`
	Reasons            []string `json:"reasons,omitempty"`
}

type HostedCoverageInput struct {
	HostedTarget       bool
	OrgTarget          bool
	Authenticated      bool
	PublicOnlyOptIn    bool
	RequestedRepos     int
	CompletedRepos     int
	FailedRepos        int
	AcquisitionMode    string
	Requests           int
	EstimatedRequests  int
	RateLimitLimit     int
	RateLimitRemaining int
	RateLimitReset     string
}

func BuildHostedCoverage(input HostedCoverageInput) *HostedCoverage {
	if !input.HostedTarget {
		return nil
	}
	coverage := &HostedCoverage{
		Authenticated:      input.Authenticated,
		RequestedRepos:     input.RequestedRepos,
		CompletedRepos:     input.CompletedRepos,
		FailedRepos:        input.FailedRepos,
		AcquisitionMode:    strings.TrimSpace(input.AcquisitionMode),
		Requests:           input.Requests,
		EstimatedRequests:  input.EstimatedRequests,
		RateLimitLimit:     input.RateLimitLimit,
		RateLimitRemaining: input.RateLimitRemaining,
		RateLimitReset:     strings.TrimSpace(input.RateLimitReset),
		Completeness:       HostedCoverageComplete,
	}
	switch {
	case !input.Authenticated:
		coverage.Scope = HostedCoveragePublicOnly
		coverage.Completeness = HostedCoverageReduced
		coverage.Reasons = append(coverage.Reasons, "github_authentication:unavailable", "private_repository_coverage:unknown")
		if input.PublicOnlyOptIn {
			coverage.Reasons = append(coverage.Reasons, "public_only_coverage:explicitly_acknowledged")
		}
	case input.OrgTarget:
		coverage.Scope = HostedCoverageAuthenticatedOrg
	default:
		coverage.Scope = HostedCoverageAuthenticatedRepo
	}
	if input.FailedRepos > 0 {
		coverage.Completeness = HostedCoverageReduced
		coverage.Reasons = append(coverage.Reasons, "repository_failures:present")
	}
	coverage.Reasons = mapKeysSorted(stringSliceSet(coverage.Reasons))
	return coverage
}

type CompactCoverageSummary struct {
	CoverageConfidence           string `json:"coverage_confidence"`
	ReducedDetectorCount         int    `json:"reduced_detector_count,omitempty"`
	ParseFailureCount            int    `json:"parse_failure_count,omitempty"`
	SuppressedGeneratedFileCount int    `json:"suppressed_generated_file_count,omitempty"`
	BlockedDetectorCount         int    `json:"blocked_detector_count,omitempty"`
	UnsupportedDeclarationCount  int    `json:"unsupported_declaration_count,omitempty"`
	ImpactStatement              string `json:"impact_statement,omitempty"`
}

type CompletenessSignals struct {
	ReducedCoverage     bool     `json:"reduced_coverage,omitempty"`
	ReducedDetectors    []string `json:"reduced_detectors,omitempty"`
	UnsupportedSurfaces []string `json:"unsupported_surfaces,omitempty"`
	Reasons             []string `json:"reasons,omitempty"`
}

type AbsenceClaim struct {
	Org     string   `json:"org,omitempty"`
	Repo    string   `json:"repo,omitempty"`
	Surface string   `json:"surface"`
	Status  string   `json:"status"`
	Reasons []string `json:"reasons,omitempty"`
	Impact  string   `json:"impact,omitempty"`
}

type DetectorHealth struct {
	Org                     string   `json:"org,omitempty"`
	Repo                    string   `json:"repo,omitempty"`
	Detector                string   `json:"detector"`
	Status                  string   `json:"status"`
	CoverageReasons         []string `json:"coverage_reasons,omitempty"`
	AttemptedFiles          int      `json:"attempted_files"`
	ParsedFiles             int      `json:"parsed_files"`
	PartialParses           int      `json:"partial_parses,omitempty"`
	SkippedFiles            int      `json:"skipped_files,omitempty"`
	SuppressedFiles         int      `json:"suppressed_files,omitempty"`
	ParseFailures           int      `json:"parse_failures,omitempty"`
	UnsupportedDeclarations int      `json:"unsupported_declarations,omitempty"`
	Findings                int      `json:"findings,omitempty"`
}

type SuppressedPath struct {
	Org    string `json:"org,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

type ParseIssue struct {
	Org               string `json:"org,omitempty"`
	Repo              string `json:"repo,omitempty"`
	Path              string `json:"path"`
	Detector          string `json:"detector,omitempty"`
	Kind              string `json:"kind"`
	Format            string `json:"format,omitempty"`
	Message           string `json:"message,omitempty"`
	Reason            string `json:"reason,omitempty"`
	RecommendedAction string `json:"recommended_action,omitempty"`
	OccurrenceCount   int    `json:"occurrence_count,omitempty"`
}

type Input struct {
	Mode                 string
	Scopes               []detect.Scope
	Findings             []model.Finding
	DetectorErrors       []detect.DetectorError
	SurfaceCoverage      []detect.SurfaceCoverage
	NormalizedFacts      int
	Bindings             int
	EffectiveAuthorities int
	EligiblePaths        int
	ConfirmedPaths       int
	CandidatePaths       int
	UnresolvedPaths      int
	DisplayedPaths       int
	SuppressedPathsCount int
}

func Build(input Input) Report {
	report := Report{
		ScanQualityVersion: ReportVersion,
		Mode:               normalizeMode(input.Mode),
		DetectorErrors:     cloneDetectorErrors(input.DetectorErrors),
		SurfaceCoverage:    cloneSurfaceCoverage(input.SurfaceCoverage),
	}
	if report.Mode != "deep" {
		report.SuppressedPaths = collectSuppressedPaths(input.Scopes)
	}
	report.ParseErrors = collectParseIssues(input.Findings)
	report.Detectors = collectDetectorHealth(input)
	report.AbsenceClaims = buildAbsenceClaims(input, report.Detectors)
	report.ReconciliationLedger = buildReconciliationLedger(input)
	compact := BuildCompactCoverageSummary(&report)
	report.CompactSummary = &compact
	return report
}

func buildReconciliationLedger(input Input) *ReconciliationLedger {
	discovered, selected, parsed := 0, 0, 0
	for _, receipt := range input.SurfaceCoverage {
		discovered += receipt.Discovered
		selected += receipt.Selected
		parsed += receipt.Parsed
	}
	ledger := &ReconciliationLedger{Version: "1", Stages: []ReconciliationStage{
		{StageID: "source_discovered", Unit: "files", Count: discovered},
		{StageID: "source_selected", Unit: "files", Count: selected},
		{StageID: "source_parsed", Unit: "files", Count: parsed},
		{StageID: "observations", Unit: "findings", Count: len(input.Findings)},
		{StageID: "normalized_facts", Unit: "facts", Count: input.NormalizedFacts},
		{StageID: "authority_bindings", Unit: "bindings", Count: input.Bindings},
		{StageID: "effective_authorities", Unit: "authorities", Count: input.EffectiveAuthorities},
		{StageID: "eligible_paths", Unit: "paths", Count: input.EligiblePaths},
		{StageID: "confirmed_paths", Unit: "paths", Count: input.ConfirmedPaths},
		{StageID: "candidate_paths", Unit: "paths", Count: input.CandidatePaths},
		{StageID: "unresolved_paths", Unit: "paths", Count: input.UnresolvedPaths},
		{StageID: "displayed_paths", Unit: "paths", Count: input.DisplayedPaths},
		{StageID: "suppressed_paths", Unit: "paths", Count: input.SuppressedPathsCount},
	}}
	ledger.Errors = validateReconciliationLedger(ledger, input.SurfaceCoverage)
	ledger.Valid = len(ledger.Errors) == 0
	return ledger
}

func UpdateReportProjection(report *Report, displayedPaths, suppressedPaths int) {
	if report == nil || report.ReconciliationLedger == nil {
		return
	}
	if displayedPaths < 0 {
		displayedPaths = 0
	}
	if suppressedPaths < 0 {
		suppressedPaths = 0
	}
	setLedgerStage(report.ReconciliationLedger, "displayed_paths", "paths", displayedPaths)
	setLedgerStage(report.ReconciliationLedger, "suppressed_paths", "paths", suppressedPaths)
	report.ReconciliationLedger.Errors = validateReconciliationLedger(report.ReconciliationLedger, report.SurfaceCoverage)
	report.ReconciliationLedger.Valid = len(report.ReconciliationLedger.Errors) == 0
}

func setLedgerStage(ledger *ReconciliationLedger, stageID, unit string, count int) {
	for index := range ledger.Stages {
		if ledger.Stages[index].StageID == stageID {
			ledger.Stages[index].Unit = unit
			ledger.Stages[index].Count = count
			return
		}
	}
	ledger.Stages = append(ledger.Stages, ReconciliationStage{StageID: stageID, Unit: unit, Count: count})
	sort.Slice(ledger.Stages, func(i, j int) bool { return ledger.Stages[i].StageID < ledger.Stages[j].StageID })
}

func validateReconciliationLedger(ledger *ReconciliationLedger, coverage []detect.SurfaceCoverage) []string {
	errorsOut := []string{}
	for _, receipt := range coverage {
		if receipt.Selected > receipt.Discovered {
			errorsOut = append(errorsOut, "surface_selected_exceeds_discovered:"+receipt.Surface)
		}
		if receipt.Attempted > receipt.Selected {
			errorsOut = append(errorsOut, "surface_attempted_exceeds_selected:"+receipt.Surface)
		}
		if receipt.Parsed > receipt.Attempted {
			errorsOut = append(errorsOut, "surface_parsed_exceeds_attempted:"+receipt.Surface)
		}
	}
	counts := map[string]int{}
	for _, stage := range ledger.Stages {
		counts[stage.StageID] = stage.Count
		if stage.Count < 0 {
			errorsOut = append(errorsOut, "negative_stage_count:"+stage.StageID)
		}
	}
	if counts["authority_bindings"] > 0 && counts["normalized_facts"] == 0 {
		errorsOut = append(errorsOut, "bindings_without_normalized_facts")
	}
	if counts["effective_authorities"] > 0 && counts["authority_bindings"] == 0 {
		errorsOut = append(errorsOut, "effective_authority_without_binding")
	}
	if counts["displayed_paths"] > counts["eligible_paths"] {
		errorsOut = append(errorsOut, "displayed_paths_exceed_eligible_paths")
	}
	if counts["displayed_paths"]+counts["suppressed_paths"] != counts["eligible_paths"] {
		errorsOut = append(errorsOut, "projected_paths_do_not_reconcile")
	}
	sort.Strings(errorsOut)
	return errorsOut
}

func cloneSurfaceCoverage(in []detect.SurfaceCoverage) []detect.SurfaceCoverage {
	out := append([]detect.SurfaceCoverage(nil), in...)
	for index := range out {
		out[index].ReasonCodes = append([]string(nil), in[index].ReasonCodes...)
	}
	return out
}

func BuildCompactCoverageSummary(report *Report) CompactCoverageSummary {
	if report != nil && report.CompactSummary != nil {
		return cloneCompactCoverageSummary(report.CompactSummary)
	}
	if report == nil {
		return CompactCoverageSummary{
			CoverageConfidence: CoverageConfidenceUnknown,
			ImpactStatement:    "Coverage metadata was unavailable; absence claims remain scoped to available evidence.",
		}
	}

	reducedDetectorCount := 0
	blockedDetectorCount := 0
	suppressedGeneratedFileCount := 0
	unsupportedDeclarationCount := 0
	reducedDetectorKeys := map[detectorScopeKey]struct{}{}
	for _, detector := range report.Detectors {
		if detectorHasMaterialCoverageReduction(detector) {
			reducedDetectorKeys[detectorScopeKey{
				org:      strings.TrimSpace(detector.Org),
				repo:     strings.TrimSpace(detector.Repo),
				detector: strings.TrimSpace(detector.Detector),
			}] = struct{}{}
		}
		if strings.TrimSpace(detector.Status) == "blocked" {
			blockedDetectorCount++
		}
		suppressedGeneratedFileCount += detector.SuppressedFiles
		unsupportedDeclarationCount += detector.UnsupportedDeclarations
	}
	for _, detectorErr := range report.DetectorErrors {
		reducedDetectorKeys[detectorScopeKey{
			org:      strings.TrimSpace(detectorErr.Org),
			repo:     strings.TrimSpace(detectorErr.Repo),
			detector: strings.TrimSpace(detectorErr.Detector),
		}] = struct{}{}
	}
	reducedDetectorCount = len(reducedDetectorKeys)
	parseFailureCount := materialParseFailureCount(report.ParseErrors)
	coverageConfidence := CoverageConfidenceComplete
	if reducedDetectorCount > 0 || parseFailureCount > 0 || blockedDetectorCount > 0 || (report.HostedCoverage != nil && report.HostedCoverage.Completeness == HostedCoverageReduced) {
		coverageConfidence = CoverageConfidenceReduced
	}

	return CompactCoverageSummary{
		CoverageConfidence:           coverageConfidence,
		ReducedDetectorCount:         reducedDetectorCount,
		ParseFailureCount:            parseFailureCount,
		SuppressedGeneratedFileCount: suppressedGeneratedFileCount,
		BlockedDetectorCount:         blockedDetectorCount,
		UnsupportedDeclarationCount:  unsupportedDeclarationCount,
		ImpactStatement:              compactCoverageImpactStatement(report, coverageConfidence, blockedDetectorCount, parseFailureCount, unsupportedDeclarationCount),
	}
}

func CoverageReduced(report *Report) bool {
	return CoverageConfidence(report) == CoverageConfidenceReduced
}

func CoverageConfidence(report *Report) string {
	return BuildCompactCoverageSummary(report).CoverageConfidence
}

func CompletenessSignalsForRepo(report *Report, org string, repo string) CompletenessSignals {
	signals := CompletenessSignals{}
	if report == nil {
		return signals
	}
	org = strings.TrimSpace(org)
	repo = strings.TrimSpace(repo)
	reducedDetectors := map[string]struct{}{}
	unsupportedSurfaces := map[string]struct{}{}
	reasons := map[string]struct{}{}
	for _, detector := range report.Detectors {
		if org != "" && strings.TrimSpace(detector.Org) != "" && strings.TrimSpace(detector.Org) != org {
			continue
		}
		if repo != "" && strings.TrimSpace(detector.Repo) != "" && strings.TrimSpace(detector.Repo) != repo {
			continue
		}
		if detectorHasMaterialCoverageReduction(detector) {
			signals.ReducedCoverage = true
			if name := strings.TrimSpace(detector.Detector); name != "" {
				reducedDetectors[name] = struct{}{}
				reasons["detector:"+name+":"+strings.TrimSpace(detector.Status)] = struct{}{}
			}
			for _, reason := range detector.CoverageReasons {
				if trimmed := strings.TrimSpace(reason); trimmed != "" {
					reasons["coverage_reason:"+trimmed] = struct{}{}
				}
			}
		}
	}
	for _, issue := range report.ParseErrors {
		if org != "" && strings.TrimSpace(issue.Org) != "" && strings.TrimSpace(issue.Org) != org {
			continue
		}
		if repo != "" && strings.TrimSpace(issue.Repo) != "" && strings.TrimSpace(issue.Repo) != repo {
			continue
		}
		if parseIssueReducesCoverage(issue) {
			signals.ReducedCoverage = true
			reasons["parse_issue:"+strings.TrimSpace(issue.Kind)] = struct{}{}
		}
	}
	for _, claim := range report.AbsenceClaims {
		if org != "" && strings.TrimSpace(claim.Org) != "" && strings.TrimSpace(claim.Org) != org {
			continue
		}
		if repo != "" && strings.TrimSpace(claim.Repo) != "" && strings.TrimSpace(claim.Repo) != repo {
			continue
		}
		switch strings.TrimSpace(claim.Status) {
		case AbsenceStatusUnsupportedSurface, AbsenceStatusCandidateParseFailed, AbsenceStatusNotScanned:
			signals.ReducedCoverage = true
			if surface := strings.TrimSpace(claim.Surface); surface != "" {
				unsupportedSurfaces[surface] = struct{}{}
				reasons["absence_claim:"+surface+":"+strings.TrimSpace(claim.Status)] = struct{}{}
			}
		}
	}
	signals.ReducedDetectors = mapKeysSorted(reducedDetectors)
	signals.UnsupportedSurfaces = mapKeysSorted(unsupportedSurfaces)
	signals.Reasons = mapKeysSorted(reasons)
	return signals
}

func cloneCompactCoverageSummary(in *CompactCoverageSummary) CompactCoverageSummary {
	if in == nil {
		return CompactCoverageSummary{
			CoverageConfidence: CoverageConfidenceUnknown,
			ImpactStatement:    "Coverage metadata was unavailable; absence claims remain scoped to available evidence.",
		}
	}
	return *in
}

func compactCoverageImpactStatement(report *Report, coverageConfidence string, blockedDetectorCount int, parseFailureCount int, unsupportedDeclarationCount int) string {
	switch {
	case report == nil:
		return "Coverage metadata was unavailable; absence claims remain scoped to available evidence."
	case blockedDetectorCount > 0:
		return "One or more detector surfaces were blocked, so negative claims remain coverage-qualified."
	case report.HostedCoverage != nil && report.HostedCoverage.Completeness == HostedCoverageReduced:
		return "Hosted source coverage was reduced, so organization-wide completeness and negative claims are not supported."
	case coverageConfidence == CoverageConfidenceReduced || parseFailureCount > 0 || len(report.DetectorErrors) > 0:
		return "Some detector coverage was reduced or parse-limited, so negative claims remain scoped to scanned inputs."
	case unsupportedDeclarationCount > 0:
		return "Unsupported declarations were excluded from authoritative negative claims."
	default:
		return "Coverage for scanned inputs was complete enough to support scoped negative claims."
	}
}

func stringSliceSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	return out
}

func mapKeysSorted(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	sort.Strings(out)
	return out
}

func AbsenceClaimForSurface(report *Report, org string, repo string, surface string) *AbsenceClaim {
	if report == nil {
		return nil
	}
	org = strings.TrimSpace(org)
	repo = strings.TrimSpace(repo)
	surface = strings.TrimSpace(surface)
	for _, item := range report.AbsenceClaims {
		if strings.TrimSpace(item.Surface) != surface {
			continue
		}
		if org != "" && strings.TrimSpace(item.Org) != org {
			continue
		}
		if repo != "" && strings.TrimSpace(item.Repo) != repo {
			continue
		}
		copyItem := item
		copyItem.Reasons = append([]string(nil), item.Reasons...)
		return &copyItem
	}
	return nil
}

func collectSuppressedPaths(scopes []detect.Scope) []SuppressedPath {
	items := make([]SuppressedPath, 0)
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		root := strings.TrimSpace(scope.Root)
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if rel == "." || rel == "" {
				return nil
			}
			if !detect.IsGeneratedPath(rel) {
				return nil
			}
			kind := "file"
			if d != nil && d.IsDir() {
				kind = "directory"
			}
			key := strings.Join([]string{scope.Org, scope.Repo, rel, kind}, "|")
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				items = append(items, SuppressedPath{
					Org:    strings.TrimSpace(scope.Org),
					Repo:   strings.TrimSpace(scope.Repo),
					Path:   rel,
					Kind:   kind,
					Reason: "generated_or_package_noise",
				})
			}
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].Kind < items[j].Kind
	})
	return items
}

func collectParseIssues(findings []model.Finding) []ParseIssue {
	items := make([]ParseIssue, 0)
	index := map[string]int{}
	for _, finding := range findings {
		if finding.ParseError == nil {
			continue
		}
		reason := "detector_parse_error"
		recommendedAction := "debug_only"
		if detect.IsGeneratedPath(finding.Location) || detect.IsGeneratedPath(finding.ParseError.Path) {
			reason = "generated_or_package_noise"
			recommendedAction = "suppress"
		}
		item := ParseIssue{
			Org:               strings.TrimSpace(finding.Org),
			Repo:              strings.TrimSpace(finding.Repo),
			Path:              firstNonEmpty(finding.ParseError.Path, finding.Location),
			Detector:          strings.TrimSpace(finding.ParseError.Detector),
			Kind:              strings.TrimSpace(finding.ParseError.Kind),
			Format:            strings.TrimSpace(finding.ParseError.Format),
			Message:           strings.TrimSpace(finding.ParseError.Message),
			Reason:            reason,
			RecommendedAction: recommendedAction,
			OccurrenceCount:   1,
		}
		key := strings.Join([]string{item.Org, item.Repo, item.Path, item.Detector, item.Kind, item.Format, item.Message, item.Reason, item.RecommendedAction}, "\x00")
		if idx, ok := index[key]; ok {
			items[idx].OccurrenceCount++
			continue
		}
		index[key] = len(items)
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		if items[i].Detector != items[j].Detector {
			return items[i].Detector < items[j].Detector
		}
		return items[i].Message < items[j].Message
	})
	return items
}

func detectorHasMaterialCoverageReduction(detector DetectorHealth) bool {
	status := strings.TrimSpace(detector.Status)
	if status == "blocked" || status == "partial" {
		return true
	}
	if status != "reduced" {
		return false
	}
	for _, reason := range detector.CoverageReasons {
		switch strings.TrimSpace(reason) {
		case "", "generated_suppression", "no_candidate_inputs":
			continue
		default:
			return true
		}
	}
	return false
}

func parseIssueReducesCoverage(issue ParseIssue) bool {
	return strings.TrimSpace(issue.Reason) != "generated_or_package_noise"
}

func materialParseFailureCount(issues []ParseIssue) int {
	total := 0
	for _, issue := range issues {
		if !parseIssueReducesCoverage(issue) {
			continue
		}
		occurrences := issue.OccurrenceCount
		if occurrences <= 0 {
			occurrences = 1
		}
		total += occurrences
	}
	return total
}

type detectorScopeKey struct {
	org      string
	repo     string
	detector string
}

type parsePathStatus struct {
	kind    string
	message string
}

type detectorPathMetrics struct {
	attemptedPaths  []string
	suppressedFiles int
	skippedFiles    int
}

type pathDecision struct {
	candidate  bool
	suppressed bool
	skipDir    bool
}

func collectDetectorHealth(input Input) []DetectorHealth {
	parseIndex := buildParsePathIndex(input.Findings)
	positiveIndex := buildPositivePathIndex(input.Findings)
	detectorErrorCounts := buildDetectorErrorIndex(input.DetectorErrors)

	receiptHealth := detectorHealthFromSurfaceCoverage(input.SurfaceCoverage, detectorErrorCounts)
	receiptKeys := map[detectorScopeKey]struct{}{}
	out := make([]DetectorHealth, 0, len(receiptHealth))
	for _, item := range receiptHealth {
		receiptKeys[detectorScopeKey{org: item.Org, repo: item.Repo, detector: item.Detector}] = struct{}{}
		out = append(out, item)
	}
	for _, scope := range input.Scopes {
		for _, detectorID := range detectorIDsForHealth(input) {
			scopeKey := detectorScopeKey{
				org:      strings.TrimSpace(scope.Org),
				repo:     strings.TrimSpace(scope.Repo),
				detector: detectorID,
			}
			if _, migrated := receiptKeys[scopeKey]; migrated {
				continue
			}
			metrics := collectDetectorScopeMetrics(scope, detectorID, normalizeMode(input.Mode))
			parsePaths := parseIndex[scopeKey]
			positivePaths := positiveIndex[scopeKey]
			if !shouldEmitDetectorHealth(detectorID, metrics, parsePaths, positivePaths, detectorErrorCounts[scopeKey]) {
				continue
			}
			fileSet := map[string]struct{}{}
			for _, path := range metrics.attemptedPaths {
				fileSet[path] = struct{}{}
			}
			for path := range parsePaths {
				fileSet[path] = struct{}{}
			}
			for path := range positivePaths {
				fileSet[path] = struct{}{}
			}

			item := DetectorHealth{
				Org:             scopeKey.org,
				Repo:            scopeKey.repo,
				Detector:        scopeKey.detector,
				AttemptedFiles:  len(metrics.attemptedPaths),
				SuppressedFiles: metrics.suppressedFiles,
				SkippedFiles:    metrics.skippedFiles,
			}
			reasonSet := map[string]struct{}{}
			if item.AttemptedFiles == 0 && item.SuppressedFiles == 0 && len(parsePaths) == 0 && len(positivePaths) == 0 && detectorErrorCounts[scopeKey] == 0 {
				reasonSet["no_candidate_inputs"] = struct{}{}
			}
			if item.SuppressedFiles > 0 {
				reasonSet["generated_suppression"] = struct{}{}
			}
			if detectorErrorCounts[scopeKey] > 0 {
				reasonSet["detector_error"] = struct{}{}
			}

			for path := range fileSet {
				parseStatus, hasParse := parsePaths[path]
				findingsCount := positivePaths[path]
				switch {
				case hasParse && findingsCount > 0:
					item.PartialParses++
					item.ParsedFiles++
					item.Findings += findingsCount
					reasonSet["partial_parse"] = struct{}{}
				case hasParse:
					item.ParseFailures++
					if isUnsupportedParseStatus(parseStatus) {
						item.UnsupportedDeclarations++
						reasonSet["unsupported_declaration"] = struct{}{}
					} else {
						reasonSet["parse_failures"] = struct{}{}
					}
				default:
					if containsPath(metrics.attemptedPaths, path) {
						item.ParsedFiles++
					}
					item.Findings += findingsCount
				}
				if isBlockedParseStatus(parseStatus) {
					reasonSet["blocked_path"] = struct{}{}
				}
			}

			switch {
			case detectorErrorCounts[scopeKey] > 0 || hasReason(reasonSet, "blocked_path"):
				item.Status = "blocked"
			case item.PartialParses > 0:
				item.Status = "partial"
			case item.ParseFailures > 0 || item.SuppressedFiles > 0 || item.UnsupportedDeclarations > 0 || item.SkippedFiles > 0:
				item.Status = "reduced"
			default:
				item.Status = "complete"
			}
			item.CoverageReasons = sortedReasonKeys(reasonSet)
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Detector < out[j].Detector
	})
	return out
}

func detectorHealthFromSurfaceCoverage(receipts []detect.SurfaceCoverage, detectorErrors map[detectorScopeKey]int) []DetectorHealth {
	byKey := map[detectorScopeKey]*DetectorHealth{}
	for _, receipt := range receipts {
		key := detectorScopeKey{org: strings.TrimSpace(receipt.Org), repo: strings.TrimSpace(receipt.Repo), detector: strings.TrimSpace(receipt.Detector)}
		if key.detector == "" {
			continue
		}
		item := byKey[key]
		if item == nil {
			item = &DetectorHealth{Org: key.org, Repo: key.repo, Detector: key.detector}
			byKey[key] = item
		}
		item.AttemptedFiles += receipt.Attempted
		item.ParsedFiles += receipt.Parsed
		item.PartialParses += receipt.Partial
		item.SuppressedFiles += receipt.Suppressed
		item.UnsupportedDeclarations += receipt.Unsupported
		item.Findings += receipt.Findings
		item.CoverageReasons = append(item.CoverageReasons, receipt.ReasonCodes...)
		if receipt.Unresolved > 0 {
			item.CoverageReasons = append(item.CoverageReasons, "unresolved_relationships")
		}
	}
	out := make([]DetectorHealth, 0, len(byKey))
	for key, item := range byKey {
		item.CoverageReasons = sortedReasonKeys(stringSliceSet(item.CoverageReasons))
		switch {
		case detectorErrors[key] > 0:
			item.Status = "blocked"
			item.CoverageReasons = sortedReasonKeys(stringSliceSet(append(item.CoverageReasons, "detector_error")))
		case item.PartialParses > 0:
			item.Status = "partial"
		case item.UnsupportedDeclarations > 0 || item.SuppressedFiles > 0 || hasReason(stringSliceSet(item.CoverageReasons), "unresolved_relationships"):
			item.Status = "reduced"
		default:
			item.Status = "complete"
		}
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Detector < out[j].Detector
	})
	return out
}

func detectorIDsForHealth(input Input) []string {
	set := map[string]struct{}{
		"ciagent":    {},
		"dependency": {},
		"mcp":        {},
		"webmcp":     {},
	}
	for _, detectorErr := range input.DetectorErrors {
		if detector := strings.TrimSpace(detectorErr.Detector); detector != "" {
			set[detector] = struct{}{}
		}
	}
	return mapKeysSorted(set)
}

func buildAbsenceClaims(input Input, detectors []DetectorHealth) []AbsenceClaim {
	type countIndex map[string]int

	authoritative := countIndex{}
	candidates := countIndex{}
	repoKeys := map[string]struct{}{}
	for _, scope := range input.Scopes {
		repoKeys[scopeKey(scope.Org, scope.Repo)] = struct{}{}
	}
	for _, finding := range input.Findings {
		key := scopeKey(finding.Org, finding.Repo)
		repoKeys[key] = struct{}{}
		switch strings.TrimSpace(finding.FindingType) {
		case "mcp_server":
			authoritative[key]++
		case "mcp_server_candidate", "webmcp_declaration":
			candidates[key]++
		}
	}
	byRepo := map[string][]DetectorHealth{}
	for _, detector := range detectors {
		if strings.TrimSpace(detector.Detector) != "mcp" && strings.TrimSpace(detector.Detector) != "webmcp" {
			continue
		}
		key := scopeKey(detector.Org, detector.Repo)
		repoKeys[key] = struct{}{}
		byRepo[key] = append(byRepo[key], detector)
	}
	coverageByRepo := map[string][]detect.SurfaceCoverage{}
	for _, receipt := range input.SurfaceCoverage {
		if receipt.Surface != "mcp_server" && receipt.Surface != "webmcp" {
			continue
		}
		key := scopeKey(receipt.Org, receipt.Repo)
		coverageByRepo[key] = append(coverageByRepo[key], receipt)
	}

	out := make([]AbsenceClaim, 0, len(repoKeys))
	for key := range repoKeys {
		if authoritative[key] > 0 {
			continue
		}
		org, repo := splitScopeKey(key)
		status, reasons := deriveMCPAbsenceStatus(byRepo[key], candidates[key])
		if reduced, coverageReasons := reducedMCPReceipts(coverageByRepo[key]); reduced {
			if status == AbsenceStatusNotFoundCompleteCoverage {
				status = AbsenceStatusNotFoundReducedCoverage
			}
			reasons = append(reasons, coverageReasons...)
			reasons = mapKeysSorted(stringSliceSet(reasons))
		}
		if status == "" {
			continue
		}
		out = append(out, AbsenceClaim{
			Org:     org,
			Repo:    repo,
			Surface: SurfaceMCPServer,
			Status:  status,
			Reasons: reasons,
			Impact:  absenceImpact(status),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Surface < out[j].Surface
	})
	return out
}

func reducedMCPReceipts(receipts []detect.SurfaceCoverage) (bool, []string) {
	reduced := false
	reasons := []string{}
	for _, receipt := range receipts {
		if receipt.Partial > 0 || receipt.Unsupported > 0 || receipt.Unresolved > 0 {
			reduced = true
		}
		if receipt.Partial > 0 {
			reasons = append(reasons, receipt.Surface+":partial")
		}
		if receipt.Unsupported > 0 {
			reasons = append(reasons, receipt.Surface+":unsupported")
		}
		if receipt.Unresolved > 0 {
			reasons = append(reasons, receipt.Surface+":unresolved")
		}
	}
	return reduced, reasons
}

func deriveMCPAbsenceStatus(detectors []DetectorHealth, candidateCount int) (string, []string) {
	if len(detectors) == 0 {
		return AbsenceStatusNotScanned, []string{"detector_health:missing"}
	}

	reasonSet := map[string]struct{}{}
	completeCoverage := true
	parseFailure := false
	unsupportedSurface := false
	reducedCoverage := false
	anyUnsupported := false
	for _, detector := range detectors {
		label := strings.TrimSpace(detector.Detector)
		if label == "" {
			label = "unknown"
		}
		reasonSet["detector:"+label+"="+strings.TrimSpace(detector.Status)] = struct{}{}
		for _, reason := range detector.CoverageReasons {
			trimmed := strings.TrimSpace(reason)
			reasonSet[label+":"+trimmed] = struct{}{}
			switch trimmed {
			case "parse_failures", "partial_parse", "blocked_path", "detector_error", "generated_suppression", "skipped_file":
				reducedCoverage = true
			}
		}
		if (detector.ParseFailures > 0 || detector.PartialParses > 0) && detector.UnsupportedDeclarations == 0 {
			parseFailure = true
		}
		if detector.Status != "complete" {
			completeCoverage = false
		}
		if detector.UnsupportedDeclarations > 0 {
			anyUnsupported = true
		}
	}
	if candidateCount > 0 {
		reasonSet["candidate_evidence:present"] = struct{}{}
		reducedCoverage = true
		completeCoverage = false
	}
	if anyUnsupported && !parseFailure && !reducedCoverage && candidateCount == 0 {
		unsupportedSurface = true
	}

	switch {
	case unsupportedSurface:
		return AbsenceStatusUnsupportedSurface, sortedReasonKeys(reasonSet)
	case parseFailure:
		return AbsenceStatusCandidateParseFailed, sortedReasonKeys(reasonSet)
	case reducedCoverage:
		return AbsenceStatusNotFoundReducedCoverage, sortedReasonKeys(reasonSet)
	case completeCoverage:
		return AbsenceStatusNotFoundCompleteCoverage, sortedReasonKeys(reasonSet)
	default:
		return AbsenceStatusNotScanned, sortedReasonKeys(reasonSet)
	}
}

func absenceImpact(status string) string {
	switch strings.TrimSpace(status) {
	case AbsenceStatusNotFoundCompleteCoverage:
		return "Complete MCP coverage supported a clean negative result for the scanned surfaces."
	case AbsenceStatusCandidateParseFailed:
		return "At least one MCP candidate surface failed to parse, so absence is not authoritative."
	case AbsenceStatusUnsupportedSurface:
		return "Only unsupported MCP-style surfaces were seen, so absence is not authoritative."
	case AbsenceStatusNotFoundReducedCoverage:
		return "Coverage was reduced or only candidate MCP evidence was present, so absence is not authoritative."
	default:
		return "MCP coverage was not scanned for this repo, so absence is not authoritative."
	}
}

func scopeKey(org string, repo string) string {
	return strings.TrimSpace(org) + "|" + strings.TrimSpace(repo)
}

func splitScopeKey(key string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(key), "|", 2)
	if len(parts) != 2 {
		return "", strings.TrimSpace(key)
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func buildParsePathIndex(findings []model.Finding) map[detectorScopeKey]map[string]parsePathStatus {
	out := map[detectorScopeKey]map[string]parsePathStatus{}
	for _, finding := range findings {
		if finding.ParseError == nil {
			continue
		}
		if detect.IsGeneratedPath(firstNonEmpty(finding.ParseError.Path, finding.Location)) {
			continue
		}
		key := detectorScopeKey{
			org:      strings.TrimSpace(finding.Org),
			repo:     strings.TrimSpace(finding.Repo),
			detector: strings.TrimSpace(finding.ParseError.Detector),
		}
		if key.detector == "" {
			key.detector = strings.TrimSpace(finding.Detector)
		}
		if key.detector == "" {
			continue
		}
		if out[key] == nil {
			out[key] = map[string]parsePathStatus{}
		}
		path := firstNonEmpty(finding.ParseError.Path, finding.Location)
		out[key][path] = parsePathStatus{
			kind:    strings.TrimSpace(finding.ParseError.Kind),
			message: strings.TrimSpace(finding.ParseError.Message),
		}
	}
	return out
}

func buildPositivePathIndex(findings []model.Finding) map[detectorScopeKey]map[string]int {
	out := map[detectorScopeKey]map[string]int{}
	for _, finding := range findings {
		if finding.ParseError != nil {
			continue
		}
		detectorID := strings.TrimSpace(finding.Detector)
		if detectorID == "" {
			continue
		}
		key := detectorScopeKey{
			org:      strings.TrimSpace(finding.Org),
			repo:     strings.TrimSpace(finding.Repo),
			detector: detectorID,
		}
		if out[key] == nil {
			out[key] = map[string]int{}
		}
		out[key][strings.TrimSpace(finding.Location)]++
	}
	return out
}

func buildDetectorErrorIndex(in []detect.DetectorError) map[detectorScopeKey]int {
	out := map[detectorScopeKey]int{}
	for _, item := range in {
		key := detectorScopeKey{
			org:      strings.TrimSpace(item.Org),
			repo:     strings.TrimSpace(item.Repo),
			detector: strings.TrimSpace(item.Detector),
		}
		out[key]++
	}
	return out
}

func collectDetectorScopeMetrics(scope detect.Scope, detectorID, mode string) detectorPathMetrics {
	switch detectorID {
	case "ciagent":
		return collectCIAgentScopeMetrics(scope.Root)
	case "dependency":
		return collectDependencyScopeMetrics(scope.Root, mode)
	case "mcp":
		return collectMCPScopeMetrics(scope.Root)
	case "webmcp":
		return collectWebMCPScopeMetrics(scope.Root, mode)
	default:
		return detectorPathMetrics{}
	}
}

func collectCIAgentScopeMetrics(root string) detectorPathMetrics {
	metrics := detectorPathMetrics{}
	paths := []string{
		".gitlab-ci.yml",
		".gitlab-ci.yaml",
		"Jenkinsfile",
		"azure-pipelines.yml",
		"azure-pipelines.yaml",
	}
	for _, rel := range paths {
		exists, parseErr := detect.FileExistsWithinRoot("scanquality", root, rel)
		if parseErr != nil || exists {
			metrics.attemptedPaths = append(metrics.attemptedPaths, rel)
		}
	}
	for _, pattern := range []string{".github/workflows/*", ".azure/pipelines/*.yml", ".azure/pipelines/*.yaml"} {
		matches, err := detect.Glob(root, pattern)
		if err != nil {
			continue
		}
		metrics.attemptedPaths = append(metrics.attemptedPaths, matches...)
	}
	metrics.attemptedPaths = dedupeStrings(metrics.attemptedPaths)
	return metrics
}

func collectDependencyScopeMetrics(root, mode string) detectorPathMetrics {
	return walkCandidatePaths(root, func(rel string, isDir bool) pathDecision {
		if mode != "deep" && detect.IsGeneratedPath(rel) {
			return pathDecision{candidate: true, suppressed: true, skipDir: isDir}
		}
		if !isDependencyManifestPath(rel) {
			return pathDecision{}
		}
		return pathDecision{candidate: true}
	})
}

func collectMCPScopeMetrics(root string) detectorPathMetrics {
	paths := []string{
		".mcp.json",
		".cursor/mcp.json",
		".vscode/mcp.json",
		"mcp.json",
		"managed-mcp.json",
		".claude/settings.json",
		".claude/settings.local.json",
		".codex/config.toml",
		".codex/config.yaml",
	}
	metrics := detectorPathMetrics{}
	for _, rel := range paths {
		exists, parseErr := detect.FileExistsWithinRoot("scanquality", root, rel)
		if parseErr != nil || exists {
			metrics.attemptedPaths = append(metrics.attemptedPaths, rel)
		}
	}
	return metrics
}

func collectWebMCPScopeMetrics(root, mode string) detectorPathMetrics {
	return walkCandidatePaths(root, func(rel string, isDir bool) pathDecision {
		if detect.IsGeneratedPath(rel) {
			if mode != "deep" {
				return pathDecision{candidate: true, suppressed: true, skipDir: isDir}
			}
			if isDir {
				return pathDecision{}
			}
			if detect.IsWebMCPRouteFile(rel) {
				return pathDecision{candidate: true}
			}
			if !isWebMCPCandidatePath(rel) {
				return pathDecision{}
			}
			return pathDecision{candidate: true, suppressed: true}
		}
		if !isWebMCPCandidatePath(rel) {
			return pathDecision{}
		}
		return pathDecision{candidate: true}
	})
}

func walkCandidatePaths(root string, classify func(rel string, isDir bool) pathDecision) detectorPathMetrics {
	metrics := detectorPathMetrics{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			metrics.skippedFiles++
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if walkErr != nil {
			metrics.skippedFiles++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d != nil && d.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git/") {
				return filepath.SkipDir
			}
			decision := classify(rel, true)
			if decision.candidate && decision.suppressed {
				metrics.suppressedFiles++
			}
			if decision.skipDir {
				return filepath.SkipDir
			}
			return nil
		}
		decision := classify(rel, false)
		if !decision.candidate {
			return nil
		}
		if decision.suppressed {
			metrics.suppressedFiles++
			return nil
		}
		metrics.attemptedPaths = append(metrics.attemptedPaths, rel)
		return nil
	})
	sort.Strings(metrics.attemptedPaths)
	return metrics
}

func isWebMCPCandidatePath(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	ext := strings.ToLower(filepath.Ext(lower))
	if detect.IsWebMCPRouteFile(lower) {
		return true
	}
	switch ext {
	case ".html", ".htm", ".js", ".mjs", ".cjs", ".go", ".ts", ".tsx", ".mts", ".cts", ".py", ".rb", ".php", ".java", ".kt", ".rs":
		return detect.IsHighSignalWebMCPPath(rel)
	default:
		return false
	}
}

func isDependencyManifestPath(rel string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(rel)))
	switch {
	case base == "go.mod", base == "package.json", base == "pyproject.toml", base == "cargo.toml":
		return true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return true
	default:
		return false
	}
}

func shouldEmitDetectorHealth(detectorID string, metrics detectorPathMetrics, parsePaths map[string]parsePathStatus, positivePaths map[string]int, detectorErrors int) bool {
	if detectorID == "mcp" || detectorID == "webmcp" {
		return true
	}
	return len(metrics.attemptedPaths) > 0 || metrics.suppressedFiles > 0 || len(parsePaths) > 0 || len(positivePaths) > 0 || detectorErrors > 0
}

func containsPath(paths []string, path string) bool {
	for _, candidate := range paths {
		if candidate == path {
			return true
		}
	}
	return false
}

func isBlockedParseStatus(status parsePathStatus) bool {
	switch strings.TrimSpace(status.kind) {
	case "permission_denied", "unsafe_path":
		return true
	default:
		return false
	}
}

func isUnsupportedParseStatus(status parsePathStatus) bool {
	if strings.TrimSpace(status.kind) == "schema_validation_error" {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(status.message)), "unsupported")
}

func sortedReasonKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hasReason(values map[string]struct{}, reason string) bool {
	_, ok := values[reason]
	return ok
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, item := range in {
		if strings.TrimSpace(item) == "" {
			continue
		}
		set[strings.TrimSpace(item)] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func cloneDetectorErrors(in []detect.DetectorError) []detect.DetectorError {
	if len(in) == 0 {
		return nil
	}
	out := append([]detect.DetectorError(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		if out[i].Detector != out[j].Detector {
			return out[i].Detector < out[j].Detector
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func normalizeMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "quick", "deep":
		return strings.TrimSpace(mode)
	default:
		return "governance"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
