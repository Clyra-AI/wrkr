package report

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/regress"
	templatespkg "github.com/Clyra-AI/wrkr/core/report/templates"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
)

// BuildSummary composes deterministic report sections from scan, risk, score, lifecycle, regress, and proof data.
// Non-goal guardrail: this path must remain deterministic and non-generative.
func BuildSummary(in BuildInput) (Summary, error) {
	template := in.Template
	if template == "" {
		template = TemplateOperator
	}
	if _, ok := ParseTemplate(string(template)); !ok {
		return Summary{}, fmt.Errorf("unsupported report template %q", template)
	}

	shareProfile := in.ShareProfile
	if shareProfile == "" {
		shareProfile = ShareProfileInternal
	}
	if _, ok := ParseShareProfile(string(shareProfile)); !ok {
		return Summary{}, fmt.Errorf("unsupported share profile %q", shareProfile)
	}

	now := resolveGeneratedAt(in.GeneratedAt, in.Snapshot)
	top := in.Top

	riskReport := in.Snapshot.RiskReport
	if riskReport == nil {
		generated := risk.Score(in.Snapshot.Findings, top, now)
		riskReport = &generated
	}
	if len(riskReport.ActionPaths) == 0 && in.Snapshot.Inventory != nil {
		riskReport.ActionPaths, riskReport.ActionPathToControlFirst = risk.BuildActionPaths(riskReport.AttackPaths, in.Snapshot.Inventory)
	}
	profileName := ""
	if in.Snapshot.Profile != nil {
		profileName = in.Snapshot.Profile.ProfileName
	}
	riskReport.ActionPaths, riskReport.ActionPathToControlFirst = risk.ApplyGovernFirstProfile(profileName, riskReport.ActionPaths)
	topFindings := SelectTopFindings(*riskReport, top)

	proofRef, err := buildProofReference(in.StatePath, topFindings)
	if err != nil {
		return Summary{}, err
	}
	complianceSummary, err := buildComplianceSummary(in.StatePath, in.Snapshot.Findings)
	if err != nil {
		return Summary{}, err
	}

	lifecycleSummary := buildLifecycleSummary(in.Manifest, in.Snapshot.Identities, in.Snapshot.Transitions)
	regressSummary := buildRegressSummary(in.Baseline, in.RegressResult)
	deltas := buildDeltaSummary(in.Snapshot, in.PreviousSnapshot, top)
	headline := buildHeadline(in.Snapshot)
	methodology := buildMethodology(in.Snapshot)
	riskItems := buildRiskItems(topFindings, riskReport.ActionPaths)
	attackPathSummary := buildAttackPathSummary(*riskReport)
	attackPathFacts := buildAttackPathFacts(*riskReport)
	activation := BuildActivation(in.Snapshot.Target.Mode, riskReport.Ranked, in.Snapshot.Inventory, riskReport.ActionPaths, top)
	exposureGroups := risk.BuildExposureGroups(riskReport.ActionPaths)
	assessmentSummary := buildAssessmentSummary(riskReport.ActionPaths, riskReport.ActionPathToControlFirst, in.Snapshot.Inventory, proofRef)

	if shareProfile == ShareProfilePublic {
		proofRef = sanitizeProofReferencePublic(proofRef)
		lifecycleSummary = sanitizeLifecycleSummaryPublic(lifecycleSummary)
		riskItems = sanitizeRiskItemsPublic(riskItems)
		activation = sanitizeActivationSummaryPublic(activation)
		riskReport.ActionPaths = sanitizeActionPathsPublic(riskReport.ActionPaths)
		riskReport.ActionPathToControlFirst = sanitizeActionPathToControlFirstPublic(riskReport.ActionPathToControlFirst)
		exposureGroups = sanitizeExposureGroupsPublic(exposureGroups)
		assessmentSummary = sanitizeAssessmentSummaryPublic(assessmentSummary)
	}

	privilegeBudget := privilegeBudgetFromInventory(in.Snapshot.Inventory)
	securityVisibility := securityVisibilityFromInventory(in.Snapshot.Inventory)
	nextActions := buildNextActions(riskItems, lifecycleSummary, regressSummary)
	pack := templatespkg.Resolve(string(template))
	sections := buildSections(pack, template == TemplatePublic, headline, methodology, riskItems, attackPathFacts, complianceSummary, privilegeBudget, securityVisibility, deltas, lifecycleSummary, regressSummary, proofRef, nextActions)

	sectionOrder := []string{
		SectionHeadline,
		SectionTopRisks,
		SectionChanges,
		SectionLifecycle,
		SectionProof,
		SectionNextAction,
	}
	if template == TemplatePublic {
		sectionOrder = []string{
			SectionHeadline,
			SectionMethodology,
			SectionTopRisks,
			SectionChanges,
			SectionLifecycle,
			SectionProof,
			SectionNextAction,
		}
	}

	summary := Summary{
		SummaryVersion:           SummaryVersion,
		GeneratedAt:              now.Format(time.RFC3339),
		Template:                 string(template),
		ShareProfile:             string(shareProfile),
		SectionOrder:             sectionOrder,
		Sections:                 sections,
		Headline:                 headline,
		AssessmentSummary:        assessmentSummary,
		Methodology:              methodology,
		TopRisks:                 riskItems,
		PrivilegeBudget:          privilegeBudget,
		SecurityVisibility:       securityVisibility,
		Deltas:                   deltas,
		Lifecycle:                lifecycleSummary,
		RegressDrift:             regressSummary,
		AttackPaths:              attackPathSummary,
		ComplianceSummary:        complianceSummary,
		Proof:                    proofRef,
		NextActions:              nextActions,
		Activation:               activation,
		ActionPaths:              riskReport.ActionPaths,
		ActionPathToControlFirst: riskReport.ActionPathToControlFirst,
		ExposureGroups:           exposureGroups,
	}

	return summary, nil
}

type complianceSummaryError struct {
	err error
}

func (e *complianceSummaryError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *complianceSummaryError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func IsComplianceSummaryError(err error) bool {
	var target *complianceSummaryError
	return errors.As(err, &target)
}

func privilegeBudgetFromInventory(inv *agginventory.Inventory) agginventory.PrivilegeBudget {
	if inv == nil {
		return normalizePrivilegeBudget(agginventory.PrivilegeBudget{
			ProductionWrite: agginventory.ProductionWriteBudget{
				Configured: false,
				Status:     agginventory.ProductionTargetsStatusNotConfigured,
				Count:      nil,
			},
		})
	}
	return normalizePrivilegeBudget(inv.PrivilegeBudget)
}

func securityVisibilityFromInventory(inv *agginventory.Inventory) agginventory.SecurityVisibilitySummary {
	if inv == nil {
		return agginventory.SecurityVisibilitySummary{}
	}
	if !hasSecurityVisibilityReference(inv.SecurityVisibility) {
		return agginventory.SecurityVisibilitySummary{}
	}
	return inv.SecurityVisibility
}

func hasSecurityVisibilityReference(summary agginventory.SecurityVisibilitySummary) bool {
	return strings.TrimSpace(summary.ReferenceBasis) != ""
}

func normalizePrivilegeBudget(in agginventory.PrivilegeBudget) agginventory.PrivilegeBudget {
	status := strings.TrimSpace(in.ProductionWrite.Status)
	switch status {
	case agginventory.ProductionTargetsStatusConfigured, agginventory.ProductionTargetsStatusNotConfigured, agginventory.ProductionTargetsStatusInvalid:
		// Keep explicit status.
	default:
		if in.ProductionWrite.Configured {
			status = agginventory.ProductionTargetsStatusConfigured
		} else {
			status = agginventory.ProductionTargetsStatusNotConfigured
		}
	}
	in.ProductionWrite.Status = status
	in.ProductionWrite.Configured = status == agginventory.ProductionTargetsStatusConfigured
	if !in.ProductionWrite.Configured {
		in.ProductionWrite.Count = nil
	}
	if in.ProductionWrite.Configured && in.ProductionWrite.Count == nil {
		zero := 0
		in.ProductionWrite.Count = &zero
	}
	return in
}

func SelectTopFindings(report risk.Report, requested int) []risk.ScoredFinding {
	source := report.TopN
	if len(source) == 0 && len(report.Ranked) > 0 {
		source = report.Ranked
	}
	if requested >= 0 && requested > len(source) && len(report.Ranked) > len(source) {
		source = report.Ranked
	}
	if requested < 0 {
		return append([]risk.ScoredFinding(nil), source...)
	}
	if requested > len(source) {
		requested = len(source)
	}
	if requested < 0 {
		requested = 0
	}
	return append([]risk.ScoredFinding(nil), source[:requested]...)
}

func PublicSanitizeFindings(in []risk.ScoredFinding) []risk.ScoredFinding {
	out := make([]risk.ScoredFinding, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.CanonicalKey = redactValue("finding", copyItem.CanonicalKey, 12)
		copyItem.Finding.Location = redactValue("loc", copyItem.Finding.Location, 8)
		copyItem.Finding.Repo = redactValue("repo", copyItem.Finding.Repo, 6)
		copyItem.Finding.Org = redactValue("org", copyItem.Finding.Org, 6)
		out = append(out, copyItem)
	}
	return out
}

func resolveGeneratedAt(generatedAt time.Time, snapshot state.Snapshot) time.Time {
	if !generatedAt.IsZero() {
		return generatedAt.UTC().Truncate(time.Second)
	}
	if snapshot.RiskReport != nil && strings.TrimSpace(snapshot.RiskReport.GeneratedAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(snapshot.RiskReport.GeneratedAt))
		if err == nil {
			return parsed.UTC().Truncate(time.Second)
		}
	}
	return time.Now().UTC().Truncate(time.Second)
}

func buildProofReference(statePath string, top []risk.ScoredFinding) (ProofReference, error) {
	resolvedStatePath := state.ResolvePath(strings.TrimSpace(statePath))
	chainPath := proofemit.ChainPath(resolvedStatePath)
	verifyResult := verifycore.Result{}
	if verified, err := verifycore.Chain(chainPath); err == nil {
		verifyResult = verified
	}

	chain, err := proofemit.LoadChain(chainPath)
	if err != nil {
		return ProofReference{}, fmt.Errorf("load proof chain: %w", err)
	}
	byType := map[string]int{}
	for _, record := range chain.Records {
		recordType := strings.TrimSpace(record.RecordType)
		if recordType == "" {
			recordType = "unknown"
		}
		byType[recordType]++
	}
	typeCounts := make([]RecordTypeCount, 0, len(byType))
	for recordType, count := range byType {
		typeCounts = append(typeCounts, RecordTypeCount{RecordType: recordType, Count: count})
	}
	sort.Slice(typeCounts, func(i, j int) bool {
		return typeCounts[i].RecordType < typeCounts[j].RecordType
	})

	keys := make([]string, 0, len(top))
	seen := map[string]struct{}{}
	for _, item := range top {
		if strings.TrimSpace(item.CanonicalKey) == "" {
			continue
		}
		if _, exists := seen[item.CanonicalKey]; exists {
			continue
		}
		seen[item.CanonicalKey] = struct{}{}
		keys = append(keys, item.CanonicalKey)
	}
	sort.Strings(keys)

	headHash := strings.TrimSpace(verifyResult.HeadHash)
	if headHash == "" {
		headHash = strings.TrimSpace(chain.HeadHash)
	}
	recordCount := verifyResult.Count
	if recordCount == 0 {
		recordCount = len(chain.Records)
	}

	return ProofReference{
		ChainPath:            filepath.Clean(chainPath),
		HeadHash:             headHash,
		RecordCount:          recordCount,
		RecordTypeCounts:     typeCounts,
		CanonicalFindingKeys: keys,
	}, nil
}

func buildLifecycleSummary(m *manifest.Manifest, snapshotIdentities []manifest.IdentityRecord, transitions []lifecycle.Transition) LifecycleSummary {
	identities := []manifest.IdentityRecord{}
	if m != nil {
		identities = append(identities, model.FilterLegacyArtifactIdentityRecords(m.Identities)...)
	}
	if len(identities) == 0 {
		identities = append(identities, model.FilterLegacyArtifactIdentityRecords(snapshotIdentities)...)
	}

	underReview := 0
	revoked := 0
	deprecated := 0
	for _, record := range identities {
		switch strings.TrimSpace(record.Status) {
		case identity.StateUnderReview:
			underReview++
		case identity.StateRevoked:
			revoked++
		case identity.StateDeprecated:
			deprecated++
		}
	}

	normalizedTransitions := make([]LifecycleTransition, 0, len(transitions))
	for _, item := range transitions {
		normalizedTransitions = append(normalizedTransitions, LifecycleTransition{
			AgentID:       strings.TrimSpace(item.AgentID),
			PreviousState: strings.TrimSpace(item.PreviousState),
			NewState:      strings.TrimSpace(item.NewState),
			Trigger:       strings.TrimSpace(item.Trigger),
			Timestamp:     strings.TrimSpace(item.Timestamp),
		})
	}
	sort.Slice(normalizedTransitions, func(i, j int) bool {
		if normalizedTransitions[i].Timestamp != normalizedTransitions[j].Timestamp {
			return normalizedTransitions[i].Timestamp > normalizedTransitions[j].Timestamp
		}
		if normalizedTransitions[i].AgentID != normalizedTransitions[j].AgentID {
			return normalizedTransitions[i].AgentID < normalizedTransitions[j].AgentID
		}
		return normalizedTransitions[i].Trigger < normalizedTransitions[j].Trigger
	})
	if len(normalizedTransitions) > 5 {
		normalizedTransitions = normalizedTransitions[:5]
	}

	return LifecycleSummary{
		IdentityCount:      len(identities),
		UnderReviewCount:   underReview,
		RevokedCount:       revoked,
		DeprecatedCount:    deprecated,
		PendingActionCount: underReview + revoked + deprecated,
		RecentTransitions:  normalizedTransitions,
	}
}

func buildRegressSummary(baseline *regress.Baseline, result *regress.Result) *RegressSummary {
	if baseline == nil && result == nil {
		return nil
	}
	summary := &RegressSummary{BaselineProvided: baseline != nil}
	if result == nil {
		return summary
	}
	summary.DriftDetected = result.Drift
	summary.ReasonCount = result.ReasonCount
	byCode := map[string]int{}
	for _, reason := range result.Reasons {
		code := strings.TrimSpace(reason.Code)
		if code == "" {
			code = "unknown"
		}
		byCode[code]++
	}
	groups := make([]ReasonGroup, 0, len(byCode))
	for code, count := range byCode {
		groups = append(groups, ReasonGroup{Code: code, Count: count})
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Code != groups[j].Code {
			return groups[i].Code < groups[j].Code
		}
		return groups[i].Count > groups[j].Count
	})
	summary.ReasonGroups = groups
	return summary
}

func buildDeltaSummary(snapshot state.Snapshot, previous *state.Snapshot, top int) DeltaSummary {
	riskCurrent := averageRisk(snapshot.RiskReport, top)
	riskPrevious := 0.0
	riskHasPrevious := false
	if previous != nil {
		riskPrevious = averageRisk(previous.RiskReport, top)
		riskHasPrevious = previous.RiskReport != nil
	}
	riskDelta := 0.0
	if riskHasPrevious {
		riskDelta = round2(riskCurrent - riskPrevious)
	}

	profileCurrent := 0.0
	profilePrevious := 0.0
	profileDelta := 0.0
	profileHasPrevious := false
	if snapshot.Profile != nil {
		profileCurrent = round2(snapshot.Profile.CompliancePercent)
		profileDelta = round2(snapshot.Profile.DeltaPercent)
		profilePrevious = round2(profileCurrent - profileDelta)
		profileHasPrevious = profileDelta != 0 || previous != nil
	}

	postureCurrent := 0.0
	posturePrevious := 0.0
	postureDelta := 0.0
	postureHasPrevious := false
	if snapshot.PostureScore != nil {
		postureCurrent = round2(snapshot.PostureScore.Score)
		postureDelta = round2(snapshot.PostureScore.TrendDelta)
		posturePrevious = round2(postureCurrent - postureDelta)
		postureHasPrevious = postureDelta != 0 || previous != nil
	}

	return DeltaSummary{
		RiskScoreTrend: DeltaMetric{
			Current:     riskCurrent,
			Previous:    riskPrevious,
			Delta:       riskDelta,
			HasPrevious: riskHasPrevious,
		},
		ProfileComplianceDelta: DeltaMetric{
			Current:     profileCurrent,
			Previous:    profilePrevious,
			Delta:       profileDelta,
			HasPrevious: profileHasPrevious,
		},
		PostureScoreTrend: DeltaMetric{
			Current:     postureCurrent,
			Previous:    posturePrevious,
			Delta:       postureDelta,
			HasPrevious: postureHasPrevious,
		},
	}
}

func averageRisk(report *risk.Report, top int) float64 {
	if report == nil {
		return 0
	}
	selected := SelectTopFindings(*report, top)
	if len(selected) == 0 {
		return 0
	}
	total := 0.0
	for _, item := range selected {
		total += item.Score
	}
	return round2(total / float64(len(selected)))
}

func buildHeadline(snapshot state.Snapshot) Headline {
	headline := Headline{}
	if snapshot.PostureScore != nil {
		headline.Score = round2(snapshot.PostureScore.Score)
		headline.Grade = strings.TrimSpace(snapshot.PostureScore.Grade)
	}
	if snapshot.Profile != nil {
		headline.ComplianceStatus = strings.TrimSpace(snapshot.Profile.Status)
		headline.Compliance = round2(snapshot.Profile.CompliancePercent)
	}
	return headline
}

func buildMethodology(snapshot state.Snapshot) Methodology {
	methodology := Methodology{
		WrkrVersion:         "devel",
		ScanStartedAt:       "",
		ScanCompletedAt:     "",
		ScanDurationSeconds: 0,
		RepoCount:           0,
		FileCountProcessed:  0,
		DetectorCount:       0,
		CommandSet: []string{
			"wrkr scan --json",
			"wrkr report --template public --share-profile public --json",
		},
		SampleDefinition:  "discovered AI tooling from configured scan target",
		ExclusionCriteria: []string{"no live endpoint probing", "no runtime execution telemetry", "no secret-value extraction"},
	}
	if snapshot.Inventory == nil {
		return methodology
	}
	method := snapshot.Inventory.Methodology
	if strings.TrimSpace(method.WrkrVersion) != "" {
		methodology.WrkrVersion = strings.TrimSpace(method.WrkrVersion)
	}
	methodology.ScanStartedAt = strings.TrimSpace(method.ScanStartedAt)
	methodology.ScanCompletedAt = strings.TrimSpace(method.ScanCompletedAt)
	methodology.ScanDurationSeconds = method.ScanDurationSeconds
	methodology.RepoCount = method.RepoCount
	methodology.FileCountProcessed = method.FileCountProcessed
	methodology.DetectorCount = len(method.Detectors)
	return methodology
}

func buildRiskItems(findings []risk.ScoredFinding, actionPaths []risk.ActionPath) []RiskItem {
	if len(actionPaths) > 0 {
		return buildActionPathRiskItems(actionPaths)
	}
	out := make([]RiskItem, 0, len(findings))
	for idx, finding := range findings {
		remediation := strings.TrimSpace(finding.Finding.Remediation)
		if remediation == "" {
			remediation = defaultRemediation(finding.Finding.FindingType)
		}
		out = append(out, RiskItem{
			Rank:         idx + 1,
			CanonicalKey: strings.TrimSpace(finding.CanonicalKey),
			Score:        round2(finding.Score),
			FindingType:  strings.TrimSpace(finding.Finding.FindingType),
			Severity:     strings.TrimSpace(finding.Finding.Severity),
			ToolType:     strings.TrimSpace(finding.Finding.ToolType),
			Org:          strings.TrimSpace(finding.Finding.Org),
			Repo:         strings.TrimSpace(finding.Finding.Repo),
			Location:     strings.TrimSpace(finding.Finding.Location),
			Rationale:    append([]string(nil), finding.Reasons...),
			Remediation:  remediation,
		})
	}
	return out
}

func buildActionPathRiskItems(paths []risk.ActionPath) []RiskItem {
	out := make([]RiskItem, 0, len(paths))
	for idx, path := range paths {
		rationale := []string{
			fmt.Sprintf("recommended_action=%s", strings.TrimSpace(path.RecommendedAction)),
			fmt.Sprintf("delivery_chain_status=%s", strings.TrimSpace(path.DeliveryChainStatus)),
			fmt.Sprintf("business_state_surface=%s", strings.TrimSpace(path.BusinessStateSurface)),
		}
		if strings.TrimSpace(path.WorkflowTriggerClass) != "" {
			rationale = append(rationale, fmt.Sprintf("workflow_trigger_class=%s", strings.TrimSpace(path.WorkflowTriggerClass)))
		}
		if path.ProductionWrite {
			rationale = append(rationale, "production_write=true")
		}
		if strings.TrimSpace(path.ExecutionIdentityStatus) != "" {
			rationale = append(rationale, fmt.Sprintf("execution_identity_status=%s", strings.TrimSpace(path.ExecutionIdentityStatus)))
		}
		if strings.TrimSpace(path.OwnershipStatus) != "" {
			rationale = append(rationale, fmt.Sprintf("ownership_status=%s", strings.TrimSpace(path.OwnershipStatus)))
		}
		if path.SharedExecutionIdentity {
			rationale = append(rationale, "shared_execution_identity=true")
		}
		if path.StandingPrivilege {
			rationale = append(rationale, "standing_privilege=true")
		}
		out = append(out, RiskItem{
			Rank:              idx + 1,
			CanonicalKey:      strings.TrimSpace(path.PathID),
			Score:             round2(math.Max(path.AttackPathScore, path.RiskScore)),
			FindingType:       "action_path",
			Severity:          actionPathSeverity(path),
			ToolType:          strings.TrimSpace(path.ToolType),
			Org:               strings.TrimSpace(path.Org),
			Repo:              strings.TrimSpace(path.Repo),
			Location:          strings.TrimSpace(path.Location),
			PathID:            strings.TrimSpace(path.PathID),
			RecommendedAction: strings.TrimSpace(path.RecommendedAction),
			WriteCapable:      path.WriteCapable,
			ProductionWrite:   path.ProductionWrite,
			Rationale:         rationale,
			Remediation:       actionPathRemediation(path),
		})
	}
	return out
}

func defaultRemediation(findingType string) string {
	switch strings.TrimSpace(findingType) {
	case "policy_violation":
		return "review and resolve violating policy rule before next scan"
	case "skill_policy_conflict":
		return "tighten skill grants and align permissions with policy"
	case "mcp_server":
		return "validate MCP trust controls and least-privilege transport settings"
	default:
		return "review finding context and apply deterministic least-privilege remediation"
	}
}

func buildNextActions(risks []RiskItem, lifecycleSummary LifecycleSummary, regressSummary *RegressSummary) []ChecklistItem {
	actions := make([]ChecklistItem, 0, 4)
	if len(risks) > 0 {
		text := fmt.Sprintf("triage highest risk finding %s (score %.2f)", risks[0].CanonicalKey, risks[0].Score)
		if risks[0].FindingType == "action_path" {
			text = fmt.Sprintf("review govern-first path %s in %s:%s (action=%s score=%.2f)", risks[0].PathID, risks[0].Repo, risks[0].Location, risks[0].RecommendedAction, risks[0].Score)
		}
		actions = append(actions, ChecklistItem{
			ID:   "action_top_risk",
			Text: text,
		})
	}
	if lifecycleSummary.PendingActionCount > 0 {
		actions = append(actions, ChecklistItem{
			ID:   "action_lifecycle",
			Text: fmt.Sprintf("review %d lifecycle records requiring approval/review/revocation action", lifecycleSummary.PendingActionCount),
		})
	}
	if regressSummary != nil && regressSummary.DriftDetected {
		actions = append(actions, ChecklistItem{
			ID:   "action_regress",
			Text: fmt.Sprintf("investigate %d regress drift reasons before promoting changes", regressSummary.ReasonCount),
		})
	}
	actions = append(actions, ChecklistItem{
		ID:   "action_verify",
		Text: "verify proof chain integrity before sharing artifacts externally",
	})
	if len(actions) > 4 {
		actions = actions[:4]
	}
	return actions
}

func buildSections(
	pack templatespkg.Pack,
	isPublic bool,
	headline Headline,
	methodology Methodology,
	risks []RiskItem,
	attackPathFacts []string,
	complianceSummary compliance.RollupSummary,
	privilegeBudget agginventory.PrivilegeBudget,
	securityVisibility agginventory.SecurityVisibilitySummary,
	deltas DeltaSummary,
	lifecycleSummary LifecycleSummary,
	regressSummary *RegressSummary,
	proof ProofReference,
	nextActions []ChecklistItem,
) []Section {
	riskFacts := make([]string, 0, len(risks))
	for _, item := range risks {
		if item.FindingType == "action_path" {
			riskFacts = append(riskFacts, fmt.Sprintf("#%d %.2f action_path [%s] action=%s repo=%s location=%s", item.Rank, item.Score, item.Severity, item.RecommendedAction, item.Repo, item.Location))
			continue
		}
		riskFacts = append(riskFacts, fmt.Sprintf("#%d %.2f %s [%s] %s", item.Rank, item.Score, item.FindingType, item.Severity, item.Location))
	}
	riskFacts = append(riskFacts, attackPathFacts...)
	if len(riskFacts) == 0 {
		riskFacts = append(riskFacts, "no ranked findings are available in the current snapshot")
	}

	changeFacts := []string{
		formatDelta("risk score trend", deltas.RiskScoreTrend),
		formatDelta("profile compliance delta", deltas.ProfileComplianceDelta),
		formatDelta("posture score trend delta", deltas.PostureScoreTrend),
	}
	if regressSummary != nil {
		changeFacts = append(changeFacts, fmt.Sprintf("regress drift detected=%t reasons=%d", regressSummary.DriftDetected, regressSummary.ReasonCount))
		for _, group := range regressSummary.ReasonGroups {
			changeFacts = append(changeFacts, fmt.Sprintf("drift reason %s count=%d", group.Code, group.Count))
		}
	}

	lifecycleFacts := []string{
		fmt.Sprintf("identities=%d pending_action=%d under_review=%d revoked=%d deprecated=%d", lifecycleSummary.IdentityCount, lifecycleSummary.PendingActionCount, lifecycleSummary.UnderReviewCount, lifecycleSummary.RevokedCount, lifecycleSummary.DeprecatedCount),
	}
	for _, transition := range lifecycleSummary.RecentTransitions {
		lifecycleFacts = append(lifecycleFacts, fmt.Sprintf("transition %s %s->%s (%s)", transition.AgentID, transition.PreviousState, transition.NewState, transition.Trigger))
	}

	proofFacts := []string{
		fmt.Sprintf("chain_path=%s", proof.ChainPath),
		fmt.Sprintf("head_hash=%s", proof.HeadHash),
		fmt.Sprintf("record_count=%d", proof.RecordCount),
	}
	for _, item := range proof.RecordTypeCounts {
		proofFacts = append(proofFacts, fmt.Sprintf("record_type %s=%d", item.RecordType, item.Count))
	}

	nextActionFacts := make([]string, 0, len(nextActions))
	for _, item := range nextActions {
		nextActionFacts = append(nextActionFacts, item.Text)
	}

	headlineFacts := []string{
		fmt.Sprintf("posture score %.2f (%s)", headline.Score, headline.Grade),
		fmt.Sprintf("profile status %s at %.2f%%", headline.ComplianceStatus, headline.Compliance),
		fmt.Sprintf("tools=%d write_capable=%d credential_access=%d exec_capable=%d", privilegeBudget.TotalTools, privilegeBudget.WriteCapableTools, privilegeBudget.CredentialAccessTools, privilegeBudget.ExecCapableTools),
		"bundled framework mappings stay available; profile compliance reflects only controls evidenced in the current deterministic scan state",
		"report scope stays at static posture and offline-verifiable proof; it does not claim runtime observation or control-layer enforcement",
	}
	if hasSecurityVisibilityReference(securityVisibility) {
		headlineFacts = append(headlineFacts, fmt.Sprintf("security_visibility reference=%s unknown_to_security_tools=%d unknown_to_security_agents=%d unknown_to_security_write_capable_agents=%d", securityVisibility.ReferenceBasis, securityVisibility.UnknownToSecurityTools, securityVisibility.UnknownToSecurityAgents, securityVisibility.UnknownToSecurityWriteCapableAgents))
	} else {
		headlineFacts = append(headlineFacts, "security_visibility reference_basis unavailable; unknown_to_security claims suppressed until a saved-state basis is available")
	}
	headlineFacts = append(headlineFacts, compliance.ExplainRollupSummary(complianceSummary, 3)...)
	if privilegeBudget.ProductionWrite.Configured && privilegeBudget.ProductionWrite.Count != nil {
		headlineFacts = append(headlineFacts, fmt.Sprintf("production_write=%d (status=%s)", *privilegeBudget.ProductionWrite.Count, privilegeBudget.ProductionWrite.Status))
	} else {
		headlineFacts = append(headlineFacts, fmt.Sprintf("production targets %s; default claim scope is write_capable=%d", privilegeBudget.ProductionWrite.Status, privilegeBudget.WriteCapableTools))
	}

	methodologyFacts := []string{
		fmt.Sprintf("wrkr_version=%s", methodology.WrkrVersion),
		fmt.Sprintf("scan_window=%s to %s duration=%.2fs", methodology.ScanStartedAt, methodology.ScanCompletedAt, methodology.ScanDurationSeconds),
		fmt.Sprintf("repo_count=%d file_count_processed=%d detector_count=%d", methodology.RepoCount, methodology.FileCountProcessed, methodology.DetectorCount),
		fmt.Sprintf("sample_definition=%s", methodology.SampleDefinition),
	}
	for _, command := range methodology.CommandSet {
		methodologyFacts = append(methodologyFacts, fmt.Sprintf("command=%s", command))
	}
	for _, exclusion := range methodology.ExclusionCriteria {
		methodologyFacts = append(methodologyFacts, fmt.Sprintf("exclusion=%s", exclusion))
	}

	sections := []Section{
		{
			ID:     SectionHeadline,
			Title:  pack.HeadlineTitle,
			Facts:  headlineFacts,
			Impact: postureImpact(headline),
			Action: postureAction(headline),
			Proof:  proof,
		},
		{
			ID:     SectionTopRisks,
			Title:  pack.TopRisksTitle,
			Facts:  riskFacts,
			Impact: riskImpact(risks),
			Action: riskAction(risks),
			Proof:  proof,
		},
		{
			ID:     SectionChanges,
			Title:  pack.ChangesTitle,
			Facts:  changeFacts,
			Impact: changeImpact(deltas, regressSummary),
			Action: changeAction(deltas, regressSummary),
			Proof:  proof,
		},
		{
			ID:     SectionLifecycle,
			Title:  pack.LifecycleTitle,
			Facts:  lifecycleFacts,
			Impact: lifecycleImpact(lifecycleSummary),
			Action: lifecycleAction(lifecycleSummary),
			Proof:  proof,
		},
		{
			ID:     SectionProof,
			Title:  pack.ProofTitle,
			Facts:  proofFacts,
			Impact: "proof chain references are attached for deterministic traceability",
			Action: "preserve chain path and head hash when distributing this artifact",
			Proof:  proof,
		},
		{
			ID:     SectionNextAction,
			Title:  pack.ActionsTitle,
			Facts:  nextActionFacts,
			Impact: "deterministic next actions focus operators on highest leverage controls",
			Action: "execute checklist items in order and rescan to confirm posture improvement",
			Proof:  proof,
		},
	}
	if isPublic {
		publicSections := []Section{
			sections[0],
			{
				ID:     SectionMethodology,
				Title:  "Methodology",
				Facts:  methodologyFacts,
				Impact: "transparent, reproducible method metadata improves external credibility",
				Action: "publish command set and exclusion criteria alongside headline findings",
				Proof:  proof,
			},
		}
		publicSections = append(publicSections, sections[1:]...)
		return publicSections
	}
	return sections
}

func formatDelta(label string, metric DeltaMetric) string {
	if !metric.HasPrevious {
		return fmt.Sprintf("%s current=%.2f delta=0.00 (no previous reference)", label, metric.Current)
	}
	return fmt.Sprintf("%s current=%.2f previous=%.2f delta=%+.2f", label, metric.Current, metric.Previous, metric.Delta)
}

func postureImpact(headline Headline) string {
	if strings.EqualFold(headline.ComplianceStatus, "fail") {
		return "profile compliance is failing and introduces immediate governance risk"
	}
	if headline.Score < 70 {
		return "posture score is below the safe operating threshold"
	}
	return "posture score and compliance status indicate controlled operational risk"
}

func postureAction(headline Headline) string {
	if strings.EqualFold(headline.ComplianceStatus, "fail") {
		return "resolve failing or missing controls, regenerate evidence, and rerun scan with the same deterministic inputs"
	}
	return "monitor score trend and keep profile compliance above configured minimums"
}

func riskImpact(risks []RiskItem) string {
	if len(risks) == 0 {
		return "no prioritized risks were emitted by the current state snapshot"
	}
	return fmt.Sprintf("top %d risks concentrate the highest blast-radius findings", len(risks))
}

func riskAction(risks []RiskItem) string {
	if len(risks) == 0 {
		return "maintain current controls and keep deterministic scans on schedule"
	}
	return "work highest score first and apply deterministic least-privilege remediation"
}

func changeImpact(deltas DeltaSummary, regressSummary *RegressSummary) string {
	if regressSummary != nil && regressSummary.DriftDetected {
		return "regress drift is present and indicates contract movement since baseline"
	}
	if deltas.PostureScoreTrend.HasPrevious && deltas.PostureScoreTrend.Delta < 0 {
		return "posture trend declined relative to previous state"
	}
	return "change deltas remain within expected deterministic variance"
}

func changeAction(deltas DeltaSummary, regressSummary *RegressSummary) string {
	if regressSummary != nil && regressSummary.DriftDetected {
		return "triage grouped regress reasons and block promotion until drift is understood"
	}
	if deltas.PostureScoreTrend.HasPrevious && deltas.PostureScoreTrend.Delta < 0 {
		return "investigate posture regression causes and remediate before next release gate"
	}
	return "continue baseline comparison on every governance scan cadence"
}

func lifecycleImpact(summary LifecycleSummary) string {
	if summary.PendingActionCount == 0 {
		return "no lifecycle identities are waiting on governance action"
	}
	return fmt.Sprintf("%d identities require lifecycle approval/review/revocation handling", summary.PendingActionCount)
}

func lifecycleAction(summary LifecycleSummary) string {
	if summary.PendingActionCount == 0 {
		return "maintain periodic lifecycle review cadence"
	}
	return "prioritize under_review and revoked identities before enabling additional autonomy"
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}

func buildAttackPathSummary(report risk.Report) AttackPathSummary {
	out := AttackPathSummary{Total: len(report.AttackPaths), TopPathIDs: []string{}}
	for _, path := range report.TopAttackPaths {
		out.TopPathIDs = append(out.TopPathIDs, strings.TrimSpace(path.PathID))
	}
	out.TopPathIDs = uniqueStrings(out.TopPathIDs)
	return out
}

func buildAttackPathFacts(report risk.Report) []string {
	if len(report.TopAttackPaths) == 0 {
		return []string{"attack paths: none generated from current findings"}
	}
	facts := make([]string, 0, len(report.TopAttackPaths)+1)
	facts = append(facts, fmt.Sprintf("attack paths total=%d", len(report.AttackPaths)))
	for idx, path := range report.TopAttackPaths {
		facts = append(facts, fmt.Sprintf("attack_path #%d score=%.2f id=%s", idx+1, path.PathScore, path.PathID))
	}
	return facts
}

func buildAssessmentSummary(paths []risk.ActionPath, controlFirst *risk.ActionPathToControlFirst, inventory *agginventory.Inventory, proof ProofReference) *AssessmentSummary {
	if len(paths) == 0 {
		return nil
	}
	identityToReviewFirst, identityToRevokeFirst := risk.BuildIdentityActionTargets(paths)
	summary := &AssessmentSummary{
		GovernablePathCount:       len(paths),
		WriteCapablePathCount:     0,
		ProductionBackedPathCount: 0,
		OwnerlessExposure:         risk.BuildOwnerlessExposure(paths),
		IdentityExposureSummary:   risk.BuildIdentityExposureSummary(paths, inventory),
		IdentityToReviewFirst:     identityToReviewFirst,
		IdentityToRevokeFirst:     identityToRevokeFirst,
		ProofChainPath:            proof.ChainPath,
	}
	for _, path := range paths {
		if path.WriteCapable {
			summary.WriteCapablePathCount++
		}
		if path.ProductionWrite {
			summary.ProductionBackedPathCount++
		}
		if summary.TopExecutionIdentityBacked == nil && strings.TrimSpace(path.ExecutionIdentityStatus) == "known" {
			candidate := path
			summary.TopExecutionIdentityBacked = &candidate
		}
	}
	if controlFirst != nil {
		candidate := controlFirst.Path
		summary.TopPathToControlFirst = &candidate
	}
	return summary
}

func actionPathSeverity(path risk.ActionPath) string {
	switch strings.TrimSpace(path.RecommendedAction) {
	case "control":
		return model.SeverityHigh
	case "approval", "proof":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func actionPathRemediation(path risk.ActionPath) string {
	if strings.TrimSpace(path.OwnerSource) == "multi_repo_conflict" || strings.TrimSpace(path.OwnershipStatus) == "unresolved" {
		return "needs owner clarification before this path should be approved, delegated, or expanded"
	}
	switch strings.TrimSpace(path.RecommendedAction) {
	case "control":
		if strings.TrimSpace(path.WorkflowTriggerClass) == "deploy_pipeline" {
			return "apply the highest-priority control on this deploy-pipeline backed path and rescan to confirm reduced exposure"
		}
		return "apply the highest-priority control on this write-capable path and rescan to confirm reduced exposure"
	case "approval":
		return "add or tighten deterministic human approval gates on this path before allowing further automation"
	case "proof":
		return "collect stronger identity, ownership, trigger-posture, or deployment proof for this path before approving it"
	default:
		return "inventory this visibility-first path before expanding its privileges"
	}
}

func buildComplianceSummary(statePath string, findings []source.Finding) (compliance.RollupSummary, error) {
	chainPath := proofemit.ChainPath(state.ResolvePath(strings.TrimSpace(statePath)))
	chain, err := proofemit.LoadChain(chainPath)
	if err != nil {
		return compliance.RollupSummary{}, err
	}
	summary, err := compliance.BuildRollupSummary(findings, chain)
	if err != nil {
		return compliance.RollupSummary{}, &complianceSummaryError{err: err}
	}
	return summary, nil
}

func uniqueStrings(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func sanitizeProofReferencePublic(in ProofReference) ProofReference {
	copyRef := in
	copyRef.ChainPath = "redacted://proof-chain.json"
	keys := make([]string, 0, len(copyRef.CanonicalFindingKeys))
	for _, key := range copyRef.CanonicalFindingKeys {
		redacted := redactValue("finding", key, 12)
		if redacted == "" {
			continue
		}
		keys = append(keys, redacted)
	}
	sort.Strings(keys)
	copyRef.CanonicalFindingKeys = keys
	return copyRef
}

func sanitizeLifecycleSummaryPublic(in LifecycleSummary) LifecycleSummary {
	copySummary := in
	for idx := range copySummary.RecentTransitions {
		copySummary.RecentTransitions[idx].AgentID = redactValue("agent", copySummary.RecentTransitions[idx].AgentID, 8)
	}
	return copySummary
}

func sanitizeRiskItemsPublic(in []RiskItem) []RiskItem {
	out := make([]RiskItem, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.CanonicalKey = redactValue("finding", copyItem.CanonicalKey, 12)
		copyItem.Location = redactValue("loc", copyItem.Location, 8)
		copyItem.Repo = redactValue("repo", copyItem.Repo, 6)
		copyItem.Org = redactValue("org", copyItem.Org, 6)
		copyItem.PathID = redactValue("path", copyItem.PathID, 8)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeActivationSummaryPublic(in *ActivationSummary) *ActivationSummary {
	if in == nil {
		return nil
	}
	copySummary := *in
	copySummary.Items = append([]ActivationItem(nil), in.Items...)
	for idx := range copySummary.Items {
		copySummary.Items[idx].Location = redactValue("loc", copySummary.Items[idx].Location, 8)
		copySummary.Items[idx].Repo = redactValue("repo", copySummary.Items[idx].Repo, 6)
	}
	return &copySummary
}

func sanitizeActionPathsPublic(in []risk.ActionPath) []risk.ActionPath {
	if len(in) == 0 {
		return nil
	}
	out := make([]risk.ActionPath, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.PathID = redactValue("path", copyItem.PathID, 8)
		copyItem.Org = redactValue("org", copyItem.Org, 6)
		copyItem.Repo = redactValue("repo", copyItem.Repo, 6)
		copyItem.AgentID = redactValue("agent", copyItem.AgentID, 8)
		copyItem.Location = redactValue("loc", copyItem.Location, 8)
		copyItem.OperationalOwner = redactValue("owner", copyItem.OperationalOwner, 8)
		copyItem.ExecutionIdentity = redactValue("identity", copyItem.ExecutionIdentity, 8)
		targets := make([]string, 0, len(copyItem.MatchedProductionTargets))
		for _, target := range copyItem.MatchedProductionTargets {
			redacted := redactValue("target", target, 8)
			if redacted == "" {
				continue
			}
			targets = append(targets, redacted)
		}
		copyItem.MatchedProductionTargets = targets
		out = append(out, copyItem)
	}
	return out
}

func sanitizeActionPathToControlFirstPublic(in *risk.ActionPathToControlFirst) *risk.ActionPathToControlFirst {
	if in == nil {
		return nil
	}
	copySummary := in.Summary
	paths := sanitizeActionPathsPublic([]risk.ActionPath{in.Path})
	if len(paths) == 0 {
		return &risk.ActionPathToControlFirst{Summary: copySummary}
	}
	return &risk.ActionPathToControlFirst{
		Summary: copySummary,
		Path:    paths[0],
	}
}

func sanitizeExposureGroupsPublic(in []risk.ExposureGroup) []risk.ExposureGroup {
	if len(in) == 0 {
		return nil
	}
	out := make([]risk.ExposureGroup, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.GroupID = redactValue("group", copyItem.GroupID, 8)
		copyItem.Org = redactValue("org", copyItem.Org, 6)
		copyItem.ExecutionIdentity = redactValue("identity", copyItem.ExecutionIdentity, 8)
		copyItem.ExampleRepo = redactValue("repo", copyItem.ExampleRepo, 6)
		copyItem.ExampleLocation = redactValue("loc", copyItem.ExampleLocation, 8)
		copyItem.Repos = redactStringSlice(copyItem.Repos, "repo")
		copyItem.PathIDs = redactStringSlice(copyItem.PathIDs, "path")
		out = append(out, copyItem)
	}
	return out
}

func sanitizeAssessmentSummaryPublic(in *AssessmentSummary) *AssessmentSummary {
	if in == nil {
		return nil
	}
	copySummary := *in
	if in.TopPathToControlFirst != nil {
		paths := sanitizeActionPathsPublic([]risk.ActionPath{*in.TopPathToControlFirst})
		if len(paths) == 1 {
			copySummary.TopPathToControlFirst = &paths[0]
		}
	}
	if in.TopExecutionIdentityBacked != nil {
		paths := sanitizeActionPathsPublic([]risk.ActionPath{*in.TopExecutionIdentityBacked})
		if len(paths) == 1 {
			copySummary.TopExecutionIdentityBacked = &paths[0]
		}
	}
	if in.IdentityToReviewFirst != nil {
		copyTarget := *in.IdentityToReviewFirst
		copyTarget.ExecutionIdentity = redactValue("identity", copyTarget.ExecutionIdentity, 8)
		copySummary.IdentityToReviewFirst = &copyTarget
	}
	if in.IdentityToRevokeFirst != nil {
		copyTarget := *in.IdentityToRevokeFirst
		copyTarget.ExecutionIdentity = redactValue("identity", copyTarget.ExecutionIdentity, 8)
		copySummary.IdentityToRevokeFirst = &copyTarget
	}
	copySummary.ProofChainPath = sanitizeProofReferencePublic(ProofReference{ChainPath: in.ProofChainPath}).ChainPath
	return &copySummary
}

func redactStringSlice(values []string, prefix string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		redacted := redactValue(prefix, value, 8)
		if redacted == "" {
			continue
		}
		out = append(out, redacted)
	}
	return out
}

func redactValue(prefix, value string, width int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	hex := fmt.Sprintf("%x", sum)
	if width <= 0 || width > len(hex) {
		width = len(hex)
	}
	return fmt.Sprintf("%s-%s", prefix, hex[:width])
}
