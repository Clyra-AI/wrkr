package report

import (
	"crypto/sha256"
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/regress"
	templatespkg "github.com/Clyra-AI/wrkr/core/report/templates"
	"github.com/Clyra-AI/wrkr/core/risk"
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
	if top <= 0 {
		top = 5
	}

	riskReport := in.Snapshot.RiskReport
	if riskReport == nil {
		generated := risk.Score(in.Snapshot.Findings, top, now)
		riskReport = &generated
	}
	topFindings := SelectTopFindings(*riskReport, top)

	proofRef, err := buildProofReference(in.StatePath, topFindings)
	if err != nil {
		return Summary{}, err
	}

	lifecycleSummary := buildLifecycleSummary(in.Manifest, in.Snapshot.Identities, in.Snapshot.Transitions)
	regressSummary := buildRegressSummary(in.Baseline, in.RegressResult)
	deltas := buildDeltaSummary(in.Snapshot, in.PreviousSnapshot, top)
	headline := buildHeadline(in.Snapshot)
	riskItems := buildRiskItems(topFindings)

	if shareProfile == ShareProfilePublic {
		proofRef = sanitizeProofReferencePublic(proofRef)
		lifecycleSummary = sanitizeLifecycleSummaryPublic(lifecycleSummary)
		riskItems = sanitizeRiskItemsPublic(riskItems)
	}

	nextActions := buildNextActions(riskItems, lifecycleSummary, regressSummary)
	pack := templatespkg.Resolve(string(template))
	sections := buildSections(pack, headline, riskItems, deltas, lifecycleSummary, regressSummary, proofRef, nextActions)

	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    now.Format(time.RFC3339),
		Template:       string(template),
		ShareProfile:   string(shareProfile),
		SectionOrder: []string{
			SectionHeadline,
			SectionTopRisks,
			SectionChanges,
			SectionLifecycle,
			SectionProof,
			SectionNextAction,
		},
		Sections:     sections,
		Headline:     headline,
		TopRisks:     riskItems,
		Deltas:       deltas,
		Lifecycle:    lifecycleSummary,
		RegressDrift: regressSummary,
		Proof:        proofRef,
		NextActions:  nextActions,
	}

	return summary, nil
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
		identities = append(identities, m.Identities...)
	}
	if len(identities) == 0 {
		identities = append(identities, snapshotIdentities...)
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

func buildRiskItems(findings []risk.ScoredFinding) []RiskItem {
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
		actions = append(actions, ChecklistItem{
			ID:   "action_top_risk",
			Text: fmt.Sprintf("triage highest risk finding %s (score %.2f)", risks[0].CanonicalKey, risks[0].Score),
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
	headline Headline,
	risks []RiskItem,
	deltas DeltaSummary,
	lifecycleSummary LifecycleSummary,
	regressSummary *RegressSummary,
	proof ProofReference,
	nextActions []ChecklistItem,
) []Section {
	riskFacts := make([]string, 0, len(risks))
	for _, item := range risks {
		riskFacts = append(riskFacts, fmt.Sprintf("#%d %.2f %s [%s] %s", item.Rank, item.Score, item.FindingType, item.Severity, item.Location))
	}
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
	}

	return []Section{
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
		return "resolve failing profile controls and rerun scan with the same deterministic inputs"
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

func sanitizeProofReferencePublic(in ProofReference) ProofReference {
	copyRef := in
	copyRef.ChainPath = "redacted://proof-chain.json"
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
		copyItem.Location = redactValue("loc", copyItem.Location, 8)
		copyItem.Repo = redactValue("repo", copyItem.Repo, 6)
		copyItem.Org = redactValue("org", copyItem.Org, 6)
		out = append(out, copyItem)
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
