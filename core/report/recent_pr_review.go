package report

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/risk"
)

type RecentPRReviewOptions struct {
	IDs         []string
	DateFrom    time.Time
	HasDateFrom bool
	DateTo      time.Time
	HasDateTo   bool
	Limit       int
}

func BuildRecentPRReview(summary Summary, opts RecentPRReviewOptions) *RecentPRReview {
	limit := opts.Limit
	if limit <= 0 {
		limit = 10
	}
	bom := summary.AgentActionBOM
	if bom == nil {
		bom = BuildAgentActionBOM(summary)
	}
	if bom == nil {
		return &RecentPRReview{Mode: "local_sidecars", Limit: limit}
	}

	idSet := map[string]struct{}{}
	for _, id := range opts.IDs {
		trimmed := strings.TrimSpace(id)
		if trimmed != "" {
			idSet[trimmed] = struct{}{}
		}
	}

	candidates := make([]RecentPRReviewItem, 0, len(bom.Items))
	for _, item := range bom.Items {
		if !isRecentPRReviewCandidate(item) {
			continue
		}
		if len(idSet) > 0 {
			reference := reviewReference(item.IntroducedBy)
			if _, ok := idSet[reference]; !ok {
				continue
			}
		}
		timestamp := reviewTimestamp(item.IntroducedBy)
		if opts.HasDateFrom && (timestamp.IsZero() || timestamp.Before(opts.DateFrom)) {
			continue
		}
		if opts.HasDateTo && (timestamp.IsZero() || timestamp.After(opts.DateTo)) {
			continue
		}
		candidates = append(candidates, buildRecentPRReviewItem(item))
	}

	sort.Slice(candidates, func(i, j int) bool {
		leftScore := recentPRReviewScore(candidates[i])
		rightScore := recentPRReviewScore(candidates[j])
		if leftScore != rightScore {
			return leftScore > rightScore
		}
		leftTS := reviewTimestamp(candidates[i].Provenance)
		rightTS := reviewTimestamp(candidates[j].Provenance)
		if !leftTS.Equal(rightTS) {
			return leftTS.After(rightTS)
		}
		if candidates[i].Reference != candidates[j].Reference {
			return candidates[i].Reference < candidates[j].Reference
		}
		return candidates[i].PathID < candidates[j].PathID
	})

	total := len(candidates)
	if limit < len(candidates) {
		candidates = candidates[:limit]
	}
	for idx := range candidates {
		candidates[idx].Rank = idx + 1
	}

	selectedIDs := append([]string(nil), opts.IDs...)
	sort.Strings(selectedIDs)
	review := &RecentPRReview{
		Mode:            "local_sidecars",
		Limit:           limit,
		SelectedIDs:     selectedIDs,
		TotalCandidates: total,
		Ranked:          candidates,
	}
	if opts.HasDateFrom {
		review.DateFrom = opts.DateFrom.Format("2006-01-02")
	}
	if opts.HasDateTo {
		review.DateTo = opts.DateTo.Format("2006-01-02")
	}
	return review
}

func buildRecentPRReviewItem(item AgentActionBOMItem) RecentPRReviewItem {
	missingEvidence := []string{}
	if item.IntroducedBy != nil && item.IntroducedBy.Provenance != nil {
		missingEvidence = append(missingEvidence, item.IntroducedBy.Provenance.MissingEvidence...)
	}
	if strings.TrimSpace(item.EvidencePacketMissingEvidenceState) == "missing" {
		missingEvidence = append(missingEvidence, "evidence_packet_missing")
	}
	return RecentPRReviewItem{
		ReviewID:                 firstNonEmptyValue(strings.TrimSpace(item.PathID), reviewReference(item.IntroducedBy)),
		Reference:                reviewReference(item.IntroducedBy),
		Provider:                 reviewProvider(item.IntroducedBy),
		Repo:                     strings.TrimSpace(item.Repo),
		PathID:                   strings.TrimSpace(item.PathID),
		Workflow:                 strings.TrimSpace(item.Location),
		AutonomyTier:             strings.TrimSpace(item.AutonomyTier),
		DelegationReadinessState: strings.TrimSpace(item.DelegationReadinessState),
		RecommendedControl:       strings.TrimSpace(item.RecommendedControl),
		TargetClass:              strings.TrimSpace(item.TargetClass),
		EvidenceCompleteness:     evidenceCompletenessProjection(item.EvidenceCompleteness),
		Contradiction:            item.DelegationReadinessState == "blocked_by_contradiction" || len(item.Contradictions) > 0 || item.EvidencePacketStatus == "conflict",
		AIAssisted:               item.IntroducedBy != nil && item.IntroducedBy.Provenance != nil && item.IntroducedBy.Provenance.AIAssisted,
		AutomationAssisted:       item.IntroducedBy != nil && item.IntroducedBy.Provenance != nil && item.IntroducedBy.Provenance.AutomationAssisted,
		CheckCount:               reviewCheckCount(item.IntroducedBy),
		ApprovalCount:            reviewApprovalCount(item.IntroducedBy),
		DeploymentCount:          reviewDeploymentCount(item.IntroducedBy),
		FocusBOMPathID:           strings.TrimSpace(item.PathID),
		Provenance:               attribution.Merge(item.IntroducedBy, nil),
		WorkflowChainRefs:        append([]string(nil), item.WorkflowChainRefs...),
		GraphRefs:                item.GraphRefs,
		ProofRefs:                append([]string(nil), item.ProofRefs...),
		EvidencePacketRefs:       append([]string(nil), item.EvidencePacketRefs...),
		MissingEvidence:          uniqueSortedStrings(missingEvidence),
	}
}

func isRecentPRReviewCandidate(item AgentActionBOMItem) bool {
	if item.IntroducedBy == nil {
		return false
	}
	if item.IntroducedBy.Provenance != nil && (item.IntroducedBy.Provenance.AIAssisted || item.IntroducedBy.Provenance.AutomationAssisted) {
		return true
	}
	switch strings.TrimSpace(item.ActionPathType) {
	case "ai_assisted_workflow", "automation_bot", "agent_framework", "ci_cd_workflow":
		return true
	default:
		return false
	}
}

func recentPRReviewScore(item RecentPRReviewItem) int {
	score := 0
	score += autonomyTierRank(item.AutonomyTier) * 100
	score += delegationReadinessRank(item.DelegationReadinessState) * 20
	score += targetClassRank(item.TargetClass) * 10
	score += evidenceCompletenessRank(item.EvidenceCompleteness) * 5
	if item.Contradiction {
		score += 50
	}
	if item.AIAssisted {
		score += 3
	}
	if item.AutomationAssisted {
		score += 2
	}
	if len(item.MissingEvidence) > 0 {
		score += 4
	}
	return score
}

func autonomyTierRank(value string) int {
	switch strings.TrimSpace(value) {
	case "tier_4_prod_privileged_or_customer_impacting":
		return 5
	case "tier_3_sensitive_code_or_infra":
		return 4
	case "tier_2_app_code_owner_review":
		return 3
	case "tier_1_low_risk_internal":
		return 2
	case "tier_0_safe_metadata":
		return 1
	default:
		return 0
	}
}

func delegationReadinessRank(value string) int {
	switch strings.TrimSpace(value) {
	case "blocked_by_contradiction":
		return 7
	case "blocked":
		return 6
	case "proof_required":
		return 5
	case "approval_required":
		return 4
	case "review_required":
		return 3
	case "ready_for_control":
		return 2
	case "safe_to_delegate":
		return 1
	default:
		return 0
	}
}

func targetClassRank(value string) int {
	switch strings.TrimSpace(value) {
	case "production_impacting":
		return 4
	case "release_adjacent", "customer_data_adjacent":
		return 3
	case "internal_tooling", "developer_productivity":
		return 2
	case "test_demo_sandbox":
		return 1
	default:
		return 0
	}
}

func evidenceCompletenessRank(value string) int {
	switch strings.TrimSpace(value) {
	case "insufficient_evidence":
		return 3
	case "partial_evidence":
		return 2
	case "strong_evidence":
		return 1
	default:
		return 0
	}
}

func evidenceCompletenessProjection(in *risk.EvidenceCompleteness) string {
	if in == nil {
		return ""
	}
	return strings.TrimSpace(in.Label)
}

func reviewReference(in *attribution.Result) string {
	if in == nil {
		return ""
	}
	if strings.TrimSpace(in.Reference) != "" {
		return strings.TrimSpace(in.Reference)
	}
	if in.PRNumber > 0 {
		return "pr/" + strings.TrimSpace(strconv.Itoa(in.PRNumber))
	}
	return ""
}

func reviewProvider(in *attribution.Result) string {
	if in == nil {
		return ""
	}
	if strings.TrimSpace(in.Provider) != "" {
		return strings.TrimSpace(in.Provider)
	}
	if in.Provenance != nil {
		return strings.TrimSpace(in.Provenance.Provider)
	}
	return ""
}

func reviewTimestamp(in *attribution.Result) time.Time {
	if in == nil {
		return time.Time{}
	}
	value := strings.TrimSpace(in.Timestamp)
	if value == "" && in.Provenance != nil {
		value = strings.TrimSpace(in.Provenance.UpdatedAt)
	}
	parsed, _ := time.Parse(time.RFC3339, value)
	return parsed
}

func reviewCheckCount(in *attribution.Result) int {
	if in == nil || in.Provenance == nil {
		return 0
	}
	return len(in.Provenance.Checks)
}

func reviewApprovalCount(in *attribution.Result) int {
	if in == nil || in.Provenance == nil {
		return 0
	}
	return len(in.Provenance.Approvals)
}

func reviewDeploymentCount(in *attribution.Result) int {
	if in == nil || in.Provenance == nil {
		return 0
	}
	return len(in.Provenance.Deployments)
}
