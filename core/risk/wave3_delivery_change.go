package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Clyra-AI/wrkr/core/attribution"
)

const (
	AgenticDeliverySurfaceInstruction = "instruction"
	AgenticDeliverySurfaceSkillpack   = "skillpack"
	AgenticDeliverySurfaceAgentRule   = "agent_rule"
	AgenticDeliverySurfaceMCPConfig   = "mcp_config"
	AgenticDeliverySurfaceToolConfig  = "tool_config"

	AgenticReviewStateProtected  = "review_protected"
	AgenticReviewStateMissing    = "approval_missing"
	AgenticReviewStatePartial    = "review_partial"
	AgenticReviewStateBypassRisk = "review_bypass_risk"
	AgenticReviewStateUnknown    = "review_unknown"

	AgenticAuthorityImpactProduction   = "production_mutation"
	AgenticAuthorityImpactRelease      = "release_or_deploy"
	AgenticAuthorityImpactCredential   = "credential_authority" // #nosec G101 -- Deterministic authority-impact enum label, not credential material.
	AgenticAuthorityImpactReviewBypass = "review_bypass"
	AgenticAuthorityImpactWriteScope   = "write_scope"
	AgenticAuthorityImpactReview       = "review_surface"
	AgenticAuthorityImpactNone         = "none"
)

type AgenticDeliverySystemChange struct {
	ChangeID               string   `json:"change_id,omitempty"`
	SurfaceType            string   `json:"surface_type,omitempty"`
	ChangedArtifact        string   `json:"changed_artifact,omitempty"`
	AuthorityImpact        string   `json:"authority_impact,omitempty"`
	AuthorityImpactReasons []string `json:"authority_impact_reasons,omitempty"`
	ReachableTools         []string `json:"reachable_tools,omitempty"`
	ReachableTargets       []string `json:"reachable_targets,omitempty"`
	CredentialReach        string   `json:"credential_reach,omitempty"`
	ReviewState            string   `json:"review_state,omitempty"`
	ReviewStateReasons     []string `json:"review_state_reasons,omitempty"`
	RecommendedControl     string   `json:"recommended_control,omitempty"`
	EvidenceRefs           []string `json:"evidence_refs,omitempty"`
	HighImpact             bool     `json:"high_impact,omitempty"`
}

func CloneAgenticDeliverySystemChange(in *AgenticDeliverySystemChange) *AgenticDeliverySystemChange {
	if in == nil {
		return nil
	}
	out := *in
	out.ChangeID = strings.TrimSpace(out.ChangeID)
	out.SurfaceType = strings.TrimSpace(out.SurfaceType)
	out.ChangedArtifact = strings.TrimSpace(out.ChangedArtifact)
	out.AuthorityImpact = strings.TrimSpace(out.AuthorityImpact)
	out.AuthorityImpactReasons = dedupeSortedStrings(out.AuthorityImpactReasons)
	out.ReachableTools = dedupeSortedStrings(out.ReachableTools)
	out.ReachableTargets = dedupeSortedStrings(out.ReachableTargets)
	out.CredentialReach = strings.TrimSpace(out.CredentialReach)
	out.ReviewState = strings.TrimSpace(out.ReviewState)
	out.ReviewStateReasons = dedupeSortedStrings(out.ReviewStateReasons)
	out.RecommendedControl = strings.TrimSpace(out.RecommendedControl)
	out.EvidenceRefs = dedupeSortedStrings(out.EvidenceRefs)
	return &out
}

func buildAgenticDeliverySystemChange(path ActionPath) *AgenticDeliverySystemChange {
	surfaceType := classifyAgenticDeliverySurface(path)
	if surfaceType == "" {
		return nil
	}

	authorityImpact, authorityReasons := deriveAgenticAuthorityImpact(path)
	reviewState, reviewReasons := deriveAgenticReviewState(path)
	evidenceRefs := append([]string(nil), path.ControlEvidenceRefs...)
	evidenceRefs = append(evidenceRefs, path.PolicyEvidenceRefs...)
	evidenceRefs = append(evidenceRefs, path.TargetClassEvidenceRefs...)
	evidenceRefs = append(evidenceRefs, path.ActionPathTypeEvidenceRefs...)
	if path.IntroducedBy != nil {
		evidenceRefs = append(evidenceRefs, attribution.EvidenceRefs(path.IntroducedBy)...)
	}
	change := &AgenticDeliverySystemChange{
		SurfaceType:            surfaceType,
		ChangedArtifact:        strings.TrimSpace(path.Location),
		AuthorityImpact:        authorityImpact,
		AuthorityImpactReasons: dedupeSortedStrings(authorityReasons),
		ReachableTargets:       boundedStrings(path.MatchedProductionTargets, 3),
		CredentialReach:        agenticCredentialReach(path),
		ReviewState:            reviewState,
		ReviewStateReasons:     dedupeSortedStrings(reviewReasons),
		RecommendedControl:     strings.TrimSpace(path.RecommendedControl),
		EvidenceRefs:           dedupeSortedStrings(evidenceRefs),
		HighImpact:             pathHasHighStakesPreset(path) || strings.TrimSpace(path.ControlPriority) == ControlPriorityControlFirst,
	}
	change.ChangeID = agenticDeliveryChangeID(path, *change)
	if change.AuthorityImpact == AgenticAuthorityImpactNone &&
		change.ReviewState == AgenticReviewStateUnknown &&
		!change.HighImpact &&
		change.CredentialReach == "no_visible_credential" {
		return nil
	}
	return change
}

func classifyAgenticDeliverySurface(path ActionPath) string {
	toolType := strings.ToLower(strings.TrimSpace(path.ToolType))
	location := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path.Location), "\\", "/"))
	switch {
	case strings.HasSuffix(location, "/skill.md") || strings.Contains(location, "/skills/"):
		return AgenticDeliverySurfaceSkillpack
	case toolType == "prompt_channel",
		strings.Contains(location, "agents.md"),
		strings.Contains(location, "claude.md"),
		strings.Contains(location, "prompt"),
		strings.Contains(location, "instruction"):
		return AgenticDeliverySurfaceInstruction
	case strings.Contains(location, ".cursor/rules/"),
		strings.HasSuffix(location, ".cursorrules"),
		strings.Contains(location, "copilot-instructions"):
		return AgenticDeliverySurfaceAgentRule
	case strings.Contains(location, "mcp.json"),
		strings.Contains(location, "/mcp."),
		strings.Contains(location, "mcpgateway"),
		strings.Contains(location, "mcp-gateway"),
		strings.Contains(toolType, "mcp"):
		return AgenticDeliverySurfaceMCPConfig
	case strings.Contains(location, ".codex/config."),
		strings.Contains(location, ".claude/settings"),
		strings.Contains(location, "settings.local.json"),
		strings.Contains(location, "managed-mcp.json"):
		return AgenticDeliverySurfaceToolConfig
	default:
		return ""
	}
}

func deriveAgenticAuthorityImpact(path ActionPath) (string, []string) {
	reasons := []string{}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}
	for _, preset := range path.HighStakesPresets {
		add("preset:" + strings.TrimSpace(preset.Preset))
	}
	if len(path.AuthorityBindings) > 0 {
		add("authority_bindings:present")
	}
	if path.ProductionWrite || pathHasHighImpactMutableEndpoint(path) {
		add("production_write:true")
		if pathHasHighImpactMutableEndpoint(path) {
			add("mutable_endpoint:high_impact")
		}
		return AgenticAuthorityImpactProduction, dedupeSortedStrings(reasons)
	}
	if pathHasReviewBypassRisk(path) {
		add("review_bypass_risk:true")
		return AgenticAuthorityImpactReviewBypass, dedupeSortedStrings(reasons)
	}
	if path.DeployWrite || path.MergeExecute || hasAgenticHighStakesPreset(path, HighStakesPresetReleaseAutomation, HighStakesPresetPackagePublishing, HighStakesPresetInfrastructureAsCode) {
		if path.DeployWrite {
			add("deploy_write:true")
		}
		if path.MergeExecute {
			add("merge_execute:true")
		}
		return AgenticAuthorityImpactRelease, dedupeSortedStrings(reasons)
	}
	if path.CredentialAccess || path.StandingPrivilege || len(path.AuthorityBindings) > 0 {
		if path.CredentialAccess {
			add("credential_access:true")
		}
		if path.StandingPrivilege {
			add("standing_privilege:true")
		}
		return AgenticAuthorityImpactCredential, dedupeSortedStrings(reasons)
	}
	if path.WriteCapable || path.PullRequestWrite {
		if path.WriteCapable {
			add("write_capable:true")
		}
		if path.PullRequestWrite {
			add("pull_request_write:true")
		}
		return AgenticAuthorityImpactWriteScope, dedupeSortedStrings(reasons)
	}
	if path.ApprovalGap || strings.TrimSpace(path.ControlResolutionState) == ControlResolutionStateNoVisibleControl {
		if path.ApprovalGap {
			add("approval_gap:true")
		}
		if strings.TrimSpace(path.ControlResolutionState) == ControlResolutionStateNoVisibleControl {
			add("control_resolution:no_visible_control")
		}
		return AgenticAuthorityImpactReview, dedupeSortedStrings(reasons)
	}
	return AgenticAuthorityImpactNone, dedupeSortedStrings(reasons)
}

func deriveAgenticReviewState(path ActionPath) (string, []string) {
	reasons := []string{}
	add := func(reason string) {
		if strings.TrimSpace(reason) != "" {
			reasons = append(reasons, strings.TrimSpace(reason))
		}
	}
	if pathHasReviewBypassRisk(path) {
		add("review_controls:missing_or_conflicting")
		if path.IntroducedBy != nil && path.IntroducedBy.Provenance != nil {
			add("provenance_conflict:" + strings.TrimSpace(path.IntroducedBy.Provenance.ConflictState))
			reasons = append(reasons, path.IntroducedBy.Provenance.MissingEvidence...)
		}
		return AgenticReviewStateBypassRisk, dedupeSortedStrings(reasons)
	}
	switch normalizeEvidenceState(path.ApprovalEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateContradictory:
		add("approval_evidence:" + normalizeEvidenceState(path.ApprovalEvidenceState))
		if path.ApprovalGap {
			reasons = append(reasons, path.ApprovalGapReasons...)
		}
		return AgenticReviewStateMissing, dedupeSortedStrings(reasons)
	}
	if path.IntroducedBy != nil && path.IntroducedBy.Provenance != nil {
		provenance := path.IntroducedBy.Provenance
		protected := len(provenance.BranchProtections) > 0 || len(provenance.EnvironmentGates) > 0 || len(provenance.Approvals) > 0 || len(provenance.Checks) > 0
		if protected && len(provenance.MissingEvidence) == 0 && strings.TrimSpace(provenance.ConflictState) == "none" {
			add("provenance:protected")
			return AgenticReviewStateProtected, dedupeSortedStrings(reasons)
		}
		if protected || len(provenance.MissingEvidence) > 0 {
			add("provenance:partial")
			reasons = append(reasons, provenance.MissingEvidence...)
			return AgenticReviewStatePartial, dedupeSortedStrings(reasons)
		}
	}
	return AgenticReviewStateUnknown, nil
}

func pathHasReviewBypassRisk(path ActionPath) bool {
	if !path.MergeExecute && !path.DeployWrite && !path.PullRequestWrite {
		return false
	}
	if path.IntroducedBy == nil || path.IntroducedBy.Provenance == nil {
		return false
	}
	provenance := path.IntroducedBy.Provenance
	if strings.TrimSpace(provenance.ConflictState) == "conflict" {
		return true
	}
	for _, missing := range provenance.MissingEvidence {
		switch strings.TrimSpace(missing) {
		case "branch_protection_missing", "checks_missing", "approvals_missing", "environment_gates_missing":
			return true
		}
	}
	if len(provenance.BranchProtections) == 0 || len(provenance.Checks) == 0 {
		return true
	}
	for _, item := range provenance.BranchProtections {
		switch strings.TrimSpace(item.Status) {
		case "", "missing", "conflict", "unknown":
			return true
		}
	}
	for _, item := range provenance.EnvironmentGates {
		switch strings.TrimSpace(item.Status) {
		case "missing", "conflict":
			return true
		}
	}
	return false
}

func agenticCredentialReach(path ActionPath) string {
	if path.CredentialAuthority != nil {
		parts := []string{}
		if kind := strings.TrimSpace(path.CredentialAuthority.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if target := strings.TrimSpace(path.CredentialAuthority.TargetSystem); target != "" {
			parts = append(parts, target)
		}
		if scope := strings.TrimSpace(path.CredentialAuthority.LikelyScope); scope != "" {
			parts = append(parts, scope)
		}
		switch {
		case path.CredentialAuthority.StandingAccess:
			parts = append(parts, "standing")
		case path.CredentialAuthority.LikelyJIT:
			parts = append(parts, "jit")
		}
		if len(parts) > 0 {
			return strings.Join(dedupeSortedStrings(parts), " ")
		}
	}
	if path.CredentialProvenance != nil {
		parts := []string{}
		if kind := strings.TrimSpace(path.CredentialProvenance.CredentialKind); kind != "" {
			parts = append(parts, kind)
		}
		if target := strings.TrimSpace(path.CredentialProvenance.TargetSystem); target != "" {
			parts = append(parts, target)
		}
		if scope := strings.TrimSpace(path.CredentialProvenance.LikelyScope); scope != "" {
			parts = append(parts, scope)
		}
		switch {
		case path.CredentialProvenance.StandingAccess:
			parts = append(parts, "standing")
		case path.CredentialProvenance.LikelyJIT:
			parts = append(parts, "jit")
		}
		if len(parts) > 0 {
			return strings.Join(dedupeSortedStrings(parts), " ")
		}
	}
	if path.CredentialAccess {
		return "credential_access_present"
	}
	return "no_visible_credential"
}

func agenticDeliveryChangeID(path ActionPath, change AgenticDeliverySystemChange) string {
	raw := strings.Join([]string{
		strings.TrimSpace(path.PathID),
		strings.TrimSpace(change.SurfaceType),
		strings.TrimSpace(change.AuthorityImpact),
		strings.TrimSpace(change.ReviewState),
		strings.TrimSpace(change.ChangedArtifact),
	}, "|")
	sum := sha256.Sum256([]byte(raw))
	return "adc-" + hex.EncodeToString(sum[:6])
}

func hasAgenticHighStakesPreset(path ActionPath, presets ...string) bool {
	set := map[string]struct{}{}
	for _, preset := range presets {
		trimmed := strings.TrimSpace(preset)
		if trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	for _, preset := range path.HighStakesPresets {
		if _, ok := set[strings.TrimSpace(preset.Preset)]; ok {
			return true
		}
	}
	return false
}

func boundedStrings(values []string, limit int) []string {
	out := dedupeSortedStrings(values)
	if limit <= 0 || len(out) <= limit {
		return out
	}
	return append([]string(nil), out[:limit]...)
}

func agenticDeliverySystemChangeRank(change *AgenticDeliverySystemChange) int {
	if change == nil {
		return 0
	}
	score := 0
	if change.HighImpact {
		score += 20
	}
	switch strings.TrimSpace(change.AuthorityImpact) {
	case AgenticAuthorityImpactProduction:
		score += 10
	case AgenticAuthorityImpactReviewBypass:
		score += 9
	case AgenticAuthorityImpactRelease:
		score += 8
	case AgenticAuthorityImpactCredential:
		score += 7
	case AgenticAuthorityImpactWriteScope:
		score += 5
	case AgenticAuthorityImpactReview:
		score += 3
	}
	switch strings.TrimSpace(change.ReviewState) {
	case AgenticReviewStateBypassRisk:
		score += 4
	case AgenticReviewStateMissing:
		score += 3
	case AgenticReviewStatePartial:
		score += 2
	case AgenticReviewStateProtected:
		score += 1
	}
	score += len(boundedStrings(change.ReachableTools, 3))
	return score
}

func AddReachabilityToAgenticChange(change *AgenticDeliverySystemChange, reachableTools []string, reachableTargets []string) *AgenticDeliverySystemChange {
	if change == nil {
		return nil
	}
	copyChange := CloneAgenticDeliverySystemChange(change)
	copyChange.ReachableTools = boundedStrings(append(copyChange.ReachableTools, reachableTools...), 5)
	copyChange.ReachableTargets = boundedStrings(append(copyChange.ReachableTargets, reachableTargets...), 5)
	return copyChange
}
