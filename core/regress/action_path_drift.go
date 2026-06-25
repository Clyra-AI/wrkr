package regress

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

const (
	DriftCategoryNewWritePaths           = "new_write_paths"
	DriftCategoryNewDeployPaths          = "new_deploy_paths"
	DriftCategoryNewCredentials          = "new_credentials"
	DriftCategoryNewUnknownApproval      = "new_unknown_approval_evidence"
	DriftCategoryResolvedGaps            = "resolved_gaps"
	DriftCategoryWorsenedPaths           = "worsened_paths"
	DriftCategoryNewContradictions       = "new_contradictions"
	DriftCategoryPathsReadyForControl    = "paths_ready_for_control"
	DriftCategoryRemovedPaths            = "removed_paths"
	DriftCategoryChangedAuthority        = "changed_authority"
	DriftCategoryChangedEvidence         = "changed_evidence"
	DriftCategoryChangedTargetClass      = "changed_target_class"
	DriftComparisonStatusOK              = "ok"
	DriftComparisonStatusBaselineMissing = "baseline_action_paths_unavailable"
	DriftComparisonStatusCurrentMissing  = "current_action_paths_unavailable"
	DriftComparisonStatusIncomplete      = "comparison_incomplete"
	driftExampleLimit                    = 5
)

type ActionPathState struct {
	PathID                       string   `json:"path_id,omitempty"`
	ResolutionKey                string   `json:"resolution_key,omitempty"`
	MatchKey                     string   `json:"match_key,omitempty"`
	Platform                     string   `json:"platform,omitempty"`
	Org                          string   `json:"org"`
	Repo                         string   `json:"repo"`
	Location                     string   `json:"location,omitempty"`
	ToolType                     string   `json:"tool_type,omitempty"`
	ActionPathType               string   `json:"action_path_type,omitempty"`
	TargetClass                  string   `json:"target_class,omitempty"`
	BoundaryLabel                string   `json:"boundary_label,omitempty"`
	ControlResolutionState       string   `json:"control_resolution_state,omitempty"`
	ReviewLifecycleState         string   `json:"review_lifecycle_state,omitempty"`
	PreviousReviewLifecycleState string   `json:"previous_review_lifecycle_state,omitempty"`
	ResolvedVisibility           string   `json:"resolved_visibility,omitempty"`
	ReopenState                  string   `json:"reopen_state,omitempty"`
	DelegationReadinessState     string   `json:"delegation_readiness_state,omitempty"`
	ApprovalEvidenceState        string   `json:"approval_evidence_state,omitempty"`
	OwnerEvidenceState           string   `json:"owner_evidence_state,omitempty"`
	ProofEvidenceState           string   `json:"proof_evidence_state,omitempty"`
	RuntimeEvidenceState         string   `json:"runtime_evidence_state,omitempty"`
	TargetEvidenceState          string   `json:"target_evidence_state,omitempty"`
	CredentialEvidenceState      string   `json:"credential_evidence_state,omitempty"`
	WriteCapable                 bool     `json:"write_capable,omitempty"`
	DeployWrite                  bool     `json:"deploy_write,omitempty"`
	ProductionWrite              bool     `json:"production_write,omitempty"`
	CredentialAccess             bool     `json:"credential_access,omitempty"`
	ApprovalGap                  bool     `json:"approval_gap,omitempty"`
	RiskScore                    float64  `json:"risk_score,omitempty"`
	ContradictionCount           int      `json:"contradiction_count,omitempty"`
	ActionClasses                []string `json:"action_classes,omitempty"`
	WritePathClasses             []string `json:"write_path_classes,omitempty"`
	AuthorityBindings            []string `json:"authority_bindings,omitempty"`
	CredentialSubjects           []string `json:"credential_subjects,omitempty"`
	CredentialAuthority          string   `json:"credential_authority,omitempty"`
	ReviewScope                  string   `json:"review_scope,omitempty"`
	ReviewValidUntil             string   `json:"review_valid_until,omitempty"`
	ConfigFingerprint            string   `json:"config_fingerprint,omitempty"`
	EvidenceRefs                 []string `json:"evidence_refs,omitempty"`
	ReopenReasons                []string `json:"reopen_reasons,omitempty"`
}

type DriftCategorySummary struct {
	Category               string         `json:"category"`
	Severity               string         `json:"severity"`
	Priority               string         `json:"priority"`
	Count                  int            `json:"count"`
	AffectedPathRefs       []string       `json:"affected_path_refs,omitempty"`
	EvidenceRefs           []string       `json:"evidence_refs,omitempty"`
	RecommendedNextActions []string       `json:"recommended_next_actions,omitempty"`
	Examples               []DriftExample `json:"examples,omitempty"`
}

type DriftExample struct {
	PathID                       string   `json:"path_id,omitempty"`
	BaselinePathID               string   `json:"baseline_path_id,omitempty"`
	CurrentPathRef               string   `json:"current_path_ref,omitempty"`
	BaselinePathRef              string   `json:"baseline_path_ref,omitempty"`
	Repo                         string   `json:"repo,omitempty"`
	Location                     string   `json:"location,omitempty"`
	BaselineLocation             string   `json:"baseline_location,omitempty"`
	CurrentTargetClass           string   `json:"current_target_class,omitempty"`
	BaselineTargetClass          string   `json:"baseline_target_class,omitempty"`
	CurrentBoundaryLabel         string   `json:"current_boundary_label,omitempty"`
	BaselineBoundaryLabel        string   `json:"baseline_boundary_label,omitempty"`
	CurrentAuthoritySummary      []string `json:"current_authority_summary,omitempty"`
	BaselineAuthoritySummary     []string `json:"baseline_authority_summary,omitempty"`
	CurrentEvidenceSummary       []string `json:"current_evidence_summary,omitempty"`
	BaselineEvidenceSummary      []string `json:"baseline_evidence_summary,omitempty"`
	CurrentEvidenceRefs          []string `json:"current_evidence_refs,omitempty"`
	BaselineEvidenceRefs         []string `json:"baseline_evidence_refs,omitempty"`
	CurrentReviewLifecycleState  string   `json:"current_review_lifecycle_state,omitempty"`
	BaselineReviewLifecycleState string   `json:"baseline_review_lifecycle_state,omitempty"`
	ReopenState                  string   `json:"reopen_state,omitempty"`
	ReopenReasons                []string `json:"reopen_reasons,omitempty"`
	Detail                       string   `json:"detail"`
	RecommendedNextAction        string   `json:"recommended_next_action,omitempty"`
}

type actionPathPair struct {
	Baseline ActionPathState
	Current  ActionPathState
}

type driftBucket struct {
	category        string
	severity        string
	priority        string
	recommended     []string
	count           int
	affectedPathSet map[string]struct{}
	evidenceRefSet  map[string]struct{}
	exampleKeys     map[string]struct{}
	examples        []DriftExample
}

type categoryMetadata struct {
	category    string
	severity    string
	priority    string
	recommended []string
}

var driftCategoryPlanOrder = []categoryMetadata{
	{
		category: DriftCategoryNewWritePaths,
		severity: "high",
		priority: "P0",
		recommended: []string{
			"Review the new write-capable path before it is treated as business-as-usual automation.",
			"Attach owner, approval, and proof evidence or reduce the path's write reach.",
		},
	},
	{
		category: DriftCategoryNewDeployPaths,
		severity: "high",
		priority: "P0",
		recommended: []string{
			"Treat newly observed deploy authority as release-blocking drift until owner and approval evidence are attached.",
			"Confirm production-target scope, credential mode, and rollback expectations for the new deploy path.",
		},
	},
	{
		category: DriftCategoryNewCredentials,
		severity: "high",
		priority: "P0",
		recommended: []string{
			"Review newly introduced credential-bearing authority and prefer JIT or brokered credentials where possible.",
			"Document the governing owner and boundary before expanding runtime use of the path.",
		},
	},
	{
		category: DriftCategoryNewUnknownApproval,
		severity: "high",
		priority: "P0",
		recommended: []string{
			"Recover explicit approval evidence for the exact workflow, environment, or release target.",
			"Keep the path in review until approval evidence is restored in a buyer-safe way.",
		},
	},
	{
		category: DriftCategoryResolvedGaps,
		severity: "low",
		priority: "P2",
		recommended: []string{
			"Preserve the newly improved evidence links in the baseline after validation.",
			"Use the resolved gap to tighten future drift-review expectations.",
		},
	},
	{
		category: DriftCategoryWorsenedPaths,
		severity: "high",
		priority: "P0",
		recommended: []string{
			"Prioritize the worsened path in the next control or remediation cycle.",
			"Capture what changed in authority, proof, or evidence before allowing wider rollout.",
		},
	},
	{
		category: DriftCategoryNewContradictions,
		severity: "high",
		priority: "P0",
		recommended: []string{
			"Resolve contradictory evidence before treating the path as approval-capable or control-ready.",
			"Choose one source of truth and update linked evidence refs to match.",
		},
	},
	{
		category: DriftCategoryPathsReadyForControl,
		severity: "medium",
		priority: "P1",
		recommended: []string{
			"Review paths that became control-ready and decide whether to formalize them in a control workflow.",
			"Do not imply enforcement unless the path boundary is explicitly enforcement-capable.",
		},
	},
	{
		category: DriftCategoryRemovedPaths,
		severity: "medium",
		priority: "P1",
		recommended: []string{
			"Verify whether the removed path was intentionally retired or whether scan coverage changed.",
			"Regenerate the baseline after confirming the removal is expected.",
		},
	},
	{
		category: DriftCategoryChangedAuthority,
		severity: "medium",
		priority: "P1",
		recommended: []string{
			"Review changed authority scope, provider, or credential subject before relying on historical approvals.",
			"Update ownership and approval evidence when authority semantics change.",
		},
	},
	{
		category: DriftCategoryChangedEvidence,
		severity: "medium",
		priority: "P1",
		recommended: []string{
			"Review evidence movement to confirm the report still matches what Wrkr can claim.",
			"Refresh the baseline only after validating the evidence-state change.",
		},
	},
	{
		category: DriftCategoryChangedTargetClass,
		severity: "medium",
		priority: "P1",
		recommended: []string{
			"Review target-class movement because buyer-facing severity and workflow ordering may change.",
			"Confirm the new class reflects the path's real deploy, release, or customer impact.",
		},
	},
}

func snapshotActionPathStates(snapshot state.Snapshot) ([]ActionPathState, bool) {
	paths, ok := snapshotComparableActionPaths(snapshot)
	if !ok {
		return nil, false
	}
	states := make([]ActionPathState, 0, len(paths))
	for _, path := range paths {
		states = append(states, newActionPathState(path))
	}
	sortActionPathStates(states)
	return states, true
}

func snapshotComparableActionPaths(snapshot state.Snapshot) ([]risk.ActionPath, bool) {
	if snapshot.RiskReport != nil {
		if len(snapshot.RiskReport.ActionPaths) > 0 {
			return append([]risk.ActionPath(nil), snapshot.RiskReport.ActionPaths...), true
		}
		if snapshot.Inventory != nil {
			paths, _ := risk.BuildActionPaths(snapshot.RiskReport.AttackPaths, snapshot.Inventory)
			return paths, true
		}
		// Older saved states can carry a risk report while omitting comparable
		// action-path material entirely. Treat that as unavailable so drift
		// review fails closed instead of comparing against a synthetic empty set.
		return nil, false
	}
	if snapshot.Inventory != nil {
		paths, _ := risk.BuildActionPaths(nil, snapshot.Inventory)
		return paths, true
	}
	return nil, false
}

func newActionPathState(path risk.ActionPath) ActionPathState {
	if strings.TrimSpace(path.ResolutionKey) == "" {
		path.ResolutionKey = risk.ProjectActionPath(path).ResolutionKey
	}
	out := normalizeActionPathState(ActionPathState{
		PathID:                       strings.TrimSpace(path.PathID),
		ResolutionKey:                strings.TrimSpace(path.ResolutionKey),
		Platform:                     actionPathPlatform(path),
		Org:                          fallback(strings.TrimSpace(path.Org), "local"),
		Repo:                         strings.TrimSpace(path.Repo),
		Location:                     strings.TrimSpace(path.Location),
		ToolType:                     strings.TrimSpace(path.ToolType),
		ActionPathType:               strings.TrimSpace(path.ActionPathType),
		TargetClass:                  strings.TrimSpace(path.TargetClass),
		BoundaryLabel:                strings.TrimSpace(path.BoundaryLabel),
		ControlResolutionState:       strings.TrimSpace(path.ControlResolutionState),
		ReviewLifecycleState:         strings.TrimSpace(path.ReviewLifecycleState),
		PreviousReviewLifecycleState: strings.TrimSpace(path.PreviousReviewLifecycleState),
		ResolvedVisibility:           strings.TrimSpace(path.ResolvedVisibility),
		ReopenState:                  strings.TrimSpace(path.ReopenState),
		DelegationReadinessState:     strings.TrimSpace(path.DelegationReadinessState),
		ApprovalEvidenceState:        strings.TrimSpace(path.ApprovalEvidenceState),
		OwnerEvidenceState:           strings.TrimSpace(path.OwnerEvidenceState),
		ProofEvidenceState:           strings.TrimSpace(path.ProofEvidenceState),
		RuntimeEvidenceState:         strings.TrimSpace(path.RuntimeEvidenceState),
		TargetEvidenceState:          strings.TrimSpace(path.TargetEvidenceState),
		CredentialEvidenceState:      strings.TrimSpace(path.CredentialEvidenceState),
		WriteCapable:                 path.WriteCapable,
		DeployWrite:                  path.DeployWrite,
		ProductionWrite:              path.ProductionWrite,
		CredentialAccess:             path.CredentialAccess,
		ApprovalGap:                  path.ApprovalGap,
		RiskScore:                    round2(path.RiskScore),
		ContradictionCount:           len(path.Contradictions),
		ActionClasses:                mergeSortedStrings(path.ActionClasses, nil),
		WritePathClasses:             mergeSortedStrings(path.WritePathClasses, nil),
		AuthorityBindings:            actionPathAuthorityBindings(path),
		CredentialSubjects:           actionPathCredentialSubjects(path),
		CredentialAuthority:          actionPathCredentialAuthority(path),
		ReviewScope:                  strings.TrimSpace(path.ReviewScope),
		ReviewValidUntil:             strings.TrimSpace(path.ReviewValidUntil),
		ConfigFingerprint:            strings.TrimSpace(path.ConfigFingerprint),
		EvidenceRefs:                 mergeSortedStrings(append(append(append(append([]string(nil), path.SourceFindingKeys...), path.AttackPathRefs...), append(path.ControlEvidenceRefs, path.ReopenEvidenceRefs...)...), reviewAuditEvidenceRefs(path.ReviewAuditContext)...), nil),
		ReopenReasons:                mergeSortedStrings(path.ReopenReasons, nil),
	})
	out.MatchKey = actionPathFallbackMatchKey(out)
	return out
}

func normalizeActionPathState(in ActionPathState) ActionPathState {
	in.PathID = strings.TrimSpace(in.PathID)
	in.ResolutionKey = strings.TrimSpace(in.ResolutionKey)
	in.MatchKey = strings.TrimSpace(in.MatchKey)
	in.Platform = strings.TrimSpace(in.Platform)
	in.Org = fallback(strings.TrimSpace(in.Org), "local")
	in.Repo = strings.TrimSpace(in.Repo)
	in.Location = strings.TrimSpace(in.Location)
	in.ToolType = strings.TrimSpace(in.ToolType)
	in.ActionPathType = strings.TrimSpace(in.ActionPathType)
	in.TargetClass = strings.TrimSpace(in.TargetClass)
	in.BoundaryLabel = strings.TrimSpace(in.BoundaryLabel)
	in.ControlResolutionState = strings.TrimSpace(in.ControlResolutionState)
	in.ReviewLifecycleState = strings.TrimSpace(in.ReviewLifecycleState)
	in.PreviousReviewLifecycleState = strings.TrimSpace(in.PreviousReviewLifecycleState)
	in.ResolvedVisibility = strings.TrimSpace(in.ResolvedVisibility)
	in.ReopenState = strings.TrimSpace(in.ReopenState)
	in.DelegationReadinessState = strings.TrimSpace(in.DelegationReadinessState)
	in.ApprovalEvidenceState = strings.TrimSpace(in.ApprovalEvidenceState)
	in.OwnerEvidenceState = strings.TrimSpace(in.OwnerEvidenceState)
	in.ProofEvidenceState = strings.TrimSpace(in.ProofEvidenceState)
	in.RuntimeEvidenceState = strings.TrimSpace(in.RuntimeEvidenceState)
	in.TargetEvidenceState = strings.TrimSpace(in.TargetEvidenceState)
	in.CredentialEvidenceState = strings.TrimSpace(in.CredentialEvidenceState)
	in.ActionClasses = mergeSortedStrings(in.ActionClasses, nil)
	in.WritePathClasses = mergeSortedStrings(in.WritePathClasses, nil)
	in.AuthorityBindings = mergeSortedStrings(in.AuthorityBindings, nil)
	in.CredentialSubjects = mergeSortedStrings(in.CredentialSubjects, nil)
	in.CredentialAuthority = strings.TrimSpace(in.CredentialAuthority)
	in.ReviewScope = strings.TrimSpace(in.ReviewScope)
	in.ReviewValidUntil = strings.TrimSpace(in.ReviewValidUntil)
	in.ConfigFingerprint = strings.TrimSpace(in.ConfigFingerprint)
	in.EvidenceRefs = mergeSortedStrings(in.EvidenceRefs, nil)
	in.ReopenReasons = mergeSortedStrings(in.ReopenReasons, nil)
	if in.MatchKey == "" {
		in.MatchKey = actionPathFallbackMatchKey(in)
	}
	return in
}

func sortActionPathStates(values []ActionPathState) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].PathID != values[j].PathID {
			return values[i].PathID < values[j].PathID
		}
		if values[i].ResolutionKey != values[j].ResolutionKey {
			return values[i].ResolutionKey < values[j].ResolutionKey
		}
		if values[i].MatchKey != values[j].MatchKey {
			return values[i].MatchKey < values[j].MatchKey
		}
		if values[i].Repo != values[j].Repo {
			return values[i].Repo < values[j].Repo
		}
		return values[i].Location < values[j].Location
	})
}

func compareActionPathDrift(baseline Baseline, current state.Snapshot) ([]DriftCategorySummary, string, []string) {
	currentStates, currentCaptured := snapshotActionPathStates(current)
	if !baseline.ActionPathsCaptured {
		if !currentCaptured || strings.TrimSpace(baseline.GeneratedAt) == "" {
			return nil, "", nil
		}
		return nil, DriftComparisonStatusBaselineMissing, []string{
			"baseline action-path comparison data is unavailable; regenerate the regress baseline from a current Wrkr scan snapshot",
		}
	}
	if !currentCaptured {
		return nil, DriftComparisonStatusCurrentMissing, []string{
			"current scan state does not carry comparable action-path data; rerun scan before drift review",
		}
	}

	baseStates := make([]ActionPathState, 0, len(baseline.ActionPaths))
	for _, item := range baseline.ActionPaths {
		baseStates = append(baseStates, normalizeActionPathState(item))
	}
	sortActionPathStates(baseStates)

	pairs, unmatchedCurrent, unmatchedBaseline, issues := matchActionPathStates(baseStates, currentStates)
	buckets := makeDriftBuckets()
	for _, currentState := range unmatchedCurrent {
		if isDeployPathState(currentState) {
			addDriftCategoryExample(buckets[DriftCategoryNewDeployPaths], currentState, ActionPathState{}, "new deploy-capable path appeared since baseline")
		} else if isWritePathState(currentState) {
			addDriftCategoryExample(buckets[DriftCategoryNewWritePaths], currentState, ActionPathState{}, "new write-capable path appeared since baseline")
		}
		if currentState.CredentialAccess {
			addDriftCategoryExample(buckets[DriftCategoryNewCredentials], currentState, ActionPathState{}, "new credential-bearing path appeared since baseline")
		}
	}
	for _, baselineState := range unmatchedBaseline {
		addDriftCategoryExample(buckets[DriftCategoryRemovedPaths], ActionPathState{}, baselineState, "baseline path is no longer present in the current scan")
	}
	for _, pair := range pairs {
		addMatchedDriftExamples(buckets, pair)
	}

	status := DriftComparisonStatusOK
	if len(issues) > 0 {
		status = DriftComparisonStatusIncomplete
	}
	return finalizeDriftBuckets(buckets), status, uniqueSortedStrings(issues)
}

func matchActionPathStates(baseline []ActionPathState, current []ActionPathState) ([]actionPathPair, []ActionPathState, []ActionPathState, []string) {
	issues := []string{}
	pairs := []actionPathPair{}
	baselineMatched := make([]bool, len(baseline))
	currentMatched := make([]bool, len(current))

	baseByPathID := map[string]int{}
	for idx, item := range baseline {
		if item.PathID == "" {
			continue
		}
		if _, exists := baseByPathID[item.PathID]; exists {
			issues = append(issues, "duplicate baseline path_id:"+item.PathID)
			continue
		}
		baseByPathID[item.PathID] = idx
	}

	for idx, item := range current {
		if item.PathID == "" {
			continue
		}
		if baseIdx, exists := baseByPathID[item.PathID]; exists && !baselineMatched[baseIdx] {
			baselineMatched[baseIdx] = true
			currentMatched[idx] = true
			pairs = append(pairs, actionPathPair{Baseline: baseline[baseIdx], Current: item})
		}
	}

	baseByResolutionKey := map[string]int{}
	for idx, item := range baseline {
		if baselineMatched[idx] {
			continue
		}
		if item.ResolutionKey == "" {
			continue
		}
		if _, exists := baseByResolutionKey[item.ResolutionKey]; exists {
			issues = append(issues, "duplicate baseline resolution_key:"+item.ResolutionKey)
			continue
		}
		baseByResolutionKey[item.ResolutionKey] = idx
	}

	for idx, item := range current {
		if currentMatched[idx] {
			continue
		}
		if item.ResolutionKey == "" {
			continue
		}
		if baseIdx, exists := baseByResolutionKey[item.ResolutionKey]; exists && !baselineMatched[baseIdx] {
			baselineMatched[baseIdx] = true
			currentMatched[idx] = true
			pairs = append(pairs, actionPathPair{Baseline: baseline[baseIdx], Current: item})
		}
	}

	baseByMatchKey := map[string]int{}
	for idx, item := range baseline {
		if baselineMatched[idx] {
			continue
		}
		if strings.TrimSpace(item.MatchKey) == "" {
			issues = append(issues, "baseline path missing normalized comparison key:"+firstPathIdentity(item))
			continue
		}
		if _, exists := baseByMatchKey[item.MatchKey]; exists {
			issues = append(issues, "duplicate baseline normalized comparison key:"+item.MatchKey)
			continue
		}
		baseByMatchKey[item.MatchKey] = idx
	}

	for idx, item := range current {
		if currentMatched[idx] {
			continue
		}
		if strings.TrimSpace(item.MatchKey) == "" {
			issues = append(issues, "current path missing normalized comparison key:"+firstPathIdentity(item))
			continue
		}
		if baseIdx, exists := baseByMatchKey[item.MatchKey]; exists && !baselineMatched[baseIdx] {
			baselineMatched[baseIdx] = true
			currentMatched[idx] = true
			pairs = append(pairs, actionPathPair{Baseline: baseline[baseIdx], Current: item})
		}
	}

	unmatchedCurrent := []ActionPathState{}
	for idx, item := range current {
		if !currentMatched[idx] {
			unmatchedCurrent = append(unmatchedCurrent, item)
		}
	}
	unmatchedBaseline := []ActionPathState{}
	for idx, item := range baseline {
		if !baselineMatched[idx] {
			unmatchedBaseline = append(unmatchedBaseline, item)
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Current.PathID != pairs[j].Current.PathID {
			return pairs[i].Current.PathID < pairs[j].Current.PathID
		}
		if pairs[i].Current.ResolutionKey != pairs[j].Current.ResolutionKey {
			return pairs[i].Current.ResolutionKey < pairs[j].Current.ResolutionKey
		}
		if pairs[i].Current.MatchKey != pairs[j].Current.MatchKey {
			return pairs[i].Current.MatchKey < pairs[j].Current.MatchKey
		}
		return pairs[i].Current.Repo < pairs[j].Current.Repo
	})
	sortActionPathStates(unmatchedCurrent)
	sortActionPathStates(unmatchedBaseline)
	return pairs, unmatchedCurrent, unmatchedBaseline, uniqueSortedStrings(issues)
}

func makeDriftBuckets() map[string]*driftBucket {
	out := map[string]*driftBucket{}
	for _, item := range driftCategoryPlanOrder {
		out[item.category] = &driftBucket{
			category:        item.category,
			severity:        item.severity,
			priority:        item.priority,
			recommended:     append([]string(nil), item.recommended...),
			affectedPathSet: map[string]struct{}{},
			evidenceRefSet:  map[string]struct{}{},
			exampleKeys:     map[string]struct{}{},
		}
	}
	return out
}

func addMatchedDriftExamples(buckets map[string]*driftBucket, pair actionPathPair) {
	if pair.Baseline.TargetClass != pair.Current.TargetClass {
		addDriftCategoryExample(buckets[DriftCategoryChangedTargetClass], pair.Current, pair.Baseline, "target classification changed since baseline")
	}
	if newCredentialAuthority(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryNewCredentials], pair.Current, pair.Baseline, "credential-bearing authority widened since baseline")
	} else if authorityChanged(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryChangedAuthority], pair.Current, pair.Baseline, "authority bindings changed since baseline")
	}
	if approvalEvidenceBecameUnknown(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryNewUnknownApproval], pair.Current, pair.Baseline, "approval evidence moved to unknown since baseline")
	}
	if contradictionsIntroduced(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryNewContradictions], pair.Current, pair.Baseline, "contradictory evidence is now attached to the path")
	}
	if pathReadyForControl(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryPathsReadyForControl], pair.Current, pair.Baseline, "path is now ready for control review")
	}
	if pathWorsened(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryWorsenedPaths], pair.Current, pair.Baseline, "risk or evidence posture worsened since baseline")
	} else if pathResolvedGap(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryResolvedGaps], pair.Current, pair.Baseline, "evidence or control gaps improved since baseline")
	} else if evidenceChanged(pair.Baseline, pair.Current) {
		addDriftCategoryExample(buckets[DriftCategoryChangedEvidence], pair.Current, pair.Baseline, "evidence state changed since baseline")
	}
}

func finalizeDriftBuckets(buckets map[string]*driftBucket) []DriftCategorySummary {
	out := make([]DriftCategorySummary, 0, len(buckets))
	for _, item := range driftCategoryPlanOrder {
		bucket := buckets[item.category]
		if bucket == nil || bucket.count == 0 {
			continue
		}
		out = append(out, DriftCategorySummary{
			Category:               bucket.category,
			Severity:               bucket.severity,
			Priority:               bucket.priority,
			Count:                  bucket.count,
			AffectedPathRefs:       mapKeysSorted(bucket.affectedPathSet),
			EvidenceRefs:           mapKeysSorted(bucket.evidenceRefSet),
			RecommendedNextActions: append([]string(nil), bucket.recommended...),
			Examples:               append([]DriftExample(nil), bucket.examples...),
		})
	}
	return out
}

func addDriftCategoryExample(bucket *driftBucket, current ActionPathState, baseline ActionPathState, detail string) {
	if bucket == nil {
		return
	}
	exampleKey := strings.Join([]string{bucket.category, current.PathID, baseline.PathID, current.MatchKey, baseline.MatchKey}, "|")
	if _, exists := bucket.exampleKeys[exampleKey]; exists {
		return
	}
	bucket.exampleKeys[exampleKey] = struct{}{}
	bucket.count++

	if currentRef := driftPathRef("current", current); currentRef != "" {
		bucket.affectedPathSet[currentRef] = struct{}{}
	}
	if baselineRef := driftPathRef("baseline", baseline); baselineRef != "" {
		bucket.affectedPathSet[baselineRef] = struct{}{}
	}
	for _, ref := range current.EvidenceRefs {
		if strings.TrimSpace(ref) != "" {
			bucket.evidenceRefSet[ref] = struct{}{}
		}
	}
	for _, ref := range baseline.EvidenceRefs {
		if strings.TrimSpace(ref) != "" {
			bucket.evidenceRefSet[ref] = struct{}{}
		}
	}

	if len(bucket.examples) >= driftExampleLimit {
		return
	}
	bucket.examples = append(bucket.examples, DriftExample{
		PathID:                       current.PathID,
		BaselinePathID:               baseline.PathID,
		CurrentPathRef:               driftPathRef("current", current),
		BaselinePathRef:              driftPathRef("baseline", baseline),
		Repo:                         firstNonEmptyString(current.Repo, baseline.Repo),
		Location:                     current.Location,
		BaselineLocation:             baseline.Location,
		CurrentTargetClass:           current.TargetClass,
		BaselineTargetClass:          baseline.TargetClass,
		CurrentBoundaryLabel:         current.BoundaryLabel,
		BaselineBoundaryLabel:        baseline.BoundaryLabel,
		CurrentAuthoritySummary:      actionPathAuthoritySummary(current),
		BaselineAuthoritySummary:     actionPathAuthoritySummary(baseline),
		CurrentEvidenceSummary:       actionPathEvidenceSummary(current),
		BaselineEvidenceSummary:      actionPathEvidenceSummary(baseline),
		CurrentEvidenceRefs:          append([]string(nil), current.EvidenceRefs...),
		BaselineEvidenceRefs:         append([]string(nil), baseline.EvidenceRefs...),
		CurrentReviewLifecycleState:  strings.TrimSpace(current.ReviewLifecycleState),
		BaselineReviewLifecycleState: strings.TrimSpace(baseline.ReviewLifecycleState),
		ReopenState:                  strings.TrimSpace(current.ReopenState),
		ReopenReasons:                append([]string(nil), current.ReopenReasons...),
		Detail:                       detail,
		RecommendedNextAction:        firstCategoryAction(bucket.recommended),
	})
}

func actionPathPlatform(path risk.ActionPath) string {
	location := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path.Location), "\\", "/"))
	switch {
	case strings.HasPrefix(location, ".github/workflows/"), strings.Contains(location, "/.github/workflows/"):
		return "github_actions"
	case strings.HasSuffix(location, ".gitlab-ci.yml"), strings.HasSuffix(location, ".gitlab-ci.yaml"), strings.HasPrefix(location, ".gitlab/ci/"), strings.Contains(location, "/.gitlab/ci/"):
		return "gitlab_ci"
	case strings.HasSuffix(location, "azure-pipelines.yml"), strings.HasSuffix(location, "azure-pipelines.yaml"), strings.HasPrefix(location, ".azure/pipelines/"), strings.Contains(location, "/.azure/pipelines/"):
		return "azure_devops"
	case strings.HasSuffix(location, "jenkinsfile"), strings.Contains(location, "/jenkinsfile"):
		return "jenkins"
	default:
		return strings.TrimSpace(path.ActionPathType)
	}
}

func actionPathAuthorityBindings(path risk.ActionPath) []string {
	out := []string{}
	for _, item := range path.AuthorityBindings {
		if item == nil {
			continue
		}
		out = append(out, strings.Join([]string{
			strings.TrimSpace(item.Kind),
			strings.TrimSpace(item.Provider),
			strings.TrimSpace(item.TargetSystem),
			strings.TrimSpace(item.Subject),
			strings.TrimSpace(item.Resource),
		}, "|"))
	}
	return mergeSortedStrings(out, nil)
}

func actionPathCredentialSubjects(path risk.ActionPath) []string {
	out := []string{}
	for _, item := range path.Credentials {
		if item == nil {
			continue
		}
		if subject := strings.TrimSpace(item.Subject); subject != "" {
			out = append(out, subject)
		}
	}
	if path.CredentialProvenance != nil {
		if subject := strings.TrimSpace(path.CredentialProvenance.Subject); subject != "" {
			out = append(out, subject)
		}
	}
	return mergeSortedStrings(out, nil)
}

func actionPathCredentialAuthority(path risk.ActionPath) string {
	if path.CredentialAuthority == nil {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(path.CredentialAuthority.CredentialKind),
		strings.TrimSpace(path.CredentialAuthority.AccessType),
		strings.TrimSpace(path.CredentialAuthority.CredentialSource),
		strings.TrimSpace(path.CredentialAuthority.TargetSystem),
		strings.TrimSpace(path.CredentialAuthority.LikelyScope),
	}, "|")
}

func actionPathFallbackMatchKey(path ActionPathState) string {
	parts := []string{
		strings.TrimSpace(path.Platform),
		fallback(strings.TrimSpace(path.Org), "local"),
		strings.TrimSpace(path.Repo),
		strings.TrimSpace(path.Location),
		strings.TrimSpace(path.ActionPathType),
		strings.TrimSpace(path.TargetClass),
		strings.Join(path.ActionClasses, ","),
		strings.Join(path.CredentialSubjects, ","),
		strings.TrimSpace(path.BoundaryLabel),
		strings.TrimSpace(path.ConfigFingerprint),
		actionPathEvidenceSignature(path),
	}
	return strings.Trim(strings.Join(parts, "|"), "|")
}

func actionPathEvidenceSignature(path ActionPathState) string {
	return strings.Join([]string{
		strings.TrimSpace(path.ControlResolutionState),
		strings.TrimSpace(path.ReviewLifecycleState),
		strings.TrimSpace(path.PreviousReviewLifecycleState),
		strings.TrimSpace(path.ResolvedVisibility),
		strings.TrimSpace(path.ReopenState),
		strings.Join(path.ReopenReasons, ","),
		strings.TrimSpace(path.ApprovalEvidenceState),
		strings.TrimSpace(path.OwnerEvidenceState),
		strings.TrimSpace(path.ProofEvidenceState),
		strings.TrimSpace(path.RuntimeEvidenceState),
		strings.TrimSpace(path.TargetEvidenceState),
		strings.TrimSpace(path.CredentialEvidenceState),
		strings.TrimSpace(path.ReviewScope),
		strings.TrimSpace(path.ReviewValidUntil),
		boolString(path.ApprovalGap),
	}, "|")
}

func reviewAuditEvidenceRefs(ctx *risk.ReviewAuditContext) []string {
	if ctx == nil {
		return nil
	}
	return append([]string(nil), ctx.EvidenceRefs...)
}

func actionPathAuthoritySummary(path ActionPathState) []string {
	out := []string{}
	if strings.TrimSpace(path.CredentialAuthority) != "" {
		out = append(out, "authority:"+strings.TrimSpace(path.CredentialAuthority))
	}
	for _, item := range path.AuthorityBindings {
		out = append(out, "binding:"+item)
	}
	for _, item := range path.CredentialSubjects {
		out = append(out, "subject:"+item)
	}
	return mergeSortedStrings(out, nil)
}

func actionPathEvidenceSummary(path ActionPathState) []string {
	out := []string{}
	for _, item := range []struct {
		label string
		value string
	}{
		{label: "control", value: path.ControlResolutionState},
		{label: "approval", value: path.ApprovalEvidenceState},
		{label: "owner", value: path.OwnerEvidenceState},
		{label: "proof", value: path.ProofEvidenceState},
		{label: "runtime", value: path.RuntimeEvidenceState},
		{label: "target", value: path.TargetEvidenceState},
		{label: "credential", value: path.CredentialEvidenceState},
	} {
		if strings.TrimSpace(item.value) == "" {
			continue
		}
		out = append(out, item.label+":"+strings.TrimSpace(item.value))
	}
	if path.ApprovalGap {
		out = append(out, "approval_gap:true")
	}
	return mergeSortedStrings(out, nil)
}

func isWritePathState(path ActionPathState) bool {
	if path.WriteCapable || path.ProductionWrite {
		return true
	}
	for _, item := range append(append([]string(nil), path.ActionClasses...), path.WritePathClasses...) {
		switch strings.TrimSpace(item) {
		case "write", "merge", "deploy", "release", agginventory.WritePathRepoWrite, agginventory.WritePathPullRequestWrite, agginventory.WritePathReleaseWrite, agginventory.WritePathDeployWrite, agginventory.WritePathInfraWrite, agginventory.WritePathPackagePublish:
			return true
		}
	}
	return false
}

func isDeployPathState(path ActionPathState) bool {
	if path.DeployWrite || path.ProductionWrite {
		return true
	}
	for _, item := range append(append([]string(nil), path.ActionClasses...), path.WritePathClasses...) {
		switch strings.TrimSpace(item) {
		case "deploy", "release", agginventory.WritePathDeployWrite:
			return true
		}
	}
	return false
}

func newCredentialAuthority(baseline ActionPathState, current ActionPathState) bool {
	if !current.CredentialAccess {
		return false
	}
	if !baseline.CredentialAccess {
		return true
	}
	if len(stringDelta(baseline.CredentialSubjects, current.CredentialSubjects)) > 0 {
		return true
	}
	if len(stringDelta(baseline.AuthorityBindings, current.AuthorityBindings)) > 0 {
		return true
	}
	return strings.TrimSpace(baseline.CredentialAuthority) == "" && strings.TrimSpace(current.CredentialAuthority) != ""
}

func authorityChanged(baseline ActionPathState, current ActionPathState) bool {
	if baseline.CredentialAccess != current.CredentialAccess {
		return true
	}
	if strings.TrimSpace(baseline.CredentialAuthority) != strings.TrimSpace(current.CredentialAuthority) {
		return true
	}
	return strings.Join(baseline.AuthorityBindings, ",") != strings.Join(current.AuthorityBindings, ",") ||
		strings.Join(baseline.CredentialSubjects, ",") != strings.Join(current.CredentialSubjects, ",")
}

func approvalEvidenceBecameUnknown(baseline ActionPathState, current ActionPathState) bool {
	return normalizeEvidenceStateValue(baseline.ApprovalEvidenceState) != risk.EvidenceStateUnknown &&
		normalizeEvidenceStateValue(current.ApprovalEvidenceState) == risk.EvidenceStateUnknown
}

func contradictionsIntroduced(baseline ActionPathState, current ActionPathState) bool {
	return baseline.ContradictionCount == 0 && current.ContradictionCount > 0
}

func pathReadyForControl(baseline ActionPathState, current ActionPathState) bool {
	if strings.TrimSpace(current.DelegationReadinessState) == risk.DelegationReadinessReadyForControl &&
		strings.TrimSpace(baseline.DelegationReadinessState) != risk.DelegationReadinessReadyForControl {
		return true
	}
	return boundaryRank(current.BoundaryLabel) >= boundaryRank("approval_capable") &&
		boundaryRank(current.BoundaryLabel) > boundaryRank(baseline.BoundaryLabel)
}

func pathWorsened(baseline ActionPathState, current ActionPathState) bool {
	if round2(current.RiskScore-baseline.RiskScore) >= 1 {
		return true
	}
	if evidenceGapCount(current) > evidenceGapCount(baseline) {
		return true
	}
	if delegationReadinessRank(current.DelegationReadinessState) > delegationReadinessRank(baseline.DelegationReadinessState) {
		return true
	}
	return boundaryRank(current.BoundaryLabel) < boundaryRank(baseline.BoundaryLabel)
}

func pathResolvedGap(baseline ActionPathState, current ActionPathState) bool {
	if evidenceGapCount(current) >= evidenceGapCount(baseline) {
		return false
	}
	if strings.TrimSpace(current.DelegationReadinessState) == risk.DelegationReadinessBlockedByContradiction {
		return false
	}
	return true
}

func evidenceChanged(baseline ActionPathState, current ActionPathState) bool {
	return actionPathEvidenceSignature(baseline) != actionPathEvidenceSignature(current)
}

func evidenceGapCount(path ActionPathState) int {
	count := 0
	for _, item := range []string{
		normalizeEvidenceStateValue(path.OwnerEvidenceState),
		normalizeEvidenceStateValue(path.ApprovalEvidenceState),
		normalizeEvidenceStateValue(path.ProofEvidenceState),
		normalizeEvidenceStateValue(path.RuntimeEvidenceState),
		normalizeEvidenceStateValue(path.TargetEvidenceState),
		normalizeEvidenceStateValue(path.CredentialEvidenceState),
	} {
		switch item {
		case risk.EvidenceStateUnknown, risk.EvidenceStateContradictory:
			count++
		}
	}
	switch strings.TrimSpace(path.ControlResolutionState) {
	case risk.ControlResolutionStateNoVisibleControl, risk.ControlResolutionStateContradictoryControl:
		count++
	}
	if path.ApprovalGap {
		count++
	}
	return count
}

func normalizeEvidenceStateValue(value string) string {
	switch strings.TrimSpace(value) {
	case risk.EvidenceStateVerified,
		risk.EvidenceStateDeclared,
		risk.EvidenceStateInferred,
		risk.EvidenceStateUnknown,
		risk.EvidenceStateContradictory:
		return strings.TrimSpace(value)
	default:
		return risk.EvidenceStateUnknown
	}
}

func boundaryRank(value string) int {
	switch strings.TrimSpace(value) {
	case "enforcement_capable":
		return 4
	case "approval_capable":
		return 3
	case "report_only":
		return 2
	case "discovery_only":
		return 1
	default:
		return 0
	}
}

func delegationReadinessRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.DelegationReadinessSafeToDelegate:
		return 0
	case risk.DelegationReadinessReadyForControl:
		return 1
	case risk.DelegationReadinessReviewRequired:
		return 2
	case risk.DelegationReadinessApprovalRequired:
		return 3
	case risk.DelegationReadinessProofRequired:
		return 4
	case risk.DelegationReadinessBlocked:
		return 5
	case risk.DelegationReadinessBlockedByContradiction:
		return 6
	default:
		return 4
	}
}

func driftPathRef(kind string, path ActionPathState) string {
	if strings.TrimSpace(path.PathID) != "" {
		return strings.TrimSpace(kind) + ":" + strings.TrimSpace(path.PathID)
	}
	if strings.TrimSpace(path.ResolutionKey) != "" {
		return strings.TrimSpace(kind) + ":" + strings.TrimSpace(path.ResolutionKey)
	}
	if strings.TrimSpace(path.MatchKey) != "" {
		return strings.TrimSpace(kind) + ":" + strings.TrimSpace(path.MatchKey)
	}
	return ""
}

func firstPathIdentity(path ActionPathState) string {
	return firstNonEmptyString(path.PathID, path.ResolutionKey, path.MatchKey, path.Repo+"@"+path.Location)
}

func firstCategoryAction(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func mapKeysSorted(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		if strings.TrimSpace(key) != "" {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return mapKeysSorted(set)
}

func stringDelta(base []string, current []string) []string {
	baseSet := map[string]struct{}{}
	for _, item := range base {
		baseSet[strings.TrimSpace(item)] = struct{}{}
	}
	added := []string{}
	for _, item := range current {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := baseSet[trimmed]; exists {
			continue
		}
		added = append(added, trimmed)
	}
	return uniqueSortedStrings(added)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
