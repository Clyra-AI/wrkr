package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

const (
	ClosureSeverityCritical = "critical"
	ClosureSeverityHigh     = "high"
	ClosureSeverityMedium   = "medium"
	ClosureSeverityLow      = "low"

	ClosureRequirementAssignOwner               = "assign_owner"
	ClosureRequirementAttachApproval            = "attach_approval"
	ClosureRequirementAttachPolicyReference     = "attach_policy_reference"
	ClosureRequirementAttachProof               = "attach_proof"
	ClosureRequirementCollectRuntimeEvidence    = "collect_runtime_evidence"
	ClosureRequirementExpandScanCoverage        = "expand_scan_coverage"
	ClosureRequirementProvideProviderExport     = "provide_provider_export"
	ClosureRequirementProveDeploymentConstraint = "prove_deployment_constraint"
	ClosureRequirementProveJITCredential        = "prove_jit_credential"
	ClosureRequirementRefreshExpiredEvidence    = "refresh_expired_evidence"
	ClosureRequirementResolveContradiction      = "resolve_contradiction"
	ClosureRequirementAcceptInternalTooling     = "accept_declared_internal_tooling"

	CompletenessAxisDiscovery = "discovery"
	CompletenessAxisAuthority = "authority"
	CompletenessAxisBlast     = "blast_radius"
	CompletenessAxisControl   = "control"
	CompletenessAxisRuntime   = "runtime_evidence"
	CompletenessAxisProof     = "proof"

	EvidenceCompletenessStrong       = "strong_evidence"
	EvidenceCompletenessPartial      = "partial_evidence"
	EvidenceCompletenessInsufficient = "insufficient_evidence"
)

var completenessAxisOrder = []string{
	CompletenessAxisDiscovery,
	CompletenessAxisAuthority,
	CompletenessAxisBlast,
	CompletenessAxisControl,
	CompletenessAxisRuntime,
	CompletenessAxisProof,
}

type ClosureRequirement struct {
	ID                      string   `json:"id"`
	Severity                string   `json:"severity"`
	RequirementType         string   `json:"requirement_type"`
	CurrentEvidenceState    string   `json:"current_evidence_state,omitempty"`
	RequiredEvidence        string   `json:"required_evidence"`
	AcceptableSourceClasses []string `json:"acceptable_source_classes,omitempty"`
	FreshnessRequirement    string   `json:"freshness_requirement,omitempty"`
	Examples                []string `json:"examples,omitempty"`
	ClosureRefs             []string `json:"closure_refs,omitempty"`
	ReasonCodes             []string `json:"reason_codes,omitempty"`
	Guidance                string   `json:"guidance"`
}

type EvidenceCompletenessAxisScore struct {
	Axis    string   `json:"axis"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons,omitempty"`
}

type EvidenceCompleteness struct {
	TotalScore            int                            `json:"total_score"`
	Label                 string                         `json:"label"`
	AxisScores            []EvidenceCompletenessAxisScore `json:"axis_scores"`
	EvidenceGaps          []string                       `json:"evidence_gaps,omitempty"`
	UnsupportedSurfaces    []string                        `json:"unsupported_surfaces,omitempty"`
	FreshnessPenalties     []string                        `json:"freshness_penalties,omitempty"`
	ContradictionPenalties []string                        `json:"contradiction_penalties,omitempty"`
	Reasons                []string                        `json:"reasons,omitempty"`
}

type EvidenceCompletenessSummary struct {
	PathCount               int                            `json:"path_count"`
	AverageTotalScore       int                            `json:"average_total_score"`
	Label                   string                         `json:"label"`
	LowEvidencePathCount    int                            `json:"low_evidence_path_count,omitempty"`
	ReducedCoveragePathCount int                            `json:"reduced_coverage_path_count,omitempty"`
	AxisScores               []EvidenceCompletenessAxisScore `json:"axis_scores,omitempty"`
	Reasons                  []string                       `json:"reasons,omitempty"`
}

func DecorateEvidenceContext(paths []ActionPath, report *scanquality.Report) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]ActionPath, 0, len(paths))
	for _, raw := range paths {
		path := ProjectActionPath(raw)
		signals := scanquality.CompletenessSignalsForRepo(report, path.Org, path.Repo)
		completeness := buildEvidenceCompleteness(path, signals)
		path.EvidenceCompleteness = completeness
		path.ClosureRequirements = buildClosureRequirements(path, signals, completeness)
		out = append(out, path)
	}
	return out
}

func BuildEvidenceCompletenessSummary(paths []ActionPath) *EvidenceCompletenessSummary {
	if len(paths) == 0 {
		return nil
	}
	axisTotals := map[string]int{}
	axisReasons := map[string][]string{}
	total := 0
	lowEvidence := 0
	reducedCoverage := 0
	reasons := []string{}
	for _, raw := range paths {
		path := raw
		if path.EvidenceCompleteness == nil {
			path.EvidenceCompleteness = buildEvidenceCompleteness(path, scanquality.CompletenessSignals{})
		}
		total += path.EvidenceCompleteness.TotalScore
		if path.EvidenceCompleteness.Label == EvidenceCompletenessInsufficient {
			lowEvidence++
		}
		if len(path.EvidenceCompleteness.UnsupportedSurfaces) > 0 {
			reducedCoverage++
		}
		reasons = append(reasons, path.EvidenceCompleteness.Reasons...)
		for _, axis := range path.EvidenceCompleteness.AxisScores {
			axisTotals[axis.Axis] += axis.Score
			axisReasons[axis.Axis] = append(axisReasons[axis.Axis], axis.Reasons...)
		}
	}
	summary := &EvidenceCompletenessSummary{
		PathCount:                len(paths),
		AverageTotalScore:        int(math.Round(float64(total) / float64(len(paths)))),
		LowEvidencePathCount:     lowEvidence,
		ReducedCoveragePathCount: reducedCoverage,
		Reasons:                  dedupeSortedStrings(reasons),
	}
	summary.Label = evidenceCompletenessLabel(summary.AverageTotalScore)
	summary.AxisScores = make([]EvidenceCompletenessAxisScore, 0, len(completenessAxisOrder))
	for _, axis := range completenessAxisOrder {
		score := 0
		if len(paths) > 0 {
			score = int(math.Round(float64(axisTotals[axis]) / float64(len(paths))))
		}
		summary.AxisScores = append(summary.AxisScores, EvidenceCompletenessAxisScore{
			Axis:    axis,
			Score:   score,
			Reasons: dedupeSortedStrings(axisReasons[axis]),
		})
	}
	return summary
}

func CloneClosureRequirements(in []ClosureRequirement) []ClosureRequirement {
	if len(in) == 0 {
		return nil
	}
	out := make([]ClosureRequirement, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.AcceptableSourceClasses = append([]string(nil), item.AcceptableSourceClasses...)
		copyItem.Examples = append([]string(nil), item.Examples...)
		copyItem.ClosureRefs = append([]string(nil), item.ClosureRefs...)
		copyItem.ReasonCodes = append([]string(nil), item.ReasonCodes...)
		out = append(out, copyItem)
	}
	return out
}

func CloneEvidenceCompleteness(in *EvidenceCompleteness) *EvidenceCompleteness {
	if in == nil {
		return nil
	}
	out := *in
	out.AxisScores = cloneEvidenceCompletenessAxisScores(in.AxisScores)
	out.EvidenceGaps = append([]string(nil), in.EvidenceGaps...)
	out.UnsupportedSurfaces = append([]string(nil), in.UnsupportedSurfaces...)
	out.FreshnessPenalties = append([]string(nil), in.FreshnessPenalties...)
	out.ContradictionPenalties = append([]string(nil), in.ContradictionPenalties...)
	out.Reasons = append([]string(nil), in.Reasons...)
	return &out
}

func CloneEvidenceCompletenessSummary(in *EvidenceCompletenessSummary) *EvidenceCompletenessSummary {
	if in == nil {
		return nil
	}
	out := *in
	out.AxisScores = cloneEvidenceCompletenessAxisScores(in.AxisScores)
	out.Reasons = append([]string(nil), in.Reasons...)
	return &out
}

func cloneEvidenceCompletenessAxisScores(in []EvidenceCompletenessAxisScore) []EvidenceCompletenessAxisScore {
	if len(in) == 0 {
		return nil
	}
	out := make([]EvidenceCompletenessAxisScore, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Reasons = append([]string(nil), item.Reasons...)
		out = append(out, copyItem)
	}
	return out
}

func ClosureCriteriaText(requirements []ClosureRequirement, fallback string) string {
	if len(requirements) == 0 {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(requirements[0].Guidance)
}

func buildClosureRequirements(path ActionPath, signals scanquality.CompletenessSignals, completeness *EvidenceCompleteness) []ClosureRequirement {
	requirements := []ClosureRequirement{}
	add := func(item ClosureRequirement) {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.Guidance) == "" {
			return
		}
		item.AcceptableSourceClasses = dedupeSortedStrings(item.AcceptableSourceClasses)
		item.Examples = dedupeSortedStrings(item.Examples)
		item.ClosureRefs = dedupeSortedStrings(item.ClosureRefs)
		item.ReasonCodes = dedupeSortedStrings(item.ReasonCodes)
		requirements = append(requirements, item)
	}

	if contradictionRequirement, ok := contradictionClosureRequirement(path); ok {
		add(contradictionRequirement)
	}
	for _, freshness := range freshnessClosureRequirements(path) {
		add(freshness)
	}
	if ownerRequirement, ok := ownerClosureRequirement(path); ok {
		add(ownerRequirement)
	}
	if approvalRequirement, ok := approvalClosureRequirement(path); ok {
		add(approvalRequirement)
	}
	if proofRequirement, ok := proofClosureRequirement(path); ok {
		add(proofRequirement)
	}
	if runtimeRequirement, ok := runtimeClosureRequirement(path); ok {
		add(runtimeRequirement)
	}
	if deployRequirement, ok := deploymentConstraintClosureRequirement(path); ok {
		add(deployRequirement)
	}
	if internalRequirement, ok := internalToolingClosureRequirement(path); ok {
		add(internalRequirement)
	}
	if scanRequirement, ok := scanCoverageClosureRequirement(path, signals, completeness); ok {
		add(scanRequirement)
	}

	sort.Slice(requirements, func(i, j int) bool {
		if closureSeverityPriority(requirements[i].Severity) != closureSeverityPriority(requirements[j].Severity) {
			return closureSeverityPriority(requirements[i].Severity) < closureSeverityPriority(requirements[j].Severity)
		}
		if requirements[i].RequirementType != requirements[j].RequirementType {
			return requirements[i].RequirementType < requirements[j].RequirementType
		}
		if normalizeEvidenceState(requirements[i].CurrentEvidenceState) != normalizeEvidenceState(requirements[j].CurrentEvidenceState) {
			return normalizeEvidenceState(requirements[i].CurrentEvidenceState) < normalizeEvidenceState(requirements[j].CurrentEvidenceState)
		}
		return requirements[i].ID < requirements[j].ID
	})
	if len(requirements) == 0 {
		return nil
	}
	return requirements
}

func contradictionClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	if len(path.Contradictions) == 0 &&
		normalizeControlResolutionState(path.ControlResolutionState) != ControlResolutionStateContradictoryControl &&
		normalizeEvidenceState(path.TargetEvidenceState) != EvidenceStateContradictory &&
		normalizeEvidenceState(path.OwnerEvidenceState) != EvidenceStateContradictory &&
		normalizeEvidenceState(path.ApprovalEvidenceState) != EvidenceStateContradictory &&
		normalizeEvidenceState(path.ProofEvidenceState) != EvidenceStateContradictory &&
		normalizeEvidenceState(path.RuntimeEvidenceState) != EvidenceStateContradictory {
		return ClosureRequirement{}, false
	}
	reasonCodes := contradictionReasonCodes(path.Contradictions)
	if len(reasonCodes) == 0 {
		reasonCodes = []string{"control_evidence:contradictory"}
	}
	refs := contradictionEvidenceRefs(path.Contradictions)
	refs = dedupeSortedStrings(append(refs, path.ControlEvidenceRefs...))
	return ClosureRequirement{
		ID:                      closureRequirementID(path.PathID, ClosureRequirementResolveContradiction, EvidenceStateContradictory),
		Severity:                ClosureSeverityCritical,
		RequirementType:         ClosureRequirementResolveContradiction,
		CurrentEvidenceState:    EvidenceStateContradictory,
		RequiredEvidence:        "One authoritative owner/control decision with matching target, credential, and approval evidence for this exact path.",
		AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeRepoPolicy, evidencepolicy.SourceTypeTicketExport},
		FreshnessRequirement:    "fresh authoritative evidence required",
		Examples: []string{
			"Replace conflicting non-production declarations with one current signed declaration.",
			"Attach one owner-approved control export that matches the production-bearing path state.",
		},
		ClosureRefs: refs,
		ReasonCodes: reasonCodes,
		Guidance:    "Resolve the contradictory evidence for this path and attach one authoritative owner/control decision before treating it as governed.",
	}, true
}

func freshnessClosureRequirements(path ActionPath) []ClosureRequirement {
	out := []ClosureRequirement{}
	for _, issue := range freshnessIssuesForPath(path) {
		required := "Fresh evidence for this path with observed_at and valid_until or max_age metadata."
		guidance := "Refresh the stale evidence for this path and rescan before treating it as verified."
		severity := ClosureSeverityMedium
		if strings.Contains(issue.reason, "expired") {
			required = "Fresh replacement evidence for this path with a new validity window."
			guidance = "Refresh the expired evidence for this path and rescan before treating it as verified."
			severity = ClosureSeverityHigh
		}
		out = append(out, ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementRefreshExpiredEvidence, issue.field),
			Severity:                severity,
			RequirementType:         ClosureRequirementRefreshExpiredEvidence,
			CurrentEvidenceState:    issue.state,
			RequiredEvidence:        required,
			AcceptableSourceClasses: freshnessSourceClasses(issue.field),
			FreshnessRequirement:    "fresh evidence with current validity metadata",
			Examples:                freshnessExamples(issue.field),
			ClosureRefs:             append([]string(nil), issue.refs...),
			ReasonCodes:             []string{issue.reason},
			Guidance:                strings.ReplaceAll(guidance, "the stale evidence", strings.TrimSpace(issue.label)+" evidence"),
		})
	}
	return out
}

func ownerClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	switch normalizeEvidenceState(path.OwnerEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementAssignOwner, path.OwnerEvidenceState),
			Severity:                ownerClosureSeverity(path),
			RequirementType:         ClosureRequirementAssignOwner,
			CurrentEvidenceState:    normalizeEvidenceState(path.OwnerEvidenceState),
			RequiredEvidence:        "Explicit owner evidence for this path with a linked team, service, or approver record.",
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeCustomerOwnerMap, evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeAppCatalog, evidencepolicy.SourceTypeCodeowners},
			FreshnessRequirement:    "owner evidence should be current and reviewable",
			Examples: []string{
				"Attach a provider-exported team ownership record for the workflow or service.",
				"Declare one owner in wrkr-control-declarations.yaml with expiry and evidence refs.",
			},
			ClosureRefs: append([]string(nil), path.OwnershipEvidence...),
			ReasonCodes: []string{"owner_evidence:" + normalizeEvidenceState(path.OwnerEvidenceState)},
			Guidance:    "Assign explicit owner evidence for this path and attach a linked owner record before approving or expanding it.",
		}, true
	case EvidenceStateDeclared:
		if path.ControlPriority != ControlPriorityControlFirst {
			return ClosureRequirement{}, false
		}
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementProvideProviderExport, evidencepolicy.FieldOwner),
			Severity:                ClosureSeverityMedium,
			RequirementType:         ClosureRequirementProvideProviderExport,
			CurrentEvidenceState:    normalizeEvidenceState(path.OwnerEvidenceState),
			RequiredEvidence:        "Provider-exported or catalog-backed owner evidence for this control path.",
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeGitHubTeamExport, evidencepolicy.SourceTypeAppCatalog},
			FreshnessRequirement:    "fresh authoritative export preferred over declarations",
			Examples: []string{
				"Attach a GitHub team export or app catalog record that resolves to one owner.",
			},
			ClosureRefs: append([]string(nil), path.OwnershipEvidence...),
			ReasonCodes: []string{"owner_evidence:declared"},
			Guidance:    "Provide provider-exported owner evidence for this path if you need it to move from declared ownership toward verified ownership.",
		}, true
	default:
		return ClosureRequirement{}, false
	}
}

func approvalClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	switch normalizeEvidenceState(path.ApprovalEvidenceState) {
	case EvidenceStateUnknown, EvidenceStateInferred:
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementAttachApproval, path.ApprovalEvidenceState),
			Severity:                approvalClosureSeverity(path),
			RequirementType:         ClosureRequirementAttachApproval,
			CurrentEvidenceState:    normalizeEvidenceState(path.ApprovalEvidenceState),
			RequiredEvidence:        "Path-scoped approval evidence with owner, scope, expiry, and linked proof or ticket refs.",
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeTicketExport, evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeRepoPolicy},
			FreshnessRequirement:    "approval evidence must be current and time-bounded",
			Examples: []string{
				"Attach an approval ticket export with approver, scope, and expiry.",
				"Record a signed declaration with owner approval and a valid_until timestamp.",
			},
			ClosureRefs: append([]string(nil), path.ControlEvidenceRefs...),
			ReasonCodes: dedupeSortedStrings(append([]string{"approval_evidence:" + normalizeEvidenceState(path.ApprovalEvidenceState)}, path.ApprovalGapReasons...)),
			Guidance:    "Attach approval evidence for this exact path with scope and expiry before treating it as governed.",
		}, true
	case EvidenceStateDeclared:
		if path.ControlPriority != ControlPriorityControlFirst {
			return ClosureRequirement{}, false
		}
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementProvideProviderExport, evidencepolicy.FieldApproval),
			Severity:                ClosureSeverityMedium,
			RequirementType:         ClosureRequirementProvideProviderExport,
			CurrentEvidenceState:    normalizeEvidenceState(path.ApprovalEvidenceState),
			RequiredEvidence:        "Authoritative exported approval evidence for this control path.",
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeTicketExport},
			FreshnessRequirement:    "fresh exported approval evidence preferred over declarations",
			Examples: []string{
				"Attach a ticket or provider export that records the same approval decision.",
			},
			ClosureRefs:             append([]string(nil), path.ControlEvidenceRefs...),
			ReasonCodes:             []string{"approval_evidence:declared"},
			Guidance:                "Provide exported approval evidence for this path if you need it to move from declared approval toward verified approval.",
		}, true
	default:
		return ClosureRequirement{}, false
	}
}

func proofClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	switch {
	case strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusNone || len(path.PolicyMissingReasons) > 0:
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementAttachPolicyReference, path.PolicyCoverageStatus),
			Severity:                proofClosureSeverity(path),
			RequirementType:         ClosureRequirementAttachPolicyReference,
			CurrentEvidenceState:    normalizeEvidenceState(path.ProofEvidenceState),
			RequiredEvidence:        "Path-specific policy or proof reference that names the control bound to this path.",
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeRepoPolicy, evidencepolicy.SourceTypePolicyConfig, evidencepolicy.SourceTypeSignedDeclaration},
			FreshnessRequirement:    "policy and proof references should match the current path scope",
			Examples: []string{
				"Attach a policy export or repo policy reference for this workflow or agent config.",
				"Link a proof record that names the exact control path.",
			},
			ClosureRefs: append([]string(nil), path.PolicyEvidenceRefs...),
			ReasonCodes: dedupeSortedStrings(append([]string{"proof_evidence:none"}, path.PolicyMissingReasons...)),
			Guidance:    "Attach a path-specific policy or proof reference for this exact path and rescan so proof is no longer inferred or absent.",
		}, true
	case normalizeEvidenceState(path.ProofEvidenceState) == EvidenceStateUnknown || normalizeEvidenceState(path.ProofEvidenceState) == EvidenceStateInferred:
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, ClosureRequirementAttachProof, path.ProofEvidenceState),
			Severity:                proofClosureSeverity(path),
			RequirementType:         ClosureRequirementAttachProof,
			CurrentEvidenceState:    normalizeEvidenceState(path.ProofEvidenceState),
			RequiredEvidence:        "Path-specific proof record or export that verifies the current control claim.",
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeRuntime, evidencepolicy.SourceTypeRepoPolicy},
			FreshnessRequirement:    "proof should verify the current policy and runtime posture",
			Examples: []string{
				"Attach a proof record that references the same control_id and path_id.",
				"Provide a provider export that confirms the runtime control claim.",
			},
			ClosureRefs: append([]string(nil), path.PolicyEvidenceRefs...),
			ReasonCodes: []string{"proof_evidence:" + normalizeEvidenceState(path.ProofEvidenceState)},
			Guidance:    "Attach path-specific proof for the current control claim before treating this path as fully verified.",
		}, true
	default:
		return ClosureRequirement{}, false
	}
}

func runtimeClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	absence := RuntimeEvidenceAbsenceStatus(path)
	requirementType := ClosureRequirementCollectRuntimeEvidence
	required := "Runtime control evidence for this path with correlation back to the current path_id."
	guidance := "Collect runtime evidence for this path and correlate it back to the saved path before treating runtime claims as verified."
	examples := []string{
		"Attach a runtime evidence bundle with policy, approval, or action outcome records for this path.",
	}
	if likelyJITCredential(path) {
		requirementType = ClosureRequirementProveJITCredential
		required = "JIT credential evidence for this path that proves the credential is brokered or short-lived."
		guidance = "Provide JIT credential evidence for this path and correlate it back to the saved path before treating standing-access risk as reduced."
		examples = append(examples, "Attach a runtime record that proves the credential was issued just in time for this path.")
	}
	switch absence {
	case RuntimeEvidenceAbsenceMissingRequired, RuntimeEvidenceAbsenceMissingForClaim, RuntimeEvidenceAbsenceNotCollected:
		return ClosureRequirement{
			ID:                      closureRequirementID(path.PathID, requirementType, absence),
			Severity:                runtimeClosureSeverity(path, absence),
			RequirementType:         requirementType,
			CurrentEvidenceState:    normalizeEvidenceState(path.RuntimeEvidenceState),
			RequiredEvidence:        required,
			AcceptableSourceClasses: []string{evidencepolicy.SourceTypeRuntime, evidencepolicy.SourceTypeProviderExport},
			FreshnessRequirement:    "runtime evidence should match the current execution window",
			Examples:                examples,
			ClosureRefs:             append([]string(nil), path.ControlEvidenceRefs...),
			ReasonCodes:             []string{"runtime_absence_status:" + absence},
			Guidance:                guidance,
		}, true
	default:
		return ClosureRequirement{}, false
	}
}

func deploymentConstraintClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	if !pathNeedsDeploymentConstraintEvidence(path) {
		return ClosureRequirement{}, false
	}
	return ClosureRequirement{
		ID:                      closureRequirementID(path.PathID, ClosureRequirementProveDeploymentConstraint, path.TargetClass),
		Severity:                ClosureSeverityHigh,
		RequirementType:         ClosureRequirementProveDeploymentConstraint,
		CurrentEvidenceState:    normalizeEvidenceState(path.ProofEvidenceState),
		RequiredEvidence:        "Deterministic deployment or branch-protection constraint evidence for this path.",
		AcceptableSourceClasses: []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeRepoPolicy, evidencepolicy.SourceTypeSignedDeclaration},
		FreshnessRequirement:    "constraint evidence should match the active branch, environment, and approval gates",
		Examples: []string{
			"Attach a protected-environment or required-check export for the deploy path.",
			"Attach repo-local policy that names the deployment gate, freeze window, or kill switch for this path.",
		},
		ClosureRefs: dedupeSortedStrings(append(append([]string(nil), path.ConstraintEvidenceRefs...), path.PolicyEvidenceRefs...)),
		ReasonCodes: []string{"constraint_evidence:missing"},
		Guidance:    "Prove the deployment or branch-protection constraint for this path before treating delivery controls as verified.",
	}, true
}

func internalToolingClosureRequirement(path ActionPath) (ClosureRequirement, bool) {
	if strings.TrimSpace(path.TargetClass) != TargetClassInternalTooling {
		return ClosureRequirement{}, false
	}
	if len(path.Contradictions) > 0 || path.ControlPriority == ControlPriorityControlFirst {
		return ClosureRequirement{}, false
	}
	return ClosureRequirement{
		ID:                      closureRequirementID(path.PathID, ClosureRequirementAcceptInternalTooling, path.TargetClass),
		Severity:                ClosureSeverityLow,
		RequirementType:         ClosureRequirementAcceptInternalTooling,
		CurrentEvidenceState:    normalizeEvidenceState(path.TargetEvidenceState),
		RequiredEvidence:        "A declared internal-tooling acceptance with owner, scope, and expiry.",
		AcceptableSourceClasses: []string{evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeRepoPolicy},
		FreshnessRequirement:    "acceptance should be explicit and time-bounded",
		Examples: []string{
			"Record the path in wrkr-control-declarations.yaml as approved internal tooling with expiry.",
		},
		ClosureRefs: append([]string(nil), path.TargetClassEvidenceRefs...),
		ReasonCodes: []string{"target_class:internal_tooling"},
		Guidance:    "If this path is intentionally internal-only tooling, declare that acceptance with owner and expiry so Wrkr can keep it visible without over-escalating it.",
	}, true
}

func scanCoverageClosureRequirement(path ActionPath, signals scanquality.CompletenessSignals, completeness *EvidenceCompleteness) (ClosureRequirement, bool) {
	if !signals.ReducedCoverage {
		return ClosureRequirement{}, false
	}
	return ClosureRequirement{
		ID:                      closureRequirementID(path.PathID, ClosureRequirementExpandScanCoverage, path.ConfidenceLane),
		Severity:                ClosureSeverityMedium,
		RequirementType:         ClosureRequirementExpandScanCoverage,
		CurrentEvidenceState:    EvidenceStateUnknown,
		RequiredEvidence:        "Complete parser and detector coverage for the repository that contains this path.",
		AcceptableSourceClasses: []string{evidencepolicy.SourceTypeRepoPolicy, evidencepolicy.SourceTypeProviderExport},
		FreshnessRequirement:    "rerun with current parser coverage after fixing reduced or blocked inputs",
		Examples: []string{
			"Fix reduced detector coverage or parse failures, then rerun the same scan inputs.",
			"Attach exported control evidence if this surface stays parser-limited.",
		},
		ClosureRefs:             append([]string(nil), signals.UnsupportedSurfaces...),
		ReasonCodes:             append([]string{"scan_quality:reduced"}, signals.Reasons...),
		Guidance:                "Restore complete scan coverage for this repository or attach stronger exported evidence before treating low-completeness conclusions as fully supported.",
	}, true
}

type freshnessIssue struct {
	field  string
	label  string
	reason string
	state  string
	refs   []string
}

func freshnessIssuesForPath(path ActionPath) []freshnessIssue {
	issues := []freshnessIssue{}
	appendDecisionIssue := func(field, label, state string) {
		decision, ok := evidenceDecisionForField(path, field)
		if !ok {
			return
		}
		switch strings.TrimSpace(decision.SelectedFreshnessState) {
		case evidencepolicy.FreshnessStateExpired:
			issues = append(issues, freshnessIssue{
				field:  field,
				label:  label,
				reason: field + ":expired",
				state:  state,
				refs:   decisionEvidenceRefs(decision),
			})
		case evidencepolicy.FreshnessStateStale:
			issues = append(issues, freshnessIssue{
				field:  field,
				label:  label,
				reason: field + ":stale",
				state:  state,
				refs:   decisionEvidenceRefs(decision),
			})
		}
	}
	appendDecisionIssue(evidencepolicy.FieldOwner, "owner", normalizeEvidenceState(path.OwnerEvidenceState))
	appendDecisionIssue(evidencepolicy.FieldApproval, "approval", normalizeEvidenceState(path.ApprovalEvidenceState))
	if strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusStale {
		issues = append(issues, freshnessIssue{
			field:  "policy",
			label:  "policy",
			reason: "policy:stale",
			state:  normalizeEvidenceState(path.ProofEvidenceState),
			refs:   append([]string(nil), path.PolicyEvidenceRefs...),
		})
	}
	if path.GaitCoverage != nil && GaitCoverageHasStatus(path.GaitCoverage, GaitStatusStale) {
		issues = append(issues, freshnessIssue{
			field:  "runtime",
			label:  "runtime",
			reason: "runtime:stale",
			state:  normalizeEvidenceState(path.RuntimeEvidenceState),
			refs:   append([]string(nil), path.ControlEvidenceRefs...),
		})
	}
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].field != issues[j].field {
			return issues[i].field < issues[j].field
		}
		return issues[i].reason < issues[j].reason
	})
	return issues
}

func buildEvidenceCompleteness(path ActionPath, signals scanquality.CompletenessSignals) *EvidenceCompleteness {
	axisScores := []EvidenceCompletenessAxisScore{
		discoveryCompletenessAxis(path, signals),
		authorityCompletenessAxis(path),
		blastCompletenessAxis(path),
		controlCompletenessAxis(path),
		runtimeCompletenessAxis(path),
		proofCompletenessAxis(path),
	}
	total := 0
	reasons := []string{}
	for _, axis := range axisScores {
		total += axis.Score
		reasons = append(reasons, axis.Reasons...)
	}
	gaps := evidenceGapsForCompleteness(path)
	freshnessPenalties := freshnessPenaltyReasons(path)
	contradictionPenalties := contradictionPenaltyReasons(path)
	reasons = append(reasons, gaps...)
	reasons = append(reasons, freshnessPenalties...)
	reasons = append(reasons, contradictionPenalties...)
	reasons = append(reasons, signals.Reasons...)
	score := int(math.Round(float64(total) / float64(len(axisScores))))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return &EvidenceCompleteness{
		TotalScore:             score,
		Label:                  evidenceCompletenessLabel(score),
		AxisScores:             axisScores,
		EvidenceGaps:           gaps,
		UnsupportedSurfaces:    dedupeSortedStrings(signals.UnsupportedSurfaces),
		FreshnessPenalties:     freshnessPenalties,
		ContradictionPenalties: contradictionPenalties,
		Reasons:                dedupeSortedStrings(reasons),
	}
}

func discoveryCompletenessAxis(path ActionPath, signals scanquality.CompletenessSignals) EvidenceCompletenessAxisScore {
	score := 60
	reasons := []string{"confidence_lane:" + firstNonEmptyString(path.ConfidenceLane, ConfidenceLaneContextOnly)}
	switch strings.TrimSpace(path.ConfidenceLane) {
	case ConfidenceLaneConfirmedActionPath:
		score = 100
	case ConfidenceLaneLikelyActionPath:
		score = 85
	case ConfidenceLaneSemanticReviewCandidate:
		score = 70
	case ConfidenceLaneContextOnly:
		score = 55
	}
	switch strings.TrimSpace(path.ActionPathType) {
	case ActionPathTypeUnknownExecutablePath:
		score -= 20
		reasons = append(reasons, "action_path_type:unknown_executable_path")
	case ActionPathTypePlainSourceCode:
		score -= 10
		reasons = append(reasons, "action_path_type:plain_source_code")
	}
	if signals.ReducedCoverage {
		score -= 25
		reasons = append(reasons, "scan_quality:reduced")
	}
	if len(signals.UnsupportedSurfaces) > 0 {
		score -= 10
		reasons = append(reasons, "unsupported_surfaces:"+strings.Join(signals.UnsupportedSurfaces, ","))
	}
	return EvidenceCompletenessAxisScore{
		Axis:    CompletenessAxisDiscovery,
		Score:   clampScore(score),
		Reasons: dedupeSortedStrings(reasons),
	}
}

func authorityCompletenessAxis(path ActionPath) EvidenceCompletenessAxisScore {
	ownerScore := evidenceStateCompletenessScore(path.OwnerEvidenceState)
	approvalScore := evidenceStateCompletenessScore(path.ApprovalEvidenceState)
	score := int(math.Round(float64(ownerScore+approvalScore) / 2.0))
	reasons := []string{
		"owner:" + normalizeEvidenceState(path.OwnerEvidenceState),
		"approval:" + normalizeEvidenceState(path.ApprovalEvidenceState),
	}
	return EvidenceCompletenessAxisScore{
		Axis:    CompletenessAxisAuthority,
		Score:   clampScore(score),
		Reasons: dedupeSortedStrings(reasons),
	}
}

func blastCompletenessAxis(path ActionPath) EvidenceCompletenessAxisScore {
	targetScore := evidenceStateCompletenessScore(path.TargetEvidenceState)
	credentialScore := evidenceStateCompletenessScore(path.CredentialEvidenceState)
	score := int(math.Round(float64(targetScore+credentialScore) / 2.0))
	reasons := []string{
		"target:" + normalizeEvidenceState(path.TargetEvidenceState),
		"credential:" + normalizeEvidenceState(path.CredentialEvidenceState),
	}
	if path.ProductionWrite && normalizeEvidenceState(path.TargetEvidenceState) == EvidenceStateUnknown {
		score -= 20
		reasons = append(reasons, "production_target:unknown")
	}
	if path.CredentialAccess && normalizeEvidenceState(path.CredentialEvidenceState) == EvidenceStateUnknown {
		score -= 20
		reasons = append(reasons, "credential_scope:unknown")
	}
	return EvidenceCompletenessAxisScore{
		Axis:    CompletenessAxisBlast,
		Score:   clampScore(score),
		Reasons: dedupeSortedStrings(reasons),
	}
}

func controlCompletenessAxis(path ActionPath) EvidenceCompletenessAxisScore {
	score := controlResolutionCompletenessScore(path.ControlResolutionState)
	reasons := []string{
		"control_resolution:" + normalizeControlResolutionState(path.ControlResolutionState),
	}
	if pathNeedsDeploymentConstraintEvidence(path) {
		score -= 20
		reasons = append(reasons, "constraint_evidence:missing")
	}
	for _, penalty := range freshnessPenaltyReasons(path) {
		score -= 10
		reasons = append(reasons, penalty)
	}
	for _, penalty := range contradictionPenaltyReasons(path) {
		score -= 15
		reasons = append(reasons, penalty)
	}
	return EvidenceCompletenessAxisScore{
		Axis:    CompletenessAxisControl,
		Score:   clampScore(score),
		Reasons: dedupeSortedStrings(reasons),
	}
}

func runtimeCompletenessAxis(path ActionPath) EvidenceCompletenessAxisScore {
	absence := RuntimeEvidenceAbsenceStatus(path)
	score := evidenceStateCompletenessScore(path.RuntimeEvidenceState)
	reasons := []string{
		"runtime:" + normalizeEvidenceState(path.RuntimeEvidenceState),
	}
	switch absence {
	case RuntimeEvidenceAbsenceNotApplicable:
		score = 100
		reasons = append(reasons, "runtime_absence_status:not_applicable")
	case RuntimeEvidenceAbsenceMissingRequired, RuntimeEvidenceAbsenceMissingForClaim:
		score = 20
		reasons = append(reasons, "runtime_absence_status:"+absence)
	case RuntimeEvidenceAbsenceNotCollected:
		score = 35
		reasons = append(reasons, "runtime_absence_status:not_collected")
	}
	if path.GaitCoverage != nil && GaitCoverageHasStatus(path.GaitCoverage, GaitStatusStale) {
		score = minInt(score, 45)
		reasons = append(reasons, "runtime:stale")
	}
	return EvidenceCompletenessAxisScore{
		Axis:    CompletenessAxisRuntime,
		Score:   clampScore(score),
		Reasons: dedupeSortedStrings(reasons),
	}
}

func proofCompletenessAxis(path ActionPath) EvidenceCompletenessAxisScore {
	score := evidenceStateCompletenessScore(path.ProofEvidenceState)
	reasons := []string{
		"proof:" + normalizeEvidenceState(path.ProofEvidenceState),
	}
	switch strings.TrimSpace(path.PolicyCoverageStatus) {
	case PolicyCoverageStatusNone:
		score = 25
		reasons = append(reasons, "policy_coverage:none")
	case PolicyCoverageStatusDeclared:
		score = maxInt(score, 75)
		reasons = append(reasons, "policy_coverage:declared")
	case PolicyCoverageStatusMatched, PolicyCoverageStatusRuntimeProven:
		score = maxInt(score, 85)
		reasons = append(reasons, "policy_coverage:"+strings.TrimSpace(path.PolicyCoverageStatus))
	case PolicyCoverageStatusStale:
		score = minInt(score, 40)
		reasons = append(reasons, "policy_coverage:stale")
	case PolicyCoverageStatusConflict:
		score = 0
		reasons = append(reasons, "policy_coverage:conflict")
	}
	return EvidenceCompletenessAxisScore{
		Axis:    CompletenessAxisProof,
		Score:   clampScore(score),
		Reasons: dedupeSortedStrings(reasons),
	}
}

func freshnessPenaltyReasons(path ActionPath) []string {
	reasons := []string{}
	for _, issue := range freshnessIssuesForPath(path) {
		reasons = append(reasons, issue.reason)
	}
	return dedupeSortedStrings(reasons)
}

func contradictionPenaltyReasons(path ActionPath) []string {
	reasons := contradictionReasonCodes(path.Contradictions)
	for _, item := range []struct {
		prefix string
		state  string
	}{
		{"owner", path.OwnerEvidenceState},
		{"approval", path.ApprovalEvidenceState},
		{"proof", path.ProofEvidenceState},
		{"runtime", path.RuntimeEvidenceState},
		{"target", path.TargetEvidenceState},
		{"credential", path.CredentialEvidenceState},
	} {
		if normalizeEvidenceState(item.state) == EvidenceStateContradictory {
			reasons = append(reasons, item.prefix+":contradictory")
		}
	}
	return dedupeSortedStrings(reasons)
}

func evidenceGapsForCompleteness(path ActionPath) []string {
	gaps := []string{}
	if normalizeEvidenceState(path.OwnerEvidenceState) == EvidenceStateUnknown {
		gaps = append(gaps, "owner_evidence:none")
	}
	if normalizeEvidenceState(path.ApprovalEvidenceState) == EvidenceStateUnknown {
		gaps = append(gaps, "approval_evidence:none")
	}
	if normalizeEvidenceState(path.ProofEvidenceState) == EvidenceStateUnknown {
		gaps = append(gaps, "proof_evidence:none")
	}
	if normalizeEvidenceState(path.RuntimeEvidenceState) == EvidenceStateUnknown {
		gaps = append(gaps, "runtime_evidence:none")
	}
	if pathNeedsDeploymentConstraintEvidence(path) {
		gaps = append(gaps, "constraint_evidence:missing")
	}
	return dedupeSortedStrings(gaps)
}

func evidenceStateCompletenessScore(state string) int {
	switch normalizeEvidenceState(state) {
	case EvidenceStateVerified:
		return 100
	case EvidenceStateDeclared:
		return 85
	case EvidenceStateInferred:
		return 70
	case EvidenceStateContradictory:
		return 0
	default:
		return 35
	}
}

func controlResolutionCompletenessScore(state string) int {
	switch normalizeControlResolutionState(state) {
	case ControlResolutionStateDetectedControl:
		return 100
	case ControlResolutionStateExternalControlReference:
		return 85
	case ControlResolutionStateDeclaredControl:
		return 80
	case ControlResolutionStateNotApplicable:
		return 90
	case ControlResolutionStateContradictoryControl:
		return 0
	default:
		return 35
	}
}

func ownerClosureSeverity(path ActionPath) string {
	if path.ControlPriority == ControlPriorityControlFirst || path.CredentialAccess || path.ProductionWrite {
		return ClosureSeverityHigh
	}
	return ClosureSeverityMedium
}

func approvalClosureSeverity(path ActionPath) string {
	if path.ControlPriority == ControlPriorityControlFirst || path.DeployWrite || path.ProductionWrite {
		return ClosureSeverityHigh
	}
	return ClosureSeverityMedium
}

func proofClosureSeverity(path ActionPath) string {
	if path.ControlPriority == ControlPriorityControlFirst || path.ProductionWrite || path.DeployWrite {
		return ClosureSeverityHigh
	}
	return ClosureSeverityMedium
}

func runtimeClosureSeverity(path ActionPath, absence string) string {
	if absence == RuntimeEvidenceAbsenceMissingRequired || absence == RuntimeEvidenceAbsenceMissingForClaim {
		return ClosureSeverityHigh
	}
	if path.CredentialAccess || path.ProductionWrite {
		return ClosureSeverityHigh
	}
	return ClosureSeverityMedium
}

func freshnessSourceClasses(field string) []string {
	switch strings.TrimSpace(field) {
	case evidencepolicy.FieldOwner:
		return []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeCustomerOwnerMap, evidencepolicy.SourceTypeSignedDeclaration}
	case evidencepolicy.FieldApproval:
		return []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeTicketExport, evidencepolicy.SourceTypeSignedDeclaration}
	case "runtime":
		return []string{evidencepolicy.SourceTypeRuntime, evidencepolicy.SourceTypeProviderExport}
	default:
		return []string{evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeRepoPolicy, evidencepolicy.SourceTypeSignedDeclaration}
	}
}

func freshnessExamples(field string) []string {
	switch strings.TrimSpace(field) {
	case evidencepolicy.FieldOwner:
		return []string{"Refresh the owner export or declaration with a current observed_at and valid_until value."}
	case evidencepolicy.FieldApproval:
		return []string{"Refresh the approval export or signed declaration with a current approval window."}
	case "runtime":
		return []string{"Recollect runtime evidence for the current execution window and correlate it to this path."}
	default:
		return []string{"Refresh the evidence with a current validity window and rescan."}
	}
}

func pathNeedsDeploymentConstraintEvidence(path ActionPath) bool {
	if !(path.DeployWrite || path.ProductionWrite || len(path.MatchedProductionTargets) > 0 || strings.TrimSpace(path.WorkflowTriggerClass) == "deploy_pipeline") {
		return false
	}
	return len(path.ConstraintEvidenceClasses) == 0 && len(path.ConstraintEvidenceRefs) == 0
}

func likelyJITCredential(path ActionPath) bool {
	if path.CredentialAuthority != nil && path.CredentialAuthority.LikelyJIT {
		return true
	}
	return path.CredentialProvenance != nil && path.CredentialProvenance.LikelyJIT
}

func closureRequirementID(pathID, requirementType, discriminator string) string {
	parts := []string{
		firstNonEmptyString(strings.TrimSpace(pathID), "path"),
		strings.TrimSpace(requirementType),
		strings.TrimSpace(discriminator),
	}
	sum := shortDigest(parts...)
	return "clr-" + sum
}

func closureSeverityPriority(value string) int {
	switch strings.TrimSpace(value) {
	case ClosureSeverityCritical:
		return 0
	case ClosureSeverityHigh:
		return 1
	case ClosureSeverityMedium:
		return 2
	case ClosureSeverityLow:
		return 3
	default:
		return 99
	}
}

func evidenceCompletenessLabel(score int) string {
	switch {
	case score >= 85:
		return EvidenceCompletenessStrong
	case score >= 60:
		return EvidenceCompletenessPartial
	default:
		return EvidenceCompletenessInsufficient
	}
}

func clampScore(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func shortDigest(parts ...string) string {
	joined := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(joined))
	return strings.ToLower(strings.TrimSpace(hex.EncodeToString(sum[:4])))
}
