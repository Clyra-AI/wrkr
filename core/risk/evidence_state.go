package risk

import (
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/owners"
)

const (
	ControlResolutionStateDetectedControl          = "detected_control"
	ControlResolutionStateDeclaredControl          = "declared_control"
	ControlResolutionStateExternalControlReference = "external_control_reference"
	ControlResolutionStateNoVisibleControl         = "no_visible_control"
	ControlResolutionStateNotApplicable            = "not_applicable"
	ControlResolutionStateContradictoryControl     = "contradictory_control"

	EvidenceStateVerified      = "verified"
	EvidenceStateDeclared      = "declared"
	EvidenceStateInferred      = "inferred"
	EvidenceStateUnknown       = "unknown"
	EvidenceStateContradictory = "contradictory"
)

func ValidControlResolutionState(value string) bool {
	switch strings.TrimSpace(value) {
	case ControlResolutionStateDetectedControl,
		ControlResolutionStateDeclaredControl,
		ControlResolutionStateExternalControlReference,
		ControlResolutionStateNoVisibleControl,
		ControlResolutionStateNotApplicable,
		ControlResolutionStateContradictoryControl:
		return true
	default:
		return false
	}
}

func ValidEvidenceState(value string) bool {
	switch strings.TrimSpace(value) {
	case EvidenceStateVerified,
		EvidenceStateDeclared,
		EvidenceStateInferred,
		EvidenceStateUnknown,
		EvidenceStateContradictory:
		return true
	default:
		return false
	}
}

func DecorateControlMetadata(paths []ActionPath, repoContexts map[string]attribution.Context) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]ActionPath(nil), paths...)
	for i := range out {
		ctx := repoContextForPath(out[i], repoContexts)
		if ctx.ControlMetadata == nil {
			continue
		}
		meta, ok := attribution.ResolveControlMetadata(ctx.ControlMetadata, strings.TrimSpace(out[i].Location))
		if !ok {
			continue
		}
		if strings.TrimSpace(out[i].OperationalOwner) == "" && strings.TrimSpace(meta.Owner) != "" {
			out[i].OperationalOwner = strings.TrimSpace(meta.Owner)
		}
		if strings.TrimSpace(out[i].OwnerSource) == "" && strings.TrimSpace(meta.OwnerSource) != "" {
			out[i].OwnerSource = strings.TrimSpace(meta.OwnerSource)
		}
		out[i].ControlResolutionState = chooseControlResolutionState(out[i].ControlResolutionState, meta.ControlResolutionState)
		out[i].ControlResolutionReasons = dedupeSortedStrings(append(append([]string(nil), out[i].ControlResolutionReasons...), meta.ControlResolutionReasons...))
		out[i].ControlEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), out[i].ControlEvidenceRefs...), append(meta.ControlEvidenceRefs, meta.ExternalReferences...)...))
		out[i].ConstraintEvidenceClasses = dedupeSortedStrings(append(append([]string(nil), out[i].ConstraintEvidenceClasses...), meta.ConstraintEvidenceClasses...))
		out[i].ConstraintEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), out[i].ConstraintEvidenceRefs...), append(meta.ConstraintEvidenceRefs, meta.ControlEvidenceRefs...)...))
		out[i].ConstraintEvidenceStatus = mergeConstraintEvidenceStatus(out[i].ConstraintEvidenceStatus, meta.ConstraintEvidenceStatus)
		out[i].ApprovalEvidenceState = chooseEvidenceState(out[i].ApprovalEvidenceState, meta.ApprovalEvidenceState)
		out[i].OwnerEvidenceState = chooseEvidenceState(out[i].OwnerEvidenceState, meta.OwnerEvidenceState)
		out[i].ProofEvidenceState = chooseEvidenceState(out[i].ProofEvidenceState, meta.ProofEvidenceState)
		out[i].RuntimeEvidenceState = chooseEvidenceState(out[i].RuntimeEvidenceState, meta.RuntimeEvidenceState)
		out[i].TargetEvidenceState = chooseEvidenceState(out[i].TargetEvidenceState, meta.TargetEvidenceState)
		out[i].CredentialEvidenceState = chooseEvidenceState(out[i].CredentialEvidenceState, meta.CredentialEvidenceState)
		out[i].TargetClass = chooseTargetClass(out[i].TargetClass, meta.TargetClass)
		out[i].TargetClassReasons = dedupeSortedStrings(append(append([]string(nil), out[i].TargetClassReasons...), meta.TargetClassReasons...))
		out[i].TargetClassEvidenceRefs = dedupeSortedStrings(append(append([]string(nil), out[i].TargetClassEvidenceRefs...), meta.TargetClassEvidenceRefs...))
		out[i].EvidenceDecisions = mergeEvidenceDecisions(out[i].EvidenceDecisions, meta.EvidenceDecisions)
	}
	return out
}

func repoContextForPath(path ActionPath, repoContexts map[string]attribution.Context) attribution.Context {
	if repoContexts == nil {
		return attribution.Context{}
	}
	ctx := repoContexts[repoKey(path.Org, path.Repo)]
	if strings.TrimSpace(ctx.RepoRoot) == "" {
		ctx = repoContexts["local::"+strings.TrimSpace(path.Repo)]
	}
	if strings.TrimSpace(ctx.RepoRoot) == "" {
		ctx = repoContexts["::"+strings.TrimSpace(path.Repo)]
	}
	return ctx
}

func projectEvidenceStates(path ActionPath) ActionPath {
	out := path

	approvalState, approvalReasons, approvalRefs := deriveApprovalEvidenceState(out)
	ownerState, ownerReasons, ownerRefs := deriveOwnerEvidenceState(out)
	proofState, proofReasons, proofRefs := deriveProofEvidenceState(out)
	runtimeState, runtimeReasons, runtimeRefs := deriveRuntimeEvidenceState(out)
	targetState, targetReasons, targetRefs := deriveTargetEvidenceState(out)
	credentialState, credentialReasons, credentialRefs := deriveCredentialEvidenceState(out)

	out.ApprovalEvidenceState = mergeEvidenceState(approvalState, out.ApprovalEvidenceState)
	out.OwnerEvidenceState = mergeEvidenceState(ownerState, out.OwnerEvidenceState)
	out.ProofEvidenceState = mergeEvidenceState(proofState, out.ProofEvidenceState)
	out.RuntimeEvidenceState = mergeEvidenceState(runtimeState, out.RuntimeEvidenceState)
	out.TargetEvidenceState = mergeEvidenceState(targetState, out.TargetEvidenceState)
	out.CredentialEvidenceState = mergeEvidenceState(credentialState, out.CredentialEvidenceState)

	out.ControlEvidenceRefs = dedupeSortedStrings(append(
		append(
			append(
				append(
					append(
						append([]string(nil), out.ControlEvidenceRefs...),
						ownerRefs...,
					),
					approvalRefs...,
				),
				proofRefs...,
			),
			runtimeRefs...,
		),
		append(targetRefs, credentialRefs...)...,
	))

	reasons := append([]string(nil), ownerReasons...)
	reasons = append(reasons, approvalReasons...)
	reasons = append(reasons, proofReasons...)
	reasons = append(reasons, runtimeReasons...)
	reasons = append(reasons, targetReasons...)
	reasons = append(reasons, credentialReasons...)

	out.ControlResolutionState, out.ControlResolutionReasons = deriveControlResolutionState(out, reasons)
	return out
}

func deriveApprovalEvidenceState(path ActionPath) (string, []string, []string) {
	if decision, ok := evidenceDecisionForField(path, evidencepolicy.FieldApproval); ok {
		refs := decisionEvidenceRefs(decision)
		switch {
		case strings.TrimSpace(decision.ConflictState) == evidencepolicy.ConflictStateAmbiguous:
			return EvidenceStateContradictory, []string{"approval_evidence:conflict"}, refs
		case decisionFreshnessExpired(decision):
			return EvidenceStateUnknown, []string{"approval_evidence:expired"}, refs
		case decisionFreshnessStale(decision):
			return EvidenceStateUnknown, []string{"approval_evidence:stale"}, refs
		default:
			return decisionEvidenceState(decision, evidencepolicy.FieldApproval), []string{"approval_evidence:precedence_selected"}, refs
		}
	}
	reasons := []string{}
	refs := []string{}
	approvalSatisfied := false
	for _, item := range path.GovernanceControls {
		if strings.TrimSpace(item.Control) != agginventory.GovernanceControlApproval {
			continue
		}
		refs = append(refs, item.Evidence...)
		if strings.TrimSpace(item.Status) == agginventory.ControlStatusSatisfied {
			approvalSatisfied = true
		}
	}
	if path.ApprovalGap {
		reasons = append(reasons, "approval_gap:true")
		reasons = append(reasons, path.ApprovalGapReasons...)
		return EvidenceStateUnknown, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	}
	if approvalSatisfied && len(refs) > 0 {
		reasons = append(reasons, "approval_control:satisfied")
		return EvidenceStateVerified, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	}
	if approvalSatisfied {
		reasons = append(reasons, "approval_control:satisfied_without_refs")
		return EvidenceStateInferred, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	}
	if strings.TrimSpace(path.SecurityVisibilityStatus) == agginventory.SecurityVisibilityApproved ||
		strings.TrimSpace(path.SecurityVisibilityStatus) == agginventory.SecurityVisibilityKnownApproved {
		reasons = append(reasons, "security_visibility:approved")
		return EvidenceStateInferred, dedupeSortedStrings(reasons), dedupeSortedStrings(refs)
	}
	return EvidenceStateUnknown, []string{"approval_evidence:none"}, nil
}

func deriveOwnerEvidenceState(path ActionPath) (string, []string, []string) {
	if decision, ok := evidenceDecisionForField(path, evidencepolicy.FieldOwner); ok {
		refs := decisionEvidenceRefs(decision)
		switch {
		case strings.TrimSpace(decision.ConflictState) == evidencepolicy.ConflictStateAmbiguous:
			reasons := []string{"owner_evidence:conflict"}
			return EvidenceStateContradictory, dedupeSortedStrings(append(reasons, path.OwnershipConflicts...)), refs
		case decisionFreshnessExpired(decision):
			return EvidenceStateUnknown, []string{"owner_evidence:expired"}, refs
		case decisionFreshnessStale(decision):
			return EvidenceStateUnknown, []string{"owner_evidence:stale"}, refs
		default:
			return decisionEvidenceState(decision, evidencepolicy.FieldOwner), []string{"owner_evidence:precedence_selected"}, refs
		}
	}
	reasons := []string{}
	refs := dedupeSortedStrings(path.OwnershipEvidence)
	switch {
	case len(path.OwnershipConflicts) > 0,
		strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceConflict,
		strings.TrimSpace(path.OwnershipState) == owners.OwnershipStateConflicting:
		reasons = append(reasons, "owner_evidence:conflict")
		reasons = append(reasons, path.OwnershipConflicts...)
		return EvidenceStateContradictory, dedupeSortedStrings(reasons), refs
	case strings.TrimSpace(path.OperationalOwner) == "",
		strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceMissing,
		strings.TrimSpace(path.OwnershipState) == owners.OwnershipStateMissing,
		strings.TrimSpace(path.OwnershipStatus) == "",
		strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusUnresolved:
		reasons = append(reasons, "owner_evidence:none")
		return EvidenceStateUnknown, dedupeSortedStrings(reasons), refs
	case strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusInferred,
		strings.TrimSpace(path.OwnershipState) == owners.OwnershipStateInferred,
		strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceRepoFallback:
		reasons = append(reasons, "owner_evidence:inferred")
		return EvidenceStateInferred, dedupeSortedStrings(reasons), refs
	case len(refs) > 0:
		reasons = append(reasons, "owner_evidence:linked")
		return EvidenceStateVerified, dedupeSortedStrings(reasons), refs
	default:
		reasons = append(reasons, "owner_evidence:present_without_refs")
		return EvidenceStateInferred, dedupeSortedStrings(reasons), refs
	}
}

func deriveProofEvidenceState(path ActionPath) (string, []string, []string) {
	reasons := []string{}
	refs := dedupeSortedStrings(append([]string(nil), path.PolicyEvidenceRefs...))
	if path.GaitCoverage != nil {
		refs = dedupeSortedStrings(append(refs, path.GaitCoverage.ProofVerification.EvidenceRefs...))
		switch strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) {
		case GaitStatusConflict:
			reasons = append(reasons, "proof_evidence:conflict")
			return EvidenceStateContradictory, dedupeSortedStrings(reasons), refs
		case GaitStatusPresent:
			if len(refs) > 0 {
				reasons = append(reasons, "proof_evidence:linked")
				return EvidenceStateVerified, dedupeSortedStrings(reasons), refs
			}
			reasons = append(reasons, "proof_evidence:present_without_refs")
			return EvidenceStateInferred, dedupeSortedStrings(reasons), refs
		}
	}
	switch strings.TrimSpace(path.PolicyCoverageStatus) {
	case PolicyCoverageStatusConflict:
		reasons = append(reasons, "policy_coverage:conflict")
		return EvidenceStateContradictory, dedupeSortedStrings(reasons), refs
	case PolicyCoverageStatusDeclared:
		if len(refs) > 0 {
			reasons = append(reasons, "policy_coverage:declared_with_refs")
			return EvidenceStateVerified, dedupeSortedStrings(reasons), refs
		}
		return EvidenceStateDeclared, []string{"policy_coverage:declared"}, refs
	case PolicyCoverageStatusMatched, PolicyCoverageStatusRuntimeProven:
		if len(refs) > 0 {
			reasons = append(reasons, "policy_coverage:linked")
			return EvidenceStateVerified, dedupeSortedStrings(reasons), refs
		}
		return EvidenceStateInferred, []string{"policy_coverage:present_without_refs"}, refs
	case PolicyCoverageStatusStale:
		return EvidenceStateUnknown, []string{"policy_coverage:stale"}, refs
	case PolicyCoverageStatusNone, "":
		return EvidenceStateUnknown, []string{"proof_evidence:none"}, refs
	default:
		return EvidenceStateUnknown, []string{"proof_evidence:none"}, refs
	}
}

func deriveRuntimeEvidenceState(path ActionPath) (string, []string, []string) {
	refs := []string{}
	if path.GaitCoverage == nil {
		return EvidenceStateUnknown, []string{"runtime_evidence:none"}, nil
	}
	details := []GaitCoverageDetail{
		path.GaitCoverage.PolicyDecision,
		path.GaitCoverage.Approval,
		path.GaitCoverage.JITCredential,
		path.GaitCoverage.FreezeWindow,
		path.GaitCoverage.KillSwitch,
		path.GaitCoverage.ActionOutcome,
		path.GaitCoverage.ProofVerification,
	}
	hasConflict := false
	hasStale := false
	hasLinkedEvidence := false
	presentWithoutRefs := false
	for _, detail := range details {
		refs = append(refs, detail.EvidenceRefs...)
		switch strings.TrimSpace(detail.Status) {
		case GaitStatusConflict:
			hasConflict = true
		case GaitStatusStale:
			hasStale = true
		case GaitStatusPresent:
			if len(detail.EvidenceRefs) == 0 {
				presentWithoutRefs = true
				continue
			}
			hasLinkedEvidence = true
		}
	}
	if hasConflict {
		return EvidenceStateContradictory, []string{"runtime_evidence:conflict"}, dedupeSortedStrings(refs)
	}
	switch RuntimeEvidenceAbsenceStatus(path) {
	case RuntimeEvidenceAbsenceMissingForClaim:
		return EvidenceStateUnknown, []string{"runtime_evidence:missing_for_control_claim"}, dedupeSortedStrings(refs)
	case RuntimeEvidenceAbsenceMissingRequired:
		return EvidenceStateUnknown, []string{"runtime_evidence:missing_required"}, dedupeSortedStrings(refs)
	}
	if hasStale {
		return EvidenceStateUnknown, []string{"runtime_evidence:stale"}, dedupeSortedStrings(refs)
	}
	if hasLinkedEvidence {
		return EvidenceStateVerified, []string{"runtime_evidence:linked"}, dedupeSortedStrings(refs)
	}
	if presentWithoutRefs {
		return EvidenceStateInferred, []string{"runtime_evidence:present_without_refs"}, dedupeSortedStrings(refs)
	}
	switch RuntimeEvidenceAbsenceStatus(path) {
	case RuntimeEvidenceAbsenceNotApplicable:
		return EvidenceStateUnknown, []string{"runtime_evidence:not_applicable"}, dedupeSortedStrings(refs)
	case RuntimeEvidenceAbsenceNotCollected:
		return EvidenceStateUnknown, []string{"runtime_evidence:not_collected"}, dedupeSortedStrings(refs)
	}
	return EvidenceStateUnknown, []string{"runtime_evidence:none"}, dedupeSortedStrings(refs)
}

func deriveTargetEvidenceState(path ActionPath) (string, []string, []string) {
	refs := []string{}
	for _, item := range pathMutableEndpointSemantics(path) {
		refs = append(refs, item.EvidenceRefs...)
	}
	switch {
	case len(refs) > 0:
		return EvidenceStateVerified, []string{"target_evidence:linked"}, dedupeSortedStrings(refs)
	case len(path.MatchedProductionTargets) > 0 && len(refs) > 0:
		return EvidenceStateVerified, []string{"target_evidence:linked"}, dedupeSortedStrings(refs)
	case len(path.MatchedProductionTargets) > 0 || pathHasAnyMutableEndpoint(path) || path.ProductionWrite:
		return EvidenceStateInferred, []string{"target_evidence:inferred"}, dedupeSortedStrings(refs)
	default:
		return EvidenceStateUnknown, []string{"target_evidence:none"}, dedupeSortedStrings(refs)
	}
}

func deriveCredentialEvidenceState(path ActionPath) (string, []string, []string) {
	refs := []string{}
	if path.CredentialAuthority != nil {
		refs = append(refs, path.CredentialAuthority.ReasonCodes...)
	}
	if path.CredentialProvenance != nil {
		refs = append(refs, path.CredentialProvenance.EvidenceBasis...)
	}
	switch {
	case path.CredentialAuthority != nil && len(refs) > 0:
		return EvidenceStateVerified, []string{"credential_evidence:linked"}, dedupeSortedStrings(refs)
	case path.CredentialProvenance != nil && len(refs) > 0:
		return EvidenceStateVerified, []string{"credential_evidence:linked"}, dedupeSortedStrings(refs)
	case path.CredentialAuthority != nil || path.CredentialProvenance != nil || path.CredentialAccess:
		return EvidenceStateInferred, []string{"credential_evidence:inferred"}, dedupeSortedStrings(refs)
	default:
		return EvidenceStateUnknown, []string{"credential_evidence:none"}, dedupeSortedStrings(refs)
	}
}

func deriveControlResolutionState(path ActionPath, fieldReasons []string) (string, []string) {
	seed := normalizeControlResolutionState(path.ControlResolutionState)
	reasons := append([]string(nil), fieldReasons...)
	reasons = append(reasons,
		"approval_evidence_state:"+normalizeEvidenceState(path.ApprovalEvidenceState),
		"owner_evidence_state:"+normalizeEvidenceState(path.OwnerEvidenceState),
		"proof_evidence_state:"+normalizeEvidenceState(path.ProofEvidenceState),
		"runtime_evidence_state:"+normalizeEvidenceState(path.RuntimeEvidenceState),
		"target_evidence_state:"+normalizeEvidenceState(path.TargetEvidenceState),
		"credential_evidence_state:"+normalizeEvidenceState(path.CredentialEvidenceState),
	)

	switch {
	case seed == ControlResolutionStateContradictoryControl,
		normalizeEvidenceState(path.ApprovalEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.OwnerEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.ProofEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.RuntimeEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.TargetEvidenceState) == EvidenceStateContradictory,
		normalizeEvidenceState(path.CredentialEvidenceState) == EvidenceStateContradictory,
		len(path.Contradictions) > 0:
		return ControlResolutionStateContradictoryControl, dedupeSortedStrings(append(reasons, "control_resolution:contradictory"))
	case seed == ControlResolutionStateExternalControlReference:
		return ControlResolutionStateExternalControlReference, dedupeSortedStrings(append(reasons, "control_resolution:external_control_reference"))
	case seed == ControlResolutionStateDeclaredControl:
		return ControlResolutionStateDeclaredControl, dedupeSortedStrings(append(reasons, "control_resolution:declared_control"))
	case !pathNeedsVisibleControl(path):
		return ControlResolutionStateNotApplicable, dedupeSortedStrings(append(reasons, "control_resolution:not_applicable"))
	case pathHasVisibleControlEvidence(path):
		return chooseControlResolutionState(ControlResolutionStateDetectedControl, seed), dedupeSortedStrings(append(reasons, "control_resolution:detected_control"))
	default:
		return chooseControlResolutionState(ControlResolutionStateNoVisibleControl, seed), dedupeSortedStrings(append(reasons, "control_resolution:no_visible_control"))
	}
}

func evidenceDecisionForField(path ActionPath, field string) (evidencepolicy.Decision, bool) {
	for _, item := range path.EvidenceDecisions {
		if strings.TrimSpace(item.Field) == strings.TrimSpace(field) {
			return item, true
		}
	}
	return evidencepolicy.Decision{}, false
}

func decisionEvidenceRefs(decision evidencepolicy.Decision) []string {
	values := append([]string(nil), decision.SelectedEvidenceRefs...)
	for _, item := range decision.RejectedCandidates {
		values = append(values, item.EvidenceRefs...)
	}
	return dedupeSortedStrings(values)
}

func decisionFreshnessExpired(decision evidencepolicy.Decision) bool {
	return strings.TrimSpace(decision.SelectedFreshnessState) == evidencepolicy.FreshnessStateExpired
}

func decisionFreshnessStale(decision evidencepolicy.Decision) bool {
	return strings.TrimSpace(decision.SelectedFreshnessState) == evidencepolicy.FreshnessStateStale
}

func decisionEvidenceState(decision evidencepolicy.Decision, field string) string {
	switch strings.TrimSpace(decision.SelectedStatus) {
	case "unmatched":
		return EvidenceStateUnknown
	case "conflict":
		return EvidenceStateContradictory
	}
	sourceType := evidencepolicy.NormalizeSourceType(decision.SelectedSourceType)
	switch strings.TrimSpace(field) {
	case evidencepolicy.FieldOwner:
		switch sourceType {
		case evidencepolicy.SourceTypeSignedDeclaration, evidencepolicy.SourceTypeCustomerOwnerMap:
			return EvidenceStateDeclared
		case evidencepolicy.SourceTypeGitHubMetadata, evidencepolicy.SourceTypeRepoFallback:
			return EvidenceStateInferred
		default:
			return EvidenceStateVerified
		}
	default:
		switch sourceType {
		case evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeGitHubTeamExport, evidencepolicy.SourceTypeBackstageExport, evidencepolicy.SourceTypeTicketExport:
			return EvidenceStateVerified
		case evidencepolicy.SourceTypeGitHubMetadata, evidencepolicy.SourceTypeRepoFallback:
			return EvidenceStateInferred
		default:
			return EvidenceStateDeclared
		}
	}
}

func pathNeedsVisibleControl(path ActionPath) bool {
	return path.WriteCapable ||
		path.PullRequestWrite ||
		path.MergeExecute ||
		path.DeployWrite ||
		path.ProductionWrite ||
		path.CredentialAccess ||
		pathHasAnyMutableEndpoint(path) ||
		path.ApprovalGap ||
		len(path.PolicyRefs) > 0 ||
		strings.TrimSpace(path.PolicyCoverageStatus) != "" ||
		actionPathHasWeakOwnership(path)
}

func pathHasVisibleControlEvidence(path ActionPath) bool {
	for _, state := range []string{
		path.OwnerEvidenceState,
		path.ApprovalEvidenceState,
		path.ProofEvidenceState,
		path.RuntimeEvidenceState,
	} {
		switch normalizeEvidenceState(state) {
		case EvidenceStateVerified, EvidenceStateDeclared, EvidenceStateInferred:
			return true
		}
	}
	return false
}

func mergeEvidenceState(derived, existing string) string {
	derived = normalizeEvidenceState(derived)
	existing = normalizeEvidenceState(existing)
	switch {
	case derived == "":
		return existing
	case existing == "":
		return derived
	case derived == EvidenceStateContradictory || existing == EvidenceStateContradictory:
		return EvidenceStateContradictory
	case derived == existing:
		return derived
	case derived == EvidenceStateUnknown:
		return existing
	case existing == EvidenceStateUnknown:
		return derived
	default:
		if evidenceStatePriority(derived) < evidenceStatePriority(existing) {
			return derived
		}
		return existing
	}
}

func chooseEvidenceState(current, incoming string) string {
	return mergeEvidenceState(current, incoming)
}

func chooseControlResolutionState(current, incoming string) string {
	current = normalizeControlResolutionState(current)
	incoming = normalizeControlResolutionState(incoming)
	switch {
	case current == "":
		return incoming
	case incoming == "":
		return current
	case current == incoming:
		return current
	default:
		if controlResolutionPriority(incoming) < controlResolutionPriority(current) {
			return incoming
		}
		return current
	}
}

func normalizeEvidenceState(value string) string {
	value = strings.TrimSpace(value)
	if !ValidEvidenceState(value) {
		return ""
	}
	return value
}

func normalizeControlResolutionState(value string) string {
	value = strings.TrimSpace(value)
	if !ValidControlResolutionState(value) {
		return ""
	}
	return value
}

func evidenceStatePriority(value string) int {
	switch strings.TrimSpace(value) {
	case EvidenceStateVerified:
		return 0
	case EvidenceStateDeclared:
		return 1
	case EvidenceStateInferred:
		return 2
	case EvidenceStateUnknown:
		return 3
	case EvidenceStateContradictory:
		return 4
	default:
		return 99
	}
}

func controlResolutionPriority(value string) int {
	switch strings.TrimSpace(value) {
	case ControlResolutionStateContradictoryControl:
		return 0
	case ControlResolutionStateExternalControlReference:
		return 1
	case ControlResolutionStateDeclaredControl:
		return 2
	case ControlResolutionStateDetectedControl:
		return 3
	case ControlResolutionStateNoVisibleControl:
		return 4
	case ControlResolutionStateNotApplicable:
		return 5
	default:
		return 99
	}
}
