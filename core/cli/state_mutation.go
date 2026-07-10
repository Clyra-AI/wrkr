package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	profilemodel "github.com/Clyra-AI/wrkr/core/policy/profile"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/statelock"
)

type stateMutationContext struct {
	preflight      stateMutationPreflight
	snapshot       state.Snapshot
	manifest       manifest.Manifest
	lifecycleChain *proof.Chain
	lease          *statelock.Lease
}

func loadStateMutationContext(statePathRaw string) (stateMutationContext, error) {
	preflight, err := preflightStateMutationArtifacts(statePathRaw)
	if err != nil {
		if isUnsafeManagedArtifactPathError(err) {
			return stateMutationContext{}, err
		}
		return stateMutationContext{}, unsafeManagedArtifactPathError{err: err}
	}
	lease, err := statelock.Acquire(context.Background(), preflight.statePath)
	if err != nil {
		return stateMutationContext{}, err
	}
	releaseOnError := func(err error) (stateMutationContext, error) {
		if releaseErr := lease.Release(); releaseErr != nil {
			return stateMutationContext{}, fmt.Errorf("%v (release managed artifact lock: %v)", err, releaseErr)
		}
		return stateMutationContext{}, err
	}
	if err := preflightManagedArtifactRead(preflight.statePath); err != nil {
		return releaseOnError(err)
	}
	snapshot, err := state.Load(preflight.statePath)
	if err != nil {
		return releaseOnError(err)
	}
	loadedManifest, err := manifest.Load(preflight.manifestPath)
	if err != nil {
		return releaseOnError(err)
	}
	loadedManifest.Identities = model.FilterLegacyArtifactIdentityRecords(loadedManifest.Identities)
	lifecycleChain, err := lifecycle.LoadChain(preflight.lifecyclePath)
	if err != nil {
		return releaseOnError(err)
	}
	if _, err := proofemit.LoadChain(preflight.proofChainPath); err != nil {
		return releaseOnError(err)
	}
	return stateMutationContext{
		preflight:      preflight,
		snapshot:       snapshot,
		manifest:       loadedManifest,
		lifecycleChain: lifecycleChain,
		lease:          lease,
	}, nil
}

func (ctx *stateMutationContext) releaseLease() error {
	if ctx == nil || ctx.lease == nil {
		return nil
	}
	lease := ctx.lease
	ctx.lease = nil
	return lease.Release()
}

func applyStateMutationToSnapshot(snapshot *state.Snapshot, nextManifest manifest.Manifest, transition lifecycle.Transition) error {
	if snapshot == nil {
		return nil
	}
	snapshot.ApprovalInventoryVersion = state.ApprovalInventoryVersion
	snapshot.Identities = append([]manifest.IdentityRecord(nil), nextManifest.Identities...)
	snapshot.Transitions = append(snapshot.Transitions, transition)
	return refreshDerivedMutationSnapshot(snapshot)
}

func refreshDerivedMutationSnapshot(snapshot *state.Snapshot) error {
	if snapshot == nil {
		return nil
	}
	if snapshot.Inventory != nil {
		agginventory.RefreshIdentityGovernance(snapshot.Inventory, snapshot.Identities)
		snapshot.LifecycleGaps = lifecycle.DetectGaps(lifecycle.GapInput{
			Identities:  snapshot.Identities,
			Inventory:   snapshot.Inventory,
			Transitions: snapshot.Transitions,
		})
		snapshot.Inventory.LifecycleQueue = lifecycle.BuildQueue(snapshot.LifecycleGaps)
	}
	actionPaths := []risk.ActionPath(nil)
	var controlPathGraph *aggattack.ControlPathGraph
	if snapshot.RiskReport != nil && snapshot.Inventory != nil {
		snapshot.RiskReport.ActionPaths, snapshot.RiskReport.ActionPathToControlFirst = risk.BuildActionPaths(snapshot.RiskReport.AttackPaths, snapshot.Inventory)
		snapshot.RiskReport.ControlPathGraph = risk.BuildControlPathGraph(snapshot.RiskReport.ActionPaths)
		snapshot.RiskReport.WorkflowChains = risk.BuildWorkflowChains(snapshot.RiskReport.ActionPaths, snapshot.RiskReport.ControlPathGraph)
		snapshot.RiskReport.ActionPaths = risk.DecorateWorkflowChainRefs(snapshot.RiskReport.ActionPaths, snapshot.RiskReport.WorkflowChains)
		snapshot.RiskReport.ActionPaths = risk.DecorateActionLineage(snapshot.RiskReport.ActionPaths, snapshot.RiskReport.ControlPathGraph)
		snapshot.RiskReport.ActionPathToControlFirst = risk.BuildActionPathChoice(snapshot.RiskReport.ActionPaths)
		actionPaths = snapshot.RiskReport.ActionPaths
		controlPathGraph = snapshot.RiskReport.ControlPathGraph
	}
	if snapshot.ControlBacklog != nil && len(snapshot.Findings) == 0 && len(actionPaths) == 0 {
		refreshExistingControlBacklog(snapshot)
	} else if snapshot.Inventory != nil || snapshot.ControlBacklog != nil {
		backlog := controlbacklog.Build(controlbacklog.Input{
			Mode:             snapshot.ScanMode,
			GeneratedAt:      mutationGeneratedAt(snapshot),
			Findings:         snapshot.Findings,
			Inventory:        snapshot.Inventory,
			Identities:       snapshot.Identities,
			LifecycleGaps:    snapshot.LifecycleGaps,
			ActionPaths:      actionPaths,
			ControlPathGraph: controlPathGraph,
		})
		snapshot.ControlBacklog = &backlog
	}

	weights := scoremodel.DefaultWeights()
	var previous *score.Result
	if snapshot.PostureScore != nil {
		copyResult := *snapshot.PostureScore
		previous = &copyResult
		if err := copyResult.Weights.Validate(); err == nil {
			weights = copyResult.Weights
		}
	}

	var profileResult profileeval.Result
	if snapshot.Profile != nil {
		profileResult = *snapshot.Profile
	} else {
		profileDef, err := profilemodel.Builtin("standard")
		if err != nil {
			return err
		}
		profileResult = profileeval.Evaluate(profileDef, snapshot.Findings, nil)
	}

	computed := score.Compute(score.Input{
		Findings:        snapshot.Findings,
		PolicyOutcomes:  outputsignal.BuildPolicyOutcomes(snapshot.Findings),
		Identities:      model.FilterLegacyArtifactIdentityRecords(snapshot.Identities),
		ProfileResult:   profileResult,
		TransitionCount: driftTransitionCount(snapshot.Transitions),
		Weights:         weights,
		Previous:        previous,
	})
	snapshot.PolicyOutcomes = outputsignal.BuildPolicyOutcomes(snapshot.Findings)
	snapshot.PostureScore = &computed
	return nil
}

func commitStateMutationContext(ctx stateMutationContext, transition lifecycle.Transition, eventType string) error {
	transaction, err := beginManagedArtifactTransactionWithLease(ctx.preflight.statePath, "state_mutation", []managedArtifactFile{
		{label: "state", path: ctx.preflight.statePath},
		{label: "manifest", path: ctx.preflight.manifestPath},
		{label: "lifecycle chain", path: ctx.preflight.lifecyclePath},
		{label: "proof chain", path: ctx.preflight.proofChainPath},
		{label: "proof attestation", path: ctx.preflight.proofAttestationPath},
		{label: "proof signing key", path: ctx.preflight.signingKeyPath},
	}, ctx.lease)
	if err != nil {
		return unsafeManagedArtifactPathError{err: err}
	}
	if err := state.Save(ctx.preflight.statePath, ctx.snapshot); err != nil {
		return transaction.Rollback(err)
	}
	if err := lifecycle.SaveChain(ctx.preflight.lifecyclePath, ctx.lifecycleChain); err != nil {
		return transaction.Rollback(err)
	}
	if err := proofemit.EmitIdentityTransition(ctx.preflight.statePath, transition, eventType); err != nil {
		return transaction.Rollback(err)
	}
	if err := manifest.Save(ctx.preflight.manifestPath, ctx.manifest); err != nil {
		return transaction.Rollback(err)
	}
	if err := verifyManagedArtifactConsistency(ctx.preflight.statePath, managedArtifactVerificationFull); err != nil {
		return transaction.Rollback(err)
	}
	if err := transaction.Complete(); err != nil {
		return transaction.Rollback(err)
	}
	return nil
}

func emitStateMutationError(stderr io.Writer, jsonOut bool, err error) int {
	if isUnsafeManagedArtifactPathError(err) {
		return emitError(stderr, jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	}
	return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
}

func refreshExistingControlBacklog(snapshot *state.Snapshot) {
	if snapshot == nil || snapshot.ControlBacklog == nil {
		return
	}
	recordsByAgent := make(map[string]manifest.IdentityRecord, len(snapshot.Identities))
	for _, record := range snapshot.Identities {
		recordsByAgent[strings.TrimSpace(record.AgentID)] = record
	}
	items := snapshot.ControlBacklog.Items[:0]
	for _, item := range snapshot.ControlBacklog.Items {
		updated := item
		agentID := agentIDForInventoryPath(*snapshot, item.Repo, item.Path)
		record, ok := recordsByAgent[strings.TrimSpace(agentID)]
		if ok {
			updated.ApprovalStatus = backlogApprovalStatus(record)
			updated.SecurityVisibility = agginventory.GovernanceSecurityVisibilityStatus(backlogSecurityVisibility(record), strings.TrimSpace(record.ApprovalState), strings.TrimSpace(record.Status))
			if owner := strings.TrimSpace(record.Approval.Owner); owner != "" {
				updated.Owner = owner
				updated.OwnerSource = "inventory_approval"
				updated.OwnershipStatus = "explicit"
			}
			switch {
			case strings.TrimSpace(record.Status) == identity.StateDeprecated:
				updated.RecommendedAction = controlbacklog.ActionDeprecate
			case strings.TrimSpace(record.ApprovalState) == "valid" || strings.TrimSpace(record.ApprovalState) == "accepted_risk":
				updated.RecommendedAction = controlbacklog.ActionMonitor
				updated.EvidenceGaps = nil
				updated.ConfidenceRaise = nil
			}
		}
		items = append(items, updated)
	}
	snapshot.ControlBacklog.Items = items
	snapshot.ControlBacklog.Summary = summarizeBacklogItems(items)
}

func applyInventoryMutationOverrides(snapshot *state.Snapshot, record manifest.IdentityRecord, requestedID string, action string) {
	if snapshot == nil || snapshot.ControlBacklog == nil {
		return
	}
	if strings.TrimSpace(action) != "exclude" {
		return
	}
	items := snapshot.ControlBacklog.Items[:0]
	for _, item := range snapshot.ControlBacklog.Items {
		updated := item
		if backlogItemMatchesRecord(item.ID, item.Repo, item.Path, requestedID, record) {
			updated.ApprovalStatus = backlogApprovalStatus(record)
			updated.SecurityVisibility = agginventory.GovernanceSecurityVisibilityStatus(backlogSecurityVisibility(record), strings.TrimSpace(record.ApprovalState), strings.TrimSpace(record.Status))
			updated.Queue = controlbacklog.QueueInventoryHygiene
			updated.FindingVisibility = controlbacklog.FindingVisibilityAppendix
			updated.RecommendedAction = controlbacklog.ActionSuppress
			updated.GovernanceDisposition = &controlbacklog.GovernanceDisposition{
				Kind:               controlbacklog.GovernanceKindSuppression,
				Status:             controlbacklog.GovernanceStatusActive,
				Reason:             firstNonEmptySnapshotValue(strings.TrimSpace(record.Approval.ExclusionReason), strings.TrimSpace(record.Approval.DecisionReason)),
				Scope:              firstNonEmptySnapshotValue(strings.TrimSpace(record.Approval.Scope), "control_path"),
				Issuer:             firstNonEmptySnapshotValue(strings.TrimSpace(record.Approval.Approver), strings.TrimSpace(record.Approval.Owner)),
				ExpiresAt:          strings.TrimSpace(record.Approval.Expires),
				EvidenceState:      firstNonEmptySnapshotValue(strings.TrimSpace(updated.ApprovalEvidenceState), "unknown"),
				VisibilityBehavior: controlbacklog.FindingVisibilityAppendix,
				RescanBehavior:     "retain_appendix_until_expiry",
				EvidenceRefs:       compactSnapshotStrings(strings.TrimSpace(record.Approval.ControlID), strings.TrimSpace(record.Approval.EvidenceURL)),
			}
		}
		items = append(items, updated)
	}
	snapshot.ControlBacklog.Items = items
	snapshot.ControlBacklog.Summary = summarizeBacklogItems(snapshot.ControlBacklog.Items)
}

func backlogApprovalStatus(record manifest.IdentityRecord) string {
	switch strings.TrimSpace(record.ApprovalState) {
	case "valid", "approved", "approved_list", "accepted_risk", "risk_accepted":
		return "approved"
	case "", "unknown":
		return "unknown"
	default:
		return "unapproved"
	}
}

func backlogItemMatchesRecord(itemID, repo, path, requestedID string, record manifest.IdentityRecord) bool {
	if strings.TrimSpace(itemID) != "" && strings.TrimSpace(itemID) == strings.TrimSpace(requestedID) {
		return true
	}
	return strings.TrimSpace(repo) == strings.TrimSpace(record.Repo) && strings.TrimSpace(path) == strings.TrimSpace(record.Location)
}

func backlogSecurityVisibility(record manifest.IdentityRecord) string {
	switch strings.TrimSpace(record.ApprovalState) {
	case "valid":
		return agginventory.SecurityVisibilityKnownApproved
	case "accepted_risk", "risk_accepted":
		return agginventory.SecurityVisibilityAcceptedRisk
	case "expired", "invalid":
		return agginventory.SecurityVisibilityNeedsReview
	case "deprecated":
		return agginventory.SecurityVisibilityDeprecated
	case "excluded", "revoked":
		return agginventory.SecurityVisibilityRevoked
	}
	switch strings.TrimSpace(record.Status) {
	case identity.StateDeprecated:
		return agginventory.SecurityVisibilityDeprecated
	case identity.StateRevoked:
		return agginventory.SecurityVisibilityRevoked
	case identity.StateActive, identity.StateApproved:
		return agginventory.SecurityVisibilityKnownApproved
	default:
		return agginventory.SecurityVisibilityNeedsReview
	}
}

func mutationGeneratedAt(snapshot *state.Snapshot) time.Time {
	if snapshot == nil || len(snapshot.Transitions) == 0 {
		return time.Now().UTC().Truncate(time.Second)
	}
	latest := strings.TrimSpace(snapshot.Transitions[len(snapshot.Transitions)-1].Timestamp)
	if latest == "" {
		return time.Now().UTC().Truncate(time.Second)
	}
	if parsed, err := time.Parse(time.RFC3339, latest); err == nil {
		return parsed.UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func firstNonEmptySnapshotValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func compactSnapshotStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
