package cli

import (
	"fmt"
	"io"
	"strings"

	proof "github.com/Clyra-AI/proof"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profilemodel "github.com/Clyra-AI/wrkr/core/policy/profile"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/state"
)

type stateMutationContext struct {
	preflight      stateMutationPreflight
	snapshot       state.Snapshot
	manifest       manifest.Manifest
	lifecycleChain *proof.Chain
}

func loadStateMutationContext(statePathRaw string) (stateMutationContext, error) {
	preflight, err := preflightStateMutationArtifacts(statePathRaw)
	if err != nil {
		if isUnsafeManagedArtifactPathError(err) {
			return stateMutationContext{}, err
		}
		return stateMutationContext{}, unsafeManagedArtifactPathError{err: err}
	}
	snapshot, err := state.Load(preflight.statePath)
	if err != nil {
		return stateMutationContext{}, err
	}
	loadedManifest, err := manifest.Load(preflight.manifestPath)
	if err != nil {
		return stateMutationContext{}, err
	}
	loadedManifest.Identities = model.FilterLegacyArtifactIdentityRecords(loadedManifest.Identities)
	lifecycleChain, err := lifecycle.LoadChain(preflight.lifecyclePath)
	if err != nil {
		return stateMutationContext{}, err
	}
	if _, err := proofemit.LoadChain(preflight.proofChainPath); err != nil {
		return stateMutationContext{}, err
	}
	return stateMutationContext{
		preflight:      preflight,
		snapshot:       snapshot,
		manifest:       loadedManifest,
		lifecycleChain: lifecycleChain,
	}, nil
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
	}
	actionPaths := []risk.ActionPath(nil)
	var controlPathGraph *aggattack.ControlPathGraph
	if snapshot.RiskReport != nil && snapshot.Inventory != nil {
		snapshot.RiskReport.ActionPaths, snapshot.RiskReport.ActionPathToControlFirst = risk.BuildActionPaths(snapshot.RiskReport.AttackPaths, snapshot.Inventory)
		snapshot.RiskReport.ControlPathGraph = risk.BuildControlPathGraph(snapshot.RiskReport.ActionPaths)
		actionPaths = snapshot.RiskReport.ActionPaths
		controlPathGraph = snapshot.RiskReport.ControlPathGraph
	}
	if snapshot.ControlBacklog != nil && len(snapshot.Findings) == 0 && len(actionPaths) == 0 {
		refreshExistingControlBacklog(snapshot)
	} else if snapshot.Inventory != nil || snapshot.ControlBacklog != nil {
		backlog := controlbacklog.Build(controlbacklog.Input{
			Mode:             snapshot.ScanMode,
			Findings:         snapshot.Findings,
			Inventory:        snapshot.Inventory,
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
		Identities:      model.FilterLegacyArtifactIdentityRecords(snapshot.Identities),
		ProfileResult:   profileResult,
		TransitionCount: driftTransitionCount(snapshot.Transitions),
		Weights:         weights,
		Previous:        previous,
	})
	snapshot.PostureScore = &computed
	return nil
}

func commitStateMutationContext(ctx stateMutationContext, transition lifecycle.Transition, eventType string) error {
	snapshots, err := captureManagedArtifacts(
		ctx.preflight.statePath,
		ctx.preflight.manifestPath,
		ctx.preflight.lifecyclePath,
		ctx.preflight.proofChainPath,
		ctx.preflight.proofAttestationPath,
		ctx.preflight.signingKeyPath,
	)
	if err != nil {
		return unsafeManagedArtifactPathError{err: err}
	}
	if err := state.Save(ctx.preflight.statePath, ctx.snapshot); err != nil {
		return rollbackStateMutationError(err, snapshots)
	}
	if err := lifecycle.SaveChain(ctx.preflight.lifecyclePath, ctx.lifecycleChain); err != nil {
		return rollbackStateMutationError(err, snapshots)
	}
	if err := proofemit.EmitIdentityTransition(ctx.preflight.statePath, transition, eventType); err != nil {
		return rollbackStateMutationError(err, snapshots)
	}
	if err := manifest.Save(ctx.preflight.manifestPath, ctx.manifest); err != nil {
		return rollbackStateMutationError(err, snapshots)
	}
	return nil
}

func rollbackStateMutationError(actionErr error, snapshots []managedArtifactSnapshot) error {
	if restoreErr := restoreManagedArtifacts(snapshots); restoreErr != nil {
		return fmt.Errorf("%v (rollback restore failed: %v)", actionErr, restoreErr)
	}
	return actionErr
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
		if backlogItemMatchesRecord(item.ID, item.Repo, item.Path, requestedID, record) {
			continue
		}
		items = append(items, item)
	}
	snapshot.ControlBacklog.Items = items
	snapshot.ControlBacklog.Summary = summarizeBacklogItems(items)
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
