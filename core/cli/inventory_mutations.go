package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runInventoryMutation(action string, args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	preID := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		preID = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("inventory "+action, flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	owner := fs.String("owner", "", "owning team or reviewer")
	evidenceRef := fs.String("evidence", "", "approval evidence ticket or URL")
	evidenceURL := fs.String("url", "", "evidence URL")
	controlID := fs.String("control", "", "governance control id")
	expires := fs.String("expires", "", "approval or accepted-risk expiry duration, RFC3339 timestamp, or YYYY-MM-DD date")
	reason := fs.String("reason", "", "deterministic lifecycle reason")
	reviewCadence := fs.String("review-cadence", "90d", "review cadence for approved inventory entries")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	id := strings.TrimSpace(preID)
	if id == "" {
		if fs.NArg() != 1 {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "inventory item id is required", exitInvalidInput)
		}
		id = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "inventory item id is required", exitInvalidInput)
	}

	now := time.Now().UTC().Truncate(time.Second)
	mutation := lifecycle.InventoryMutation{
		Action:        action,
		Owner:         strings.TrimSpace(*owner),
		ControlID:     strings.TrimSpace(*controlID),
		Reason:        strings.TrimSpace(*reason),
		ReviewCadence: strings.TrimSpace(*reviewCadence),
		Now:           now,
	}
	switch action {
	case "approve":
		mutation.EvidenceURL = strings.TrimSpace(*evidenceRef)
		if err := validateEvidenceOrTicket(mutation.EvidenceURL); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		expiresAt, err := parseRequiredFutureExpiry(*expires, now)
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		mutation.ExpiresAt = expiresAt
	case "attach_evidence":
		mutation.EvidenceURL = strings.TrimSpace(*evidenceURL)
		if err := validateEvidenceURL(mutation.EvidenceURL); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
	case "accept_risk":
		expiresAt, err := parseRequiredFutureExpiry(*expires, now)
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		mutation.ExpiresAt = expiresAt
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	ctx, err := loadStateMutationContext(resolvedStatePath)
	if err != nil {
		return emitStateMutationError(stderr, jsonRequested || *jsonOut, err)
	}

	agentID, resolveErr := resolveInventoryMutationAgentID(id, ctx.manifest, ctx.snapshot)
	if resolveErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", resolveErr.Error(), exitInvalidInput)
	}
	mutation.AgentID = agentID
	nextManifest, transition, transitionErr := lifecycle.ApplyInventoryMutation(ctx.manifest, mutation)
	if transitionErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", transitionErr.Error(), exitInvalidInput)
	}
	updatedRecord, ok := findManifestIdentity(nextManifest, agentID)
	if !ok {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", "updated identity record missing after mutation", exitRuntime)
	}
	if err := applyStateMutationToSnapshot(&ctx.snapshot, nextManifest, transition); err != nil {
		return emitStateMutationError(stderr, jsonRequested || *jsonOut, err)
	}
	if err := lifecycle.AppendTransitionRecord(ctx.lifecycleChain, transition, eventTypeForInventoryAction(action)); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	ctx.manifest = nextManifest
	if err := commitStateMutationContext(ctx, transition, eventTypeForInventoryAction(action)); err != nil {
		return emitStateMutationError(stderr, jsonRequested || *jsonOut, err)
	}

	payload := map[string]any{
		"status":                     "ok",
		"approval_inventory_version": manifest.ApprovalInventoryVersion,
		"action":                     action,
		"identity":                   updatedRecord,
		"transition":                 transition,
		"state_path":                 ctx.preflight.statePath,
		"manifest_path":              ctx.preflight.manifestPath,
		"proof_chain_path":           ctx.preflight.proofChainPath,
	}
	if jsonRequested || *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr inventory %s %s\n", action, agentID)
	return exitSuccess
}

type stateMutationPreflight struct {
	statePath            string
	manifestPath         string
	lifecyclePath        string
	proofChainPath       string
	proofAttestationPath string
	signingKeyPath       string
}

func preflightStateMutationArtifacts(statePathRaw string) (stateMutationPreflight, error) {
	statePath, err := preflightTrustedStatePath(statePathRaw)
	if err != nil {
		return stateMutationPreflight{}, err
	}
	manifestPath, err := normalizeManagedArtifactPath(manifest.ResolvePath(statePath))
	if err != nil {
		return stateMutationPreflight{}, err
	}
	lifecyclePath, err := normalizeManagedArtifactPath(lifecycle.ChainPath(statePath))
	if err != nil {
		return stateMutationPreflight{}, err
	}
	proofChainPath, err := normalizeManagedArtifactPath(proofemit.ChainPath(statePath))
	if err != nil {
		return stateMutationPreflight{}, err
	}
	proofAttestationPath, err := normalizeManagedArtifactPath(proofemit.ChainAttestationPath(proofChainPath))
	if err != nil {
		return stateMutationPreflight{}, err
	}
	signingKeyPath, err := normalizeManagedArtifactPath(proofemit.SigningKeyPath(statePath))
	if err != nil {
		return stateMutationPreflight{}, err
	}
	entries := []scanArtifactPathEntry{}
	for _, item := range []struct {
		label string
		path  string
	}{
		{label: "--state", path: statePath},
		{label: "manifest", path: manifestPath},
		{label: "lifecycle chain", path: lifecyclePath},
		{label: "proof chain", path: proofChainPath},
		{label: "proof attestation", path: proofAttestationPath},
		{label: "proof signing key", path: signingKeyPath},
	} {
		entry, entryErr := newScanArtifactPathEntry(item.label, item.path)
		if entryErr != nil {
			return stateMutationPreflight{}, entryErr
		}
		entries = append(entries, entry)
		if err := rejectUnsafeExistingMutationArtifact(item.path); err != nil {
			return stateMutationPreflight{}, err
		}
	}
	if err := detectScanArtifactPathCollisions(entries); err != nil {
		return stateMutationPreflight{}, err
	}
	return stateMutationPreflight{
		statePath:            statePath,
		manifestPath:         manifestPath,
		lifecyclePath:        lifecyclePath,
		proofChainPath:       proofChainPath,
		proofAttestationPath: proofAttestationPath,
		signingKeyPath:       signingKeyPath,
	}, nil
}

func rejectUnsafeExistingMutationArtifact(path string) error {
	return rejectUnsafeExistingManagedFile(path, "managed mutation artifact")
}

func resolveInventoryMutationAgentID(id string, m manifest.Manifest, snapshot state.Snapshot) (string, error) {
	trimmed := strings.TrimSpace(id)
	if trimmed == "" {
		return "", fmt.Errorf("inventory item id is required")
	}
	exactAgentMatches := map[string]struct{}{}
	for _, record := range m.Identities {
		if strings.TrimSpace(record.AgentID) == trimmed {
			exactAgentMatches[strings.TrimSpace(record.AgentID)] = struct{}{}
		}
	}
	if snapshot.Inventory != nil {
		for _, tool := range snapshot.Inventory.Tools {
			if strings.TrimSpace(tool.AgentID) == trimmed {
				exactAgentMatches[strings.TrimSpace(tool.AgentID)] = struct{}{}
			}
		}
	}
	if agentID, ok := singleAgentMatch(exactAgentMatches); ok {
		return agentID, nil
	}

	toolIDMatches := map[string]struct{}{}
	for _, record := range m.Identities {
		if strings.TrimSpace(record.ToolID) == trimmed && strings.TrimSpace(record.AgentID) != "" {
			toolIDMatches[strings.TrimSpace(record.AgentID)] = struct{}{}
		}
	}
	if snapshot.Inventory != nil {
		for _, tool := range snapshot.Inventory.Tools {
			if strings.TrimSpace(tool.ToolID) == trimmed && strings.TrimSpace(tool.AgentID) != "" {
				toolIDMatches[strings.TrimSpace(tool.AgentID)] = struct{}{}
			}
		}
	}
	if len(toolIDMatches) > 1 {
		return "", fmt.Errorf("inventory item %s is ambiguous; use an explicit agent_id", trimmed)
	}
	if agentID, ok := singleAgentMatch(toolIDMatches); ok {
		return agentID, nil
	}

	if snapshot.ControlBacklog != nil {
		for _, item := range snapshot.ControlBacklog.Items {
			if strings.TrimSpace(item.ID) != trimmed {
				continue
			}
			if agentID := agentIDForInventoryPath(snapshot, item.Repo, item.Path); agentID != "" {
				return agentID, nil
			}
		}
	}
	return "", fmt.Errorf("inventory item %s not found", trimmed)
}

func singleAgentMatch(matches map[string]struct{}) (string, bool) {
	if len(matches) != 1 {
		return "", false
	}
	for agentID := range matches {
		return agentID, true
	}
	return "", false
}

func findManifestIdentity(m manifest.Manifest, agentID string) (manifest.IdentityRecord, bool) {
	for _, record := range m.Identities {
		if strings.TrimSpace(record.AgentID) == strings.TrimSpace(agentID) {
			return record, true
		}
	}
	return manifest.IdentityRecord{}, false
}

func summarizeBacklogItems(items []controlbacklog.Item) controlbacklog.Summary {
	summary := controlbacklog.Summary{TotalItems: len(items)}
	for _, item := range items {
		switch strings.TrimSpace(item.SignalClass) {
		case controlbacklog.SignalClassUniqueWrkrSignal:
			summary.UniqueWrkrSignalItems++
		case controlbacklog.SignalClassSupportingSecurity:
			summary.SupportingSecurityItems++
		}
		switch strings.TrimSpace(item.RecommendedAction) {
		case controlbacklog.ActionAttachEvidence:
			summary.AttachEvidenceActionItems++
		case controlbacklog.ActionApprove:
			summary.ApproveActionItems++
		case controlbacklog.ActionRemediate:
			summary.RemediateActionItems++
		}
	}
	return summary
}

func agentIDForInventoryPath(snapshot state.Snapshot, repo string, path string) string {
	if snapshot.Inventory != nil {
		for _, tool := range snapshot.Inventory.Tools {
			for _, loc := range tool.Locations {
				if strings.TrimSpace(loc.Repo) == strings.TrimSpace(repo) && strings.TrimSpace(loc.Location) == strings.TrimSpace(path) {
					return strings.TrimSpace(tool.AgentID)
				}
			}
		}
	}
	for _, record := range snapshot.Identities {
		if strings.TrimSpace(record.Repo) == strings.TrimSpace(repo) && strings.TrimSpace(record.Location) == strings.TrimSpace(path) {
			return strings.TrimSpace(record.AgentID)
		}
	}
	return ""
}

func eventTypeForInventoryAction(action string) string {
	switch strings.TrimSpace(action) {
	case "approve":
		return "approval_recorded"
	case "attach_evidence":
		return "evidence_attached"
	case "accept_risk":
		return "risk_accepted"
	default:
		return "lifecycle_transition"
	}
}

func parseRequiredFutureExpiry(raw string, now time.Time) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, fmt.Errorf("--expires is required")
	}
	expiresAt, err := lifecycle.ParseExpiry(raw, now)
	if err != nil {
		return time.Time{}, err
	}
	if !expiresAt.After(now) {
		return time.Time{}, fmt.Errorf("expiry must be in the future")
	}
	return expiresAt, nil
}

func validateEvidenceOrTicket(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("--evidence is required")
	}
	if strings.Contains(trimmed, "://") {
		return validateEvidenceURL(trimmed)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		return fmt.Errorf("evidence ticket must not contain whitespace")
	}
	return nil
}

func validateEvidenceURL(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("evidence URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("invalid evidence URL: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https", "file":
		if parsed.Scheme != "file" && strings.TrimSpace(parsed.Host) == "" {
			return fmt.Errorf("invalid evidence URL: host is required")
		}
		return nil
	default:
		return fmt.Errorf("invalid evidence URL scheme %q", parsed.Scheme)
	}
}
