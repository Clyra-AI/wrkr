package lifecycle

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
)

const defaultApprovalTTL = 90 * 24 * time.Hour

type ObservedTool struct {
	AgentID       string
	LegacyAgentID string
	ToolID        string
	ToolType      string
	Org           string
	Repo          string
	Location      string
	DataClass     string
	EndpointClass string
	AutonomyLevel string
	RiskScore     float64
}

type Transition struct {
	AgentID       string         `json:"agent_id" yaml:"agent_id"`
	PreviousState string         `json:"previous_state" yaml:"previous_state"`
	NewState      string         `json:"new_state" yaml:"new_state"`
	Trigger       string         `json:"trigger" yaml:"trigger"`
	Diff          map[string]any `json:"diff,omitempty" yaml:"diff,omitempty"`
	Timestamp     string         `json:"timestamp" yaml:"timestamp"`
}

type InventoryMutation struct {
	Action        string
	AgentID       string
	Owner         string
	EvidenceURL   string
	ControlID     string
	Reason        string
	ReviewCadence string
	ExpiresAt     time.Time
	Now           time.Time
}

func Reconcile(previous manifest.Manifest, observed []ObservedTool, now time.Time) (manifest.Manifest, []Transition) {
	now = canonicalNow(now)
	prevByID := map[string]manifest.IdentityRecord{}
	for _, record := range previous.Identities {
		prevByID[record.AgentID] = record
	}

	next := manifest.Manifest{Version: manifest.Version, UpdatedAt: now.Format(time.RFC3339), Identities: make([]manifest.IdentityRecord, 0, len(observed))}
	transitions := make([]Transition, 0)
	seen := map[string]struct{}{}
	legacyMigrated := map[string]struct{}{}

	sortedObserved := append([]ObservedTool(nil), observed...)
	sort.Slice(sortedObserved, func(i, j int) bool {
		if sortedObserved[i].AgentID != sortedObserved[j].AgentID {
			return sortedObserved[i].AgentID < sortedObserved[j].AgentID
		}
		if sortedObserved[i].Repo != sortedObserved[j].Repo {
			return sortedObserved[i].Repo < sortedObserved[j].Repo
		}
		return sortedObserved[i].Location < sortedObserved[j].Location
	})

	for _, tool := range sortedObserved {
		previousRecord, exists := prevByID[tool.AgentID]
		migratedFromLegacy := false
		legacyAgentID := strings.TrimSpace(tool.LegacyAgentID)
		if !exists && legacyAgentID != "" {
			if _, alreadyMigrated := legacyMigrated[legacyAgentID]; !alreadyMigrated {
				if legacyRecord, legacyExists := prevByID[legacyAgentID]; legacyExists {
					previousRecord = legacyRecord
					exists = true
					migratedFromLegacy = legacyAgentID != strings.TrimSpace(tool.AgentID)
					if migratedFromLegacy {
						legacyMigrated[legacyAgentID] = struct{}{}
					}
				}
			}
		}
		previousState := previousRecord.Status
		record := manifest.IdentityRecord{
			AgentID:       tool.AgentID,
			ToolID:        tool.ToolID,
			ToolType:      tool.ToolType,
			Org:           tool.Org,
			Repo:          tool.Repo,
			Location:      tool.Location,
			Approval:      previousRecord.Approval,
			FirstSeen:     fallbackTimestamp(previousRecord.FirstSeen, now),
			LastSeen:      now.Format(time.RFC3339),
			Present:       true,
			DataClass:     tool.DataClass,
			EndpointClass: tool.EndpointClass,
			AutonomyLevel: tool.AutonomyLevel,
			RiskScore:     tool.RiskScore,
		}

		trigger := ""
		diff := map[string]any{}
		if !exists {
			record.Status = identity.StateDiscovered
			record.ApprovalState = "missing"
			trigger = "first_seen"
		} else {
			record.Status = previousRecord.Status
			record.ApprovalState = previousRecord.ApprovalState
			if !previousRecord.Present {
				trigger = "reappeared"
			}
			if changed, details := detectContractDiff(previousRecord, record); changed {
				trigger = "modified"
				diff = details
			}
			if migratedFromLegacy {
				trigger = "identity_migrated"
				diff["legacy_agent_id"] = previousRecord.AgentID
			}
		}

		applyApprovalState(&record, now)
		if record.Status == identity.StateApproved && record.ApprovalState == "valid" {
			record.Status = identity.StateActive
		}
		if record.Status == identity.StateActive && record.ApprovalState != "valid" && record.ApprovalState != "accepted_risk" {
			record.Status = identity.StateUnderReview
		}
		if record.Status == identity.StateDiscovered && record.ApprovalState != "valid" {
			record.Status = identity.StateUnderReview
		}
		if record.Status == "" {
			record.Status = identity.StateUnderReview
		}
		if trigger == "" && exists && previousState != record.Status {
			trigger = "state_changed"
		}

		next.Identities = append(next.Identities, record)
		seen[tool.AgentID] = struct{}{}
		if exists {
			seen[previousRecord.AgentID] = struct{}{}
		}

		if trigger != "" {
			transitions = append(transitions, Transition{
				AgentID:       tool.AgentID,
				PreviousState: previousRecord.Status,
				NewState:      record.Status,
				Trigger:       trigger,
				Diff:          diff,
				Timestamp:     now.Format(time.RFC3339),
			})
		}
	}

	for _, previousRecord := range previous.Identities {
		if _, exists := seen[previousRecord.AgentID]; exists {
			continue
		}
		missing := previousRecord
		missing.Present = false
		next.Identities = append(next.Identities, missing)
		transitions = append(transitions, Transition{
			AgentID:       missing.AgentID,
			PreviousState: previousRecord.Status,
			NewState:      previousRecord.Status,
			Trigger:       "removed",
			Timestamp:     now.Format(time.RFC3339),
		})
	}

	sort.Slice(next.Identities, func(i, j int) bool { return next.Identities[i].AgentID < next.Identities[j].AgentID })
	sort.Slice(transitions, func(i, j int) bool {
		if transitions[i].AgentID != transitions[j].AgentID {
			return transitions[i].AgentID < transitions[j].AgentID
		}
		return transitions[i].Trigger < transitions[j].Trigger
	})
	return next, transitions
}

func ApplyInventoryMutation(m manifest.Manifest, mutation InventoryMutation) (manifest.Manifest, Transition, error) {
	now := canonicalNow(mutation.Now)
	agentID := strings.TrimSpace(mutation.AgentID)
	if agentID == "" {
		return manifest.Manifest{}, Transition{}, fmt.Errorf("identity id is required")
	}
	index := -1
	for i := range m.Identities {
		if strings.TrimSpace(m.Identities[i].AgentID) == agentID {
			index = i
			break
		}
	}
	if index < 0 {
		return manifest.Manifest{}, Transition{}, fmt.Errorf("identity %s not found", agentID)
	}

	record := m.Identities[index]
	previousState := record.Status
	diff := map[string]any{}
	action := strings.TrimSpace(mutation.Action)
	if action == "" {
		return manifest.Manifest{}, Transition{}, fmt.Errorf("inventory action is required")
	}
	if strings.TrimSpace(record.Approval.Owner) == "" && strings.TrimSpace(record.Approval.Approver) != "" {
		record.Approval.Owner = strings.TrimSpace(record.Approval.Approver)
	}

	switch action {
	case "approve":
		if strings.TrimSpace(mutation.Owner) == "" {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--owner is required")
		}
		if strings.TrimSpace(mutation.EvidenceURL) == "" {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--evidence is required")
		}
		if mutation.ExpiresAt.IsZero() {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--expires is required")
		}
		record.Status = identity.StateActive
		record.ApprovalState = "valid"
		record.Approval.Approver = strings.TrimSpace(mutation.Owner)
		record.Approval.Owner = strings.TrimSpace(mutation.Owner)
		record.Approval.Scope = fallback(record.Approval.Scope, "control_path")
		record.Approval.EvidenceURL = strings.TrimSpace(mutation.EvidenceURL)
		record.Approval.ControlID = strings.TrimSpace(mutation.ControlID)
		record.Approval.Approved = now.Format(time.RFC3339)
		record.Approval.Expires = mutation.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339)
		record.Approval.ReviewCadence = fallback(strings.TrimSpace(mutation.ReviewCadence), "90d")
		record.Approval.LastReviewed = now.Format(time.RFC3339)
		record.Approval.RenewalState = renewalState(mutation.ExpiresAt, now)
		record.Approval.AcceptedRisk = false
		record.Approval.DecisionReason = ""
		record.Approval.ExclusionReason = ""
		diff["owner"] = strings.TrimSpace(mutation.Owner)
		diff["evidence_url"] = strings.TrimSpace(mutation.EvidenceURL)
		diff["expires"] = record.Approval.Expires
		diff["review_cadence"] = record.Approval.ReviewCadence
		if strings.TrimSpace(mutation.ControlID) != "" {
			diff["control_id"] = strings.TrimSpace(mutation.ControlID)
		}
	case "attach_evidence":
		if strings.TrimSpace(mutation.ControlID) == "" {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--control is required")
		}
		if strings.TrimSpace(mutation.EvidenceURL) == "" {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--url is required")
		}
		record.Approval.ControlID = strings.TrimSpace(mutation.ControlID)
		record.Approval.EvidenceURL = strings.TrimSpace(mutation.EvidenceURL)
		record.Approval.LastReviewed = now.Format(time.RFC3339)
		if strings.TrimSpace(mutation.Owner) != "" {
			record.Approval.Owner = strings.TrimSpace(mutation.Owner)
		}
		diff["control_id"] = strings.TrimSpace(mutation.ControlID)
		diff["evidence_url"] = strings.TrimSpace(mutation.EvidenceURL)
	case "accept_risk":
		if mutation.ExpiresAt.IsZero() {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--expires is required")
		}
		record.Status = identity.StateActive
		record.ApprovalState = "accepted_risk"
		record.Approval.AcceptedRisk = true
		record.Approval.Approved = now.Format(time.RFC3339)
		record.Approval.Expires = mutation.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339)
		record.Approval.LastReviewed = now.Format(time.RFC3339)
		record.Approval.RenewalState = renewalState(mutation.ExpiresAt, now)
		record.Approval.DecisionReason = strings.TrimSpace(mutation.Reason)
		record.Approval.ExclusionReason = ""
		diff["expires"] = record.Approval.Expires
		diff["accepted_risk"] = true
		if strings.TrimSpace(mutation.Reason) != "" {
			diff["reason"] = strings.TrimSpace(mutation.Reason)
		}
	case "deprecate":
		if strings.TrimSpace(mutation.Reason) == "" {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--reason is required")
		}
		record.Status = identity.StateDeprecated
		record.ApprovalState = "deprecated"
		record.Approval.AcceptedRisk = false
		record.Approval.Expires = ""
		record.Approval.DecisionReason = strings.TrimSpace(mutation.Reason)
		record.Approval.LastReviewed = now.Format(time.RFC3339)
		record.Approval.RenewalState = "not_applicable"
		diff["reason"] = strings.TrimSpace(mutation.Reason)
	case "exclude":
		if strings.TrimSpace(mutation.Reason) == "" {
			return manifest.Manifest{}, Transition{}, fmt.Errorf("--reason is required")
		}
		record.Status = identity.StateRevoked
		record.ApprovalState = "excluded"
		record.Approval.AcceptedRisk = false
		record.Approval.Expires = ""
		record.Approval.ExclusionReason = strings.TrimSpace(mutation.Reason)
		record.Approval.LastReviewed = now.Format(time.RFC3339)
		record.Approval.RenewalState = "not_applicable"
		diff["reason"] = strings.TrimSpace(mutation.Reason)
	default:
		return manifest.Manifest{}, Transition{}, fmt.Errorf("unsupported inventory action %q", action)
	}

	record.LastSeen = now.Format(time.RFC3339)
	m.Identities[index] = record
	m.UpdatedAt = now.Format(time.RFC3339)
	m.ApprovalInventoryVersion = manifest.ApprovalInventoryVersion

	transition := Transition{
		AgentID:       record.AgentID,
		PreviousState: previousState,
		NewState:      record.Status,
		Trigger:       "inventory_" + action,
		Timestamp:     now.Format(time.RFC3339),
		Diff:          diff,
	}
	return m, transition, nil
}

func ApplyManualState(m manifest.Manifest, agentID, state, approver, scope, reason string, expiresAt time.Time, now time.Time) (manifest.Manifest, Transition, error) {
	now = canonicalNow(now)
	if !identity.IsValidState(state) {
		return manifest.Manifest{}, Transition{}, fmt.Errorf("invalid lifecycle state %q", state)
	}

	index := -1
	for i := range m.Identities {
		if m.Identities[i].AgentID == agentID {
			index = i
			break
		}
	}
	if index < 0 {
		return manifest.Manifest{}, Transition{}, fmt.Errorf("identity %s not found", agentID)
	}

	record := m.Identities[index]
	previousState := record.Status
	record.Status = state
	switch state {
	case identity.StateApproved, identity.StateActive:
		record.Approval = manifest.Approval{
			Approver: strings.TrimSpace(approver),
			Scope:    strings.TrimSpace(scope),
			Approved: now.Format(time.RFC3339),
			Expires:  expiresAt.UTC().Format(time.RFC3339),
		}
		record.ApprovalState = "valid"
	case identity.StateRevoked, identity.StateDeprecated, identity.StateUnderReview:
		record.Approval = manifest.Approval{}
		record.ApprovalState = "revoked"
	}
	record.LastSeen = now.Format(time.RFC3339)
	m.Identities[index] = record
	m.UpdatedAt = now.Format(time.RFC3339)

	transition := Transition{
		AgentID:       record.AgentID,
		PreviousState: previousState,
		NewState:      record.Status,
		Trigger:       "manual_transition",
		Timestamp:     now.Format(time.RFC3339),
		Diff:          map[string]any{},
	}
	if strings.TrimSpace(reason) != "" {
		transition.Diff["reason"] = strings.TrimSpace(reason)
	}
	if strings.TrimSpace(approver) != "" {
		transition.Diff["approver"] = strings.TrimSpace(approver)
	}
	if strings.TrimSpace(scope) != "" {
		transition.Diff["scope"] = strings.TrimSpace(scope)
	}
	if !expiresAt.IsZero() {
		transition.Diff["expires"] = expiresAt.UTC().Format(time.RFC3339)
	}
	return m, transition, nil
}

func ParseExpiry(raw string, now time.Time) (time.Time, error) {
	now = canonicalNow(now)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return now.Add(defaultApprovalTTL), nil
	}
	if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
		return parsed.UTC().Truncate(time.Second), nil
	}
	if parsed, err := time.Parse("2006-01-02", trimmed); err == nil {
		return parsed.UTC(), nil
	}
	if strings.HasSuffix(trimmed, "d") {
		days := strings.TrimSuffix(trimmed, "d")
		value, err := strconv.Atoi(days)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse expiry %q: %w", raw, err)
		}
		if value <= 0 {
			return time.Time{}, fmt.Errorf("parse expiry %q: days must be positive", raw)
		}
		return now.Add(time.Duration(value) * 24 * time.Hour), nil
	}
	dur, err := time.ParseDuration(trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse expiry %q: %w", raw, err)
	}
	return now.Add(dur), nil
}

func applyApprovalState(record *manifest.IdentityRecord, now time.Time) {
	if strings.TrimSpace(record.Approval.ExclusionReason) != "" {
		record.ApprovalState = "excluded"
		record.Status = identity.StateRevoked
		return
	}
	record.ApprovalState = "missing"
	if strings.TrimSpace(record.Approval.Expires) == "" {
		if record.Status == identity.StateDeprecated && strings.TrimSpace(record.Approval.DecisionReason) != "" {
			record.ApprovalState = "deprecated"
		}
		return
	}
	expiresAt, err := time.Parse(time.RFC3339, record.Approval.Expires)
	if err != nil {
		record.ApprovalState = "invalid"
		return
	}
	if expiresAt.Before(now) {
		record.ApprovalState = "expired"
		record.Status = identity.StateUnderReview
		return
	}
	if record.Approval.AcceptedRisk {
		record.ApprovalState = "accepted_risk"
		record.Status = identity.StateActive
		return
	}
	record.ApprovalState = "valid"
	if record.Status == identity.StateApproved {
		record.Status = identity.StateActive
	}
}

func renewalState(expiresAt time.Time, now time.Time) string {
	if expiresAt.IsZero() {
		return "missing"
	}
	if !expiresAt.After(canonicalNow(now)) {
		return "expired"
	}
	if expiresAt.Sub(canonicalNow(now)) <= 14*24*time.Hour {
		return "renewal_due"
	}
	return "current"
}

func detectContractDiff(previous, current manifest.IdentityRecord) (bool, map[string]any) {
	diff := map[string]any{}
	if previous.DataClass != current.DataClass {
		diff["data_class"] = map[string]string{"previous": previous.DataClass, "current": current.DataClass}
	}
	if previous.EndpointClass != current.EndpointClass {
		diff["endpoint_class"] = map[string]string{"previous": previous.EndpointClass, "current": current.EndpointClass}
	}
	if previous.AutonomyLevel != current.AutonomyLevel {
		diff["autonomy_level"] = map[string]string{"previous": previous.AutonomyLevel, "current": current.AutonomyLevel}
	}
	return len(diff) > 0, diff
}

func fallbackTimestamp(value string, now time.Time) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return now.Format(time.RFC3339)
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallbackValue
}

func canonicalNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC().Truncate(time.Second)
	}
	return now.UTC().Truncate(time.Second)
}
