package lifecycle

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
)

const defaultApprovalTTL = 90 * 24 * time.Hour

type ObservedTool struct {
	AgentID       string
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

func Reconcile(previous manifest.Manifest, observed []ObservedTool, now time.Time) (manifest.Manifest, []Transition) {
	now = canonicalNow(now)
	prevByID := map[string]manifest.IdentityRecord{}
	for _, record := range previous.Identities {
		prevByID[record.AgentID] = record
	}

	next := manifest.Manifest{Version: manifest.Version, UpdatedAt: now.Format(time.RFC3339), Identities: make([]manifest.IdentityRecord, 0, len(observed))}
	transitions := make([]Transition, 0)
	seen := map[string]struct{}{}

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
		}

		applyApprovalState(&record, now)
		if record.Status == identity.StateApproved && record.ApprovalState == "valid" {
			record.Status = identity.StateActive
		}
		if record.Status == identity.StateActive && record.ApprovalState != "valid" {
			record.Status = identity.StateUnderReview
		}
		if record.Status == identity.StateDiscovered && record.ApprovalState != "valid" {
			record.Status = identity.StateUnderReview
		}
		if record.Status == "" {
			record.Status = identity.StateUnderReview
		}

		next.Identities = append(next.Identities, record)
		seen[tool.AgentID] = struct{}{}

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
		if strings.TrimSpace(reason) != "" {
			record.ApprovalState = "revoked"
		}
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
		Diff: map[string]any{
			"reason": strings.TrimSpace(reason),
		},
	}
	return m, transition, nil
}

func ParseExpiry(raw string, now time.Time) (time.Time, error) {
	now = canonicalNow(now)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return now.Add(defaultApprovalTTL), nil
	}
	if strings.HasSuffix(trimmed, "d") {
		days := strings.TrimSuffix(trimmed, "d")
		value, err := time.ParseDuration(days + "24h")
		if err != nil {
			return time.Time{}, fmt.Errorf("parse expiry %q: %w", raw, err)
		}
		return now.Add(value), nil
	}
	dur, err := time.ParseDuration(trimmed)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse expiry %q: %w", raw, err)
	}
	return now.Add(dur), nil
}

func applyApprovalState(record *manifest.IdentityRecord, now time.Time) {
	record.ApprovalState = "missing"
	if strings.TrimSpace(record.Approval.Expires) == "" {
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
	record.ApprovalState = "valid"
	if record.Status == identity.StateApproved {
		record.Status = identity.StateActive
	}
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

func canonicalNow(now time.Time) time.Time {
	if now.IsZero() {
		return time.Now().UTC().Truncate(time.Second)
	}
	return now.UTC().Truncate(time.Second)
}
