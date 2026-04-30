package report

import (
	"fmt"
	"sort"
	"strings"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/state"
)

type ControlProofStatus struct {
	LinkedActionPathID string   `json:"linked_action_path_id,omitempty"`
	Repo               string   `json:"repo,omitempty"`
	Path               string   `json:"path,omitempty"`
	ControlID          string   `json:"control_id"`
	BacklogItemID      string   `json:"backlog_item_id"`
	AgentID            string   `json:"agent_id,omitempty"`
	Status             string   `json:"status"`
	ExistingProof      []string `json:"existing_proof,omitempty"`
	MissingProof       []string `json:"missing_proof,omitempty"`
	RecordIDs          []string `json:"record_ids,omitempty"`
}

func BuildControlProofStatus(snapshot state.Snapshot, chain *proof.Chain) []ControlProofStatus {
	if chain == nil || snapshot.ControlBacklog == nil || len(snapshot.ControlBacklog.Items) == 0 {
		return nil
	}

	agentIDsByPath := actionPathAgentIDs(snapshot)
	out := make([]ControlProofStatus, 0, len(snapshot.ControlBacklog.Items))
	for _, item := range snapshot.ControlBacklog.Items {
		controlID := primaryControlID(item.GovernanceControls)
		agentID := agentIDForBacklogItem(snapshot, agentIDsByPath, item)
		requirements := proofRequirementsForBacklogItem(item.RecommendedAction, item.ClosureCriteria, item.WritePathClasses, item.SecretSignalTypes)
		existing, recordIDs := existingProofForRequirements(requirements, controlID, agentID, chain.Records)
		missing := differenceStrings(requirements, existing)
		status := "satisfied"
		if len(missing) > 0 {
			status = "missing"
		}
		out = append(out, ControlProofStatus{
			LinkedActionPathID: strings.TrimSpace(item.LinkedActionPathID),
			Repo:               strings.TrimSpace(item.Repo),
			Path:               strings.TrimSpace(item.Path),
			ControlID:          controlID,
			BacklogItemID:      strings.TrimSpace(item.ID),
			AgentID:            agentID,
			Status:             status,
			ExistingProof:      existing,
			MissingProof:       missing,
			RecordIDs:          recordIDs,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].LinkedActionPathID != out[j].LinkedActionPathID {
			return out[i].LinkedActionPathID < out[j].LinkedActionPathID
		}
		if out[i].ControlID != out[j].ControlID {
			return out[i].ControlID < out[j].ControlID
		}
		return out[i].BacklogItemID < out[j].BacklogItemID
	})
	return out
}

func actionPathAgentIDs(snapshot state.Snapshot) map[string]string {
	out := map[string]string{}
	if snapshot.RiskReport == nil {
		return out
	}
	for _, path := range snapshot.RiskReport.ActionPaths {
		pathID := strings.TrimSpace(path.PathID)
		agentID := strings.TrimSpace(path.AgentID)
		if pathID == "" || agentID == "" {
			continue
		}
		out[pathID] = agentID
	}
	return out
}

func primaryControlID(controls []agginventory.GovernanceControlMapping) string {
	values := make([]string, 0, len(controls))
	for _, item := range controls {
		control := strings.TrimSpace(item.Control)
		if control != "" {
			values = append(values, control)
		}
	}
	sort.Strings(values)
	if len(values) == 0 {
		return "control_path_governance"
	}
	return values[0]
}

func proofRequirementsForBacklogItem(action, closure string, writeClasses []string, secretSignals []string) []string {
	requirements := []string{
		agginventory.GovernanceControlOwnerAssigned,
		agginventory.GovernanceControlApproval,
		agginventory.GovernanceControlReviewCadence,
	}
	if strings.TrimSpace(action) == "attach_evidence" || strings.Contains(strings.ToLower(closure), "proof") {
		requirements = append(requirements, "evidence_attached", agginventory.GovernanceControlProof)
	}
	for _, class := range writeClasses {
		switch strings.TrimSpace(class) {
		case agginventory.WritePathRepoWrite, agginventory.WritePathPullRequestWrite, agginventory.WritePathReleaseWrite, agginventory.WritePathPackagePublish, agginventory.WritePathDeployWrite, agginventory.WritePathInfraWrite:
			requirements = append(requirements, agginventory.GovernanceControlLeastPrivilege)
		case agginventory.WritePathProductionAdjacent:
			requirements = append(requirements, agginventory.GovernanceControlProduction)
		}
		if strings.TrimSpace(class) == agginventory.WritePathDeployWrite || strings.TrimSpace(class) == agginventory.WritePathReleaseWrite {
			requirements = append(requirements, agginventory.GovernanceControlDeploymentGate)
		}
	}
	for _, signal := range secretSignals {
		if strings.TrimSpace(signal) == "secret_rotation_evidence_missing" {
			requirements = append(requirements, agginventory.GovernanceControlRotation)
		}
	}
	return uniqueSortedStrings(requirements)
}

func existingProofForRequirements(requirements []string, controlID string, agentID string, records []proof.Record) ([]string, []string) {
	existing := map[string]struct{}{}
	recordIDs := map[string]struct{}{}
	for _, record := range records {
		for _, requirement := range requirements {
			if !recordSatisfiesProofRequirement(record, requirement, controlID, agentID) {
				continue
			}
			existing[requirement] = struct{}{}
			if strings.TrimSpace(record.RecordID) != "" {
				recordIDs[strings.TrimSpace(record.RecordID)] = struct{}{}
			}
		}
	}
	return sortedStringKeys(existing), sortedStringKeys(recordIDs)
}

func recordSatisfiesProofRequirement(record proof.Record, requirement string, controlID string, agentID string) bool {
	if strings.TrimSpace(agentID) != "" && strings.TrimSpace(record.AgentID) != "" && strings.TrimSpace(record.AgentID) != strings.TrimSpace(agentID) {
		return false
	}
	eventType := eventString(record.Event, "event_type")
	if eventType == "" && record.Metadata != nil {
		eventType = metadataString(record.Metadata, "event_type")
	}
	if eventType == "" {
		eventType = strings.TrimSpace(record.RecordType)
	}
	recordControlID := eventString(record.Event, "control_id")
	if recordControlID == "" {
		if diff, ok := record.Event["diff"].(map[string]any); ok {
			recordControlID = stringFromAny(diff["control_id"])
		}
	}
	controlMatches := strings.TrimSpace(controlID) == "" || strings.TrimSpace(controlID) == "control_path_governance" || strings.TrimSpace(recordControlID) == "" || strings.TrimSpace(recordControlID) == strings.TrimSpace(controlID)
	if !controlMatches {
		return false
	}
	switch requirement {
	case agginventory.GovernanceControlOwnerAssigned:
		return eventType == "owner_assigned" || eventString(record.Event, "owner") != "" || eventString(record.Event, "approver") != ""
	case agginventory.GovernanceControlReviewCadence:
		return eventType == "review_cadence_set" || eventString(record.Event, "review_cadence") != ""
	case agginventory.GovernanceControlApproval:
		return eventType == "approval_recorded" || eventType == "approval" || strings.TrimSpace(record.RecordType) == "approval"
	case "evidence_attached":
		return eventType == "evidence_attached" || eventString(record.Event, "evidence_url") != ""
	default:
		return eventType == requirement
	}
}

func agentIDForBacklogItem(snapshot state.Snapshot, agentIDsByPath map[string]string, item controlbacklog.Item) string {
	linkedPathID := strings.TrimSpace(item.LinkedActionPathID)
	if linkedPathID != "" {
		if agentID := strings.TrimSpace(agentIDsByPath[linkedPathID]); agentID != "" {
			return agentID
		}
	}
	if snapshot.Inventory != nil {
		for _, tool := range snapshot.Inventory.Tools {
			if strings.TrimSpace(tool.AgentID) == "" {
				continue
			}
			for _, loc := range tool.Locations {
				if strings.TrimSpace(loc.Repo) == strings.TrimSpace(item.Repo) && strings.TrimSpace(loc.Location) == strings.TrimSpace(item.Path) {
					return strings.TrimSpace(tool.AgentID)
				}
			}
		}
	}
	for _, identity := range snapshot.Identities {
		if strings.TrimSpace(identity.Repo) == strings.TrimSpace(item.Repo) && strings.TrimSpace(identity.Location) == strings.TrimSpace(item.Path) {
			return strings.TrimSpace(identity.AgentID)
		}
	}
	return ""
}

func differenceStrings(all []string, existing []string) []string {
	have := map[string]struct{}{}
	for _, value := range existing {
		have[strings.TrimSpace(value)] = struct{}{}
	}
	missing := map[string]struct{}{}
	for _, value := range all {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := have[trimmed]; !ok {
			missing[trimmed] = struct{}{}
		}
	}
	return sortedStringKeys(missing)
}

func sortedStringKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	sort.Strings(out)
	return out
}

func eventString(event map[string]any, key string) string {
	if event == nil {
		return ""
	}
	return stringFromAny(event[key])
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	return stringFromAny(metadata[key])
}

func stringFromAny(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}
