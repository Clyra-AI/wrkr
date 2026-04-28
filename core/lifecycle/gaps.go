package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	GapStaleMissing         = "stale_missing"
	GapOwnerlessExposure    = "ownerless_exposure"
	GapInactiveCredentialed = "inactive_but_credentialed" // #nosec G101 -- lifecycle enum label, not credential material.
	GapOverApproved         = "over_approved"
	GapOrphanedIdentity     = "orphaned_identity"
	GapRevokedStillPresent  = "revoked_still_present"
	GapApprovalExpired      = "approval_expired"
	GapPresenceDrift        = "presence_absence_drift"
)

type Gap struct {
	GapID            string   `json:"gap_id" yaml:"gap_id"`
	ReasonCode       string   `json:"reason_code" yaml:"reason_code"`
	Severity         string   `json:"severity" yaml:"severity"`
	AgentID          string   `json:"agent_id" yaml:"agent_id"`
	ToolID           string   `json:"tool_id,omitempty" yaml:"tool_id,omitempty"`
	ToolType         string   `json:"tool_type,omitempty" yaml:"tool_type,omitempty"`
	Org              string   `json:"org" yaml:"org"`
	Repo             string   `json:"repo,omitempty" yaml:"repo,omitempty"`
	Location         string   `json:"location,omitempty" yaml:"location,omitempty"`
	Present          bool     `json:"present" yaml:"present"`
	LifecycleState   string   `json:"lifecycle_state,omitempty" yaml:"lifecycle_state,omitempty"`
	ApprovalStatus   string   `json:"approval_status,omitempty" yaml:"approval_status,omitempty"`
	Owner            string   `json:"owner,omitempty" yaml:"owner,omitempty"`
	OwnershipStatus  string   `json:"ownership_status,omitempty" yaml:"ownership_status,omitempty"`
	WriteCapable     bool     `json:"write_capable,omitempty" yaml:"write_capable,omitempty"`
	CredentialAccess bool     `json:"credential_access,omitempty" yaml:"credential_access,omitempty"`
	Message          string   `json:"message" yaml:"message"`
	EvidenceBasis    []string `json:"evidence_basis,omitempty" yaml:"evidence_basis,omitempty"`
}

type GapInput struct {
	Identities  []manifest.IdentityRecord
	Inventory   *agginventory.Inventory
	Transitions []Transition
}

func DetectGaps(input GapInput) []Gap {
	if len(input.Identities) == 0 || input.Inventory == nil {
		return nil
	}
	toolByAgent, privilegeByAgent := lifecycleGapIndexes(input.Inventory)
	latestTransition := latestTransitions(input.Transitions)
	gaps := make([]Gap, 0)

	for _, record := range input.Identities {
		agentID := strings.TrimSpace(record.AgentID)
		if agentID == "" {
			continue
		}
		if !model.IsLegacyArtifactIdentityCandidate(record.ToolType, record.ToolID, record.AgentID) {
			continue
		}
		tool := toolByAgent[agentID]
		privilege := privilegeByAgent[agentID]
		owner, ownerStatus := gapOwner(tool, privilege, record)
		writeCapable := privilege.WriteCapable || tool.PermissionSurface.Write
		credentialAccess := privilege.CredentialAccess || tool.DataClass == "secrets"
		evidence := gapEvidenceBasis(tool, privilege, record)

		appendGap := func(reasonCode, severity, message string) {
			gaps = append(gaps, Gap{
				GapID:            gapID(agentID, reasonCode, record.Repo, record.Location),
				ReasonCode:       reasonCode,
				Severity:         severity,
				AgentID:          agentID,
				ToolID:           strings.TrimSpace(record.ToolID),
				ToolType:         firstLifecycleNonEmpty(strings.TrimSpace(record.ToolType), strings.TrimSpace(tool.ToolType), strings.TrimSpace(privilege.ToolType)),
				Org:              firstLifecycleNonEmpty(strings.TrimSpace(record.Org), strings.TrimSpace(tool.Org), "local"),
				Repo:             firstLifecycleNonEmpty(strings.TrimSpace(record.Repo), firstLifecycleRepo(tool), firstLifecycleRepoFromPrivilege(privilege)),
				Location:         firstLifecycleNonEmpty(strings.TrimSpace(record.Location), firstLifecycleLocation(tool), strings.TrimSpace(privilege.Location)),
				Present:          record.Present,
				LifecycleState:   strings.TrimSpace(record.Status),
				ApprovalStatus:   strings.TrimSpace(record.ApprovalState),
				Owner:            owner,
				OwnershipStatus:  ownerStatus,
				WriteCapable:     writeCapable,
				CredentialAccess: credentialAccess,
				Message:          message,
				EvidenceBasis:    evidence,
			})
		}

		if !record.Present {
			appendGap(GapStaleMissing, "medium", "identity is no longer present in the current scan but still exists in lifecycle state")
		}
		if strings.TrimSpace(record.Status) == identity.StateRevoked && record.Present {
			appendGap(GapRevokedStillPresent, "high", "revoked identity is still present in the current scan")
		}
		if strings.TrimSpace(record.ApprovalState) == "expired" || strings.TrimSpace(record.ApprovalState) == "invalid" {
			appendGap(GapApprovalExpired, "high", "approval evidence expired or became invalid")
		}
		if owner == "" || ownerStatus == "" || ownerStatus == "unresolved" {
			if writeCapable || credentialAccess || record.Present {
				appendGap(GapOwnerlessExposure, lifecycleGapSeverity(writeCapable, credentialAccess), "identity has no resolved operational owner for its current exposure")
			}
		}
		if credentialAccess && record.Present && !isLifecycleActive(record.Status) && strings.TrimSpace(record.Status) != identity.StateRevoked {
			appendGap(GapInactiveCredentialed, "high", "identity still has credentialed posture while not in an active approved lifecycle state")
		}
		if approvalLooksValid(record.ApprovalState) && !record.Present {
			appendGap(GapOverApproved, "medium", "identity still carries approval state even though it is no longer present")
		}
		if approvalLooksValid(record.ApprovalState) && !isLifecycleActive(record.Status) && strings.TrimSpace(record.Status) != identity.StateRevoked {
			appendGap(GapOverApproved, "medium", "identity approval state is broader than its current lifecycle state")
		}
		if isLifecycleOrphan(record, tool, input.Inventory != nil) {
			appendGap(GapOrphanedIdentity, "medium", "lifecycle identity no longer has a matching current inventory record")
		}
		if transition, ok := latestTransition[agentID]; ok {
			switch strings.TrimSpace(transition.Trigger) {
			case "removed", "reappeared":
				appendGap(GapPresenceDrift, "medium", "recent lifecycle transition indicates presence drift that needs review")
			}
		}
	}

	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Severity != gaps[j].Severity {
			return lifecycleSeverityRank(gaps[i].Severity) < lifecycleSeverityRank(gaps[j].Severity)
		}
		if gaps[i].ReasonCode != gaps[j].ReasonCode {
			return gaps[i].ReasonCode < gaps[j].ReasonCode
		}
		if gaps[i].Org != gaps[j].Org {
			return gaps[i].Org < gaps[j].Org
		}
		if gaps[i].Repo != gaps[j].Repo {
			return gaps[i].Repo < gaps[j].Repo
		}
		if gaps[i].Location != gaps[j].Location {
			return gaps[i].Location < gaps[j].Location
		}
		return gaps[i].AgentID < gaps[j].AgentID
	})
	return dedupeGaps(gaps)
}

func lifecycleGapIndexes(inv *agginventory.Inventory) (map[string]agginventory.Tool, map[string]agginventory.AgentPrivilegeMapEntry) {
	tools := map[string]agginventory.Tool{}
	privileges := map[string]agginventory.AgentPrivilegeMapEntry{}
	if inv == nil {
		return tools, privileges
	}
	for _, tool := range inv.Tools {
		agentID := strings.TrimSpace(tool.AgentID)
		if agentID == "" {
			continue
		}
		tools[agentID] = tool
	}
	for _, entry := range inv.AgentPrivilegeMap {
		agentID := strings.TrimSpace(entry.AgentID)
		if agentID == "" {
			continue
		}
		privileges[agentID] = entry
	}
	return tools, privileges
}

func latestTransitions(transitions []Transition) map[string]Transition {
	out := map[string]Transition{}
	for _, item := range transitions {
		agentID := strings.TrimSpace(item.AgentID)
		if agentID == "" {
			continue
		}
		current, ok := out[agentID]
		if !ok || strings.TrimSpace(item.Timestamp) > strings.TrimSpace(current.Timestamp) || (strings.TrimSpace(item.Timestamp) == strings.TrimSpace(current.Timestamp) && strings.TrimSpace(item.Trigger) < strings.TrimSpace(current.Trigger)) {
			out[agentID] = item
		}
	}
	return out
}

func gapOwner(tool agginventory.Tool, privilege agginventory.AgentPrivilegeMapEntry, record manifest.IdentityRecord) (string, string) {
	if strings.TrimSpace(privilege.OperationalOwner) != "" {
		return strings.TrimSpace(privilege.OperationalOwner), strings.TrimSpace(privilege.OwnershipStatus)
	}
	for _, loc := range tool.Locations {
		if strings.TrimSpace(loc.Owner) != "" {
			return strings.TrimSpace(loc.Owner), strings.TrimSpace(loc.OwnershipStatus)
		}
	}
	if strings.TrimSpace(record.Approval.Owner) != "" {
		return strings.TrimSpace(record.Approval.Owner), "explicit"
	}
	return "", ""
}

func gapEvidenceBasis(tool agginventory.Tool, privilege agginventory.AgentPrivilegeMapEntry, record manifest.IdentityRecord) []string {
	values := make([]string, 0, 8)
	if strings.TrimSpace(record.Status) != "" {
		values = append(values, "lifecycle_state:"+strings.TrimSpace(record.Status))
	}
	if strings.TrimSpace(record.ApprovalState) != "" {
		values = append(values, "approval_status:"+strings.TrimSpace(record.ApprovalState))
	}
	if strings.TrimSpace(privilege.OperationalOwner) != "" {
		values = append(values, "operational_owner")
	}
	values = append(values, privilege.Permissions...)
	for _, loc := range tool.Locations {
		if strings.TrimSpace(loc.OwnerSource) != "" {
			values = append(values, loc.OwnerSource)
		}
	}
	return mergeLifecycleStrings(values...)
}

func lifecycleGapSeverity(writeCapable, credentialAccess bool) string {
	switch {
	case writeCapable || credentialAccess:
		return "high"
	default:
		return "medium"
	}
}

func isLifecycleActive(state string) bool {
	switch strings.TrimSpace(state) {
	case identity.StateApproved, identity.StateActive:
		return true
	default:
		return false
	}
}

func approvalLooksValid(status string) bool {
	switch strings.TrimSpace(status) {
	case "valid", "approved", "approved_list":
		return true
	default:
		return false
	}
}

func isLifecycleOrphan(record manifest.IdentityRecord, tool agginventory.Tool, hasInventory bool) bool {
	if !hasInventory {
		return false
	}
	if !record.Present {
		return true
	}
	if strings.TrimSpace(tool.AgentID) == "" && strings.TrimSpace(tool.ToolID) == "" {
		return true
	}
	return false
}

func firstLifecycleRepo(tool agginventory.Tool) string {
	if len(tool.Repos) > 0 {
		return strings.TrimSpace(tool.Repos[0])
	}
	if len(tool.Locations) > 0 {
		return strings.TrimSpace(tool.Locations[0].Repo)
	}
	return ""
}

func firstLifecycleRepoFromPrivilege(privilege agginventory.AgentPrivilegeMapEntry) string {
	if len(privilege.Repos) > 0 {
		return strings.TrimSpace(privilege.Repos[0])
	}
	return ""
}

func firstLifecycleLocation(tool agginventory.Tool) string {
	if len(tool.Locations) > 0 {
		return strings.TrimSpace(tool.Locations[0].Location)
	}
	return ""
}

func lifecycleSeverityRank(value string) int {
	switch strings.TrimSpace(value) {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func dedupeGaps(gaps []Gap) []Gap {
	if len(gaps) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]Gap, 0, len(gaps))
	for _, gap := range gaps {
		key := strings.Join([]string{gap.AgentID, gap.ReasonCode, gap.Repo, gap.Location}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, gap)
	}
	return out
}

func gapID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "lg-" + hex.EncodeToString(sum[:6])
}

func firstLifecycleNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func mergeLifecycleStrings(values ...string) []string {
	set := map[string]struct{}{}
	out := make([]string, 0)
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := set[trimmed]; ok {
			continue
		}
		set[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
