package lifecycle

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/governancequeue"
)

func BuildQueue(gaps []Gap) []governancequeue.Item {
	if len(gaps) == 0 {
		return nil
	}
	items := make([]governancequeue.Item, 0, len(gaps))
	for _, gap := range gaps {
		items = append(items, QueueItemFromGap(gap))
	}
	sort.Slice(items, func(i, j int) bool {
		if queueSeverityRank(items[i].Severity) != queueSeverityRank(items[j].Severity) {
			return queueSeverityRank(items[i].Severity) < queueSeverityRank(items[j].Severity)
		}
		if queueCredentialRank(items[i].CredentialStatus) != queueCredentialRank(items[j].CredentialStatus) {
			return queueCredentialRank(items[i].CredentialStatus) < queueCredentialRank(items[j].CredentialStatus)
		}
		if queueOwnerEvidenceRank(items[i].OwnerEvidenceState) != queueOwnerEvidenceRank(items[j].OwnerEvidenceState) {
			return queueOwnerEvidenceRank(items[i].OwnerEvidenceState) < queueOwnerEvidenceRank(items[j].OwnerEvidenceState)
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].QueueID < items[j].QueueID
	})
	return items
}

func QueueItemFromGap(gap Gap) governancequeue.Item {
	item := governancequeue.Item{
		QueueID:            "lq-" + strings.TrimPrefix(strings.TrimSpace(gap.GapID), "gap-"),
		GapID:              strings.TrimSpace(gap.GapID),
		AgentID:            strings.TrimSpace(gap.AgentID),
		Repo:               strings.TrimSpace(gap.Repo),
		Path:               strings.TrimSpace(gap.Location),
		ReasonCode:         strings.TrimSpace(gap.ReasonCode),
		Severity:           strings.TrimSpace(gap.Severity),
		Owner:              strings.TrimSpace(gap.Owner),
		OwnerEvidenceState: queueOwnerEvidenceStateFromGap(gap),
		CredentialStatus:   queueCredentialStatusFromGap(gap),
		LifecycleStatus:    strings.TrimSpace(gap.LifecycleState),
		RecommendedAction:  queueRecommendedAction(gap),
		SLA:                queueSLA(gap),
		ClosureCriteria:    queueClosure(gap),
		EvidenceRefs:       queueCleanStrings(gap.EvidenceBasis),
		SourceConflicts:    queueSourceConflicts(gap),
	}
	if item.QueueID == "lq-" {
		item.QueueID = "lq-" + strings.TrimSpace(gap.AgentID) + "-" + strings.TrimSpace(gap.ReasonCode)
	}
	return item
}

func queueOwnerEvidenceStateFromGap(gap Gap) string {
	switch strings.TrimSpace(gap.OwnershipStatus) {
	case "explicit":
		return "verified"
	case "inferred":
		return "inferred"
	default:
		return "unknown"
	}
}

func queueCredentialStatusFromGap(gap Gap) string {
	if gap.CredentialAccess {
		return governancequeue.CredentialStatusPresent
	}
	return governancequeue.CredentialStatusNone
}

func queueRecommendedAction(gap Gap) string {
	switch strings.TrimSpace(gap.ReasonCode) {
	case GapInactiveCredentialed, GapRevokedStillPresent:
		return "remediate"
	case GapOwnerlessExposure, GapOwnerUnresolved:
		return "attach_evidence"
	case GapOwnerInferred, GapApprovalExpired, GapMissingApproval:
		return "approve"
	default:
		return "inventory_review"
	}
}

func queueSLA(gap Gap) string {
	switch strings.TrimSpace(gap.Severity) {
	case "high":
		return "7d"
	case "medium":
		return "14d"
	default:
		return "30d"
	}
}

func queueClosure(gap Gap) string {
	switch strings.TrimSpace(gap.ReasonCode) {
	case GapInactiveCredentialed:
		return "Remove standing credential access or return the path to an active approved lifecycle state."
	case GapRevokedStillPresent:
		return "Remove the revoked path from active execution and confirm it no longer appears in scan output."
	case GapOwnerlessExposure, GapOwnerUnresolved:
		return "Assign an explicit owner and attach lifecycle review evidence for the active path."
	case GapOwnerInferred:
		return "Confirm the inferred owner with explicit review evidence."
	case GapApprovalExpired, GapMissingApproval:
		return "Attach fresh approval evidence with owner, expiry, and review scope."
	default:
		return "Record lifecycle review evidence and rescan."
	}
}

func queueSourceConflicts(gap Gap) []string {
	switch strings.TrimSpace(gap.OwnershipStatus) {
	case "unresolved":
		return []string{"owner_resolution:unresolved"}
	default:
		return nil
	}
}

func queueCleanStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func queueSeverityRank(value string) int {
	switch strings.TrimSpace(value) {
	case "high":
		return 0
	case "medium":
		return 1
	default:
		return 2
	}
}

func queueCredentialRank(value string) int {
	switch strings.TrimSpace(value) {
	case governancequeue.CredentialStatusPresent:
		return 0
	default:
		return 1
	}
}

func queueOwnerEvidenceRank(value string) int {
	switch strings.TrimSpace(value) {
	case "unknown":
		return 0
	case "inferred":
		return 1
	default:
		return 2
	}
}
