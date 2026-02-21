package manifestgen

import (
	"fmt"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/state"
)

func GenerateUnderReview(snapshot state.Snapshot, generatedAt time.Time) (manifest.Manifest, error) {
	now := generatedAt.UTC().Truncate(time.Second)
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Second)
	}

	records := recordsFromSnapshot(snapshot, now)
	if len(records) == 0 {
		return manifest.Manifest{}, fmt.Errorf("state snapshot does not contain discoverable identities")
	}

	return manifest.Manifest{
		Version:    manifest.Version,
		UpdatedAt:  now.Format(time.RFC3339),
		Identities: records,
	}, nil
}

func recordsFromSnapshot(snapshot state.Snapshot, now time.Time) []manifest.IdentityRecord {
	if len(snapshot.Identities) > 0 {
		out := make([]manifest.IdentityRecord, 0, len(snapshot.Identities))
		for _, record := range snapshot.Identities {
			item := record
			item.Status = identity.StateUnderReview
			item.Approval = manifest.Approval{}
			item.ApprovalState = "missing"
			item.Present = true
			item.FirstSeen = fallbackTimestamp(item.FirstSeen, now)
			item.LastSeen = now.Format(time.RFC3339)
			out = append(out, item)
		}
		sortRecords(out)
		return out
	}

	if snapshot.Inventory == nil {
		return nil
	}
	return recordsFromInventory(*snapshot.Inventory, now)
}

func recordsFromInventory(inv agginventory.Inventory, now time.Time) []manifest.IdentityRecord {
	out := make([]manifest.IdentityRecord, 0)
	seen := map[string]struct{}{}
	for _, tool := range inv.Tools {
		locations := append([]agginventory.ToolLocation(nil), tool.Locations...)
		sort.Slice(locations, func(i, j int) bool {
			if locations[i].Repo != locations[j].Repo {
				return locations[i].Repo < locations[j].Repo
			}
			return locations[i].Location < locations[j].Location
		})
		for _, location := range locations {
			agentID := strings.TrimSpace(tool.AgentID)
			toolID := strings.TrimSpace(tool.ToolID)
			if agentID == "" {
				toolID = identity.ToolID(tool.ToolType, location.Location)
				agentID = identity.AgentID(toolID, tool.Org)
			}
			if _, exists := seen[agentID]; exists {
				continue
			}
			seen[agentID] = struct{}{}
			out = append(out, manifest.IdentityRecord{
				AgentID:       agentID,
				ToolID:        toolID,
				ToolType:      tool.ToolType,
				Org:           tool.Org,
				Repo:          location.Repo,
				Location:      location.Location,
				Status:        identity.StateUnderReview,
				Approval:      manifest.Approval{},
				ApprovalState: "missing",
				FirstSeen:     now.Format(time.RFC3339),
				LastSeen:      now.Format(time.RFC3339),
				Present:       true,
				DataClass:     tool.DataClass,
				EndpointClass: tool.EndpointClass,
				AutonomyLevel: tool.AutonomyLevel,
				RiskScore:     tool.RiskScore,
			})
		}
	}
	sortRecords(out)
	return out
}

func fallbackTimestamp(value string, now time.Time) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return now.Format(time.RFC3339)
}

func sortRecords(items []manifest.IdentityRecord) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].AgentID != items[j].AgentID {
			return items[i].AgentID < items[j].AgentID
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		return items[i].Location < items[j].Location
	})
}
