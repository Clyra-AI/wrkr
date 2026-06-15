package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
)

const focusedEvidenceTopPathLimit = 5

// PrepareEvidenceBundleSummary trims report evidence output down to the
// selected path or focus preset while preserving shared suppression and
// redaction metadata from the canonical summary finalizer.
func PrepareEvidenceBundleSummary(summary Summary, focusPathID string, focusPreset string) Summary {
	if strings.TrimSpace(focusPathID) == "" && strings.TrimSpace(focusPreset) == "" {
		return summary
	}

	pathIDs := focusedEvidencePathIDs(summary, focusPathID)
	if len(pathIDs) == 0 {
		return summary
	}

	pathIDSet := map[string]struct{}{}
	for _, pathID := range pathIDs {
		if trimmed := strings.TrimSpace(pathID); trimmed != "" {
			pathIDSet[trimmed] = struct{}{}
		}
	}
	if len(pathIDSet) == 0 {
		return summary
	}

	focused := summary
	focused.SuppressedCounts = cloneSuppressedCounts(summary.SuppressedCounts)
	if focused.SuppressedCounts == nil {
		focused.SuppressedCounts = &SuppressedCounts{}
	}

	if summary.AgentActionBOM != nil {
		bomCopy := *summary.AgentActionBOM
		filteredItems := filterAgentActionBOMItems(summary.AgentActionBOM.Items, pathIDSet)
		if omitted := len(summary.AgentActionBOM.Items) - len(filteredItems); omitted > 0 {
			focused.SuppressedCounts.AgentActionBOM += omitted
		}
		bomCopy.Items = filteredItems
		focused.AgentActionBOM = &bomCopy
	}

	if summary.ControlBacklog != nil {
		filteredBacklog := filterFocusedBacklog(summary.ControlBacklog, pathIDSet)
		if filteredBacklog == nil {
			focused.SuppressedCounts.ControlBacklog += len(summary.ControlBacklog.Items)
			focused.ControlBacklog = nil
		} else {
			if omitted := len(summary.ControlBacklog.Items) - len(filteredBacklog.Items); omitted > 0 {
				focused.SuppressedCounts.ControlBacklog += omitted
			}
			focused.ControlBacklog = filteredBacklog
		}
	}

	if summary.ControlPathGraph != nil {
		focused.SuppressedCounts.GraphNodes += len(summary.ControlPathGraph.Nodes)
		focused.SuppressedCounts.GraphEdges += len(summary.ControlPathGraph.Edges)
		focused.ControlPathGraph = nil
	}

	if summary.WorkflowChains != nil {
		focused.SuppressedCounts.WorkflowChains += len(summary.WorkflowChains.Chains)
		focused.WorkflowChains = nil
	}

	if len(summary.ExposureGroups) > 0 {
		focused.SuppressedCounts.ExposureGroups += len(summary.ExposureGroups)
		focused.ExposureGroups = nil
	}

	focused.ActionSurfaceRegistry = filterActionSurfaceRegistry(summary.ActionSurfaceRegistry, pathIDSet)

	if !outputsignal.HasSuppressedCounts(focused.SuppressedCounts) {
		focused.SuppressedCounts = nil
	}
	return focused
}

func focusedEvidencePathIDs(summary Summary, focusPathID string) []string {
	if trimmed := strings.TrimSpace(focusPathID); trimmed != "" {
		return []string{trimmed}
	}
	if summary.FocusView == nil || len(summary.FocusView.PathIDs) == 0 {
		return nil
	}
	limit := len(summary.FocusView.PathIDs)
	if limit > focusedEvidenceTopPathLimit {
		limit = focusedEvidenceTopPathLimit
	}
	out := make([]string, 0, limit)
	for _, pathID := range summary.FocusView.PathIDs[:limit] {
		if trimmed := strings.TrimSpace(pathID); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func filterAgentActionBOMItems(items []AgentActionBOMItem, pathIDSet map[string]struct{}) []AgentActionBOMItem {
	if len(items) == 0 {
		return nil
	}
	filtered := make([]AgentActionBOMItem, 0, len(items))
	for _, item := range items {
		if _, ok := pathIDSet[strings.TrimSpace(item.PathID)]; !ok {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) == 0 {
		return nil
	}
	return filtered
}

func filterFocusedBacklog(backlog *controlbacklog.Backlog, pathIDSet map[string]struct{}) *controlbacklog.Backlog {
	if backlog == nil || len(backlog.Items) == 0 {
		return nil
	}
	filtered := make([]controlbacklog.Item, 0, len(backlog.Items))
	for _, item := range backlog.Items {
		if _, ok := pathIDSet[strings.TrimSpace(item.LinkedActionPathID)]; !ok {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) == 0 {
		return nil
	}
	copyBacklog := *backlog
	copyBacklog.Items = filtered
	return &copyBacklog
}

func filterActionSurfaceRegistry(entries []ActionSurfaceRegistryEntry, pathIDSet map[string]struct{}) []ActionSurfaceRegistryEntry {
	if len(entries) == 0 {
		return nil
	}
	filtered := make([]ActionSurfaceRegistryEntry, 0, len(entries))
	for _, entry := range entries {
		matched := false
		for _, pathID := range entry.PathIDs {
			if _, ok := pathIDSet[strings.TrimSpace(pathID)]; ok {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		filtered = append(filtered, entry)
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) > focusedEvidenceTopPathLimit {
		return append([]ActionSurfaceRegistryEntry(nil), filtered[:focusedEvidenceTopPathLimit]...)
	}
	return filtered
}
