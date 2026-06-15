package report

import (
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func FinalizeSummaryForShareProfile(summary Summary) Summary {
	profile, ok := ParseShareProfile(summary.ShareProfile)
	if !ok || profile == ShareProfileInternal {
		return summary
	}
	return FinalizeSummaryForOutput(summary)
}

func FinalizeSummaryForSerialization(summary Summary) Summary {
	summary = FinalizeSummaryForShareProfile(summary)
	attachSummaryOutputMetadata(&summary)
	return summary
}

func FinalizeSummaryForOutput(summary Summary) Summary {
	summary.ActionPaths = risk.StripCanonicalProjectionDetails(summary.ActionPaths)
	summary.ActionPathToControlFirst = risk.StripActionPathToControlFirstCanonicalProjectionDetails(summary.ActionPathToControlFirst)
	summary.ControlPathGraph = aggattack.StripCanonicalProjectionDetails(summary.ControlPathGraph)
	summary.ControlBacklog = controlbacklog.StripCanonicalProjectionDetails(summary.ControlBacklog)
	summary.AgentActionBOM = stripAgentActionBOMCanonicalProjectionDetails(summary.AgentActionBOM)
	summary.ActionSurfaceRegistry = stripActionSurfaceRegistryCanonicalProjectionDetails(summary.ActionSurfaceRegistry)
	if summary.AssessmentSummary != nil {
		copySummary := *summary.AssessmentSummary
		copySummary.TopPathToControlFirst = stripAssessmentActionPath(summary.AssessmentSummary.TopPathToControlFirst)
		copySummary.TopExecutionIdentityBacked = stripAssessmentActionPath(summary.AssessmentSummary.TopExecutionIdentityBacked)
		summary.AssessmentSummary = &copySummary
	}
	return summary
}

func stripActionSurfaceRegistryCanonicalProjectionDetails(in []ActionSurfaceRegistryEntry) []ActionSurfaceRegistryEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]ActionSurfaceRegistryEntry, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(copyItem.EndpointRefGroupProjection, copyItem.MutableEndpointSemanticRefs, copyItem.MutableEndpointSemantics)
		if len(copyItem.MutableEndpointSemanticRefs) > 0 {
			copyItem.MutableEndpointSemanticRefs = agginventory.BoundedMutableEndpointSemanticRefs(copyItem.MutableEndpointSemanticRefs, copyItem.MutableEndpointSemantics)
			copyItem.MutableEndpointSemantics = nil
		}
		if copyItem.CredentialAuthorityRef != "" {
			copyItem.CredentialAuthority = nil
		}
		out = append(out, copyItem)
	}
	return out
}

func stripAgentActionBOMCanonicalProjectionDetails(in *AgentActionBOM) *AgentActionBOM {
	if in == nil {
		return nil
	}
	copyBOM := *in
	copyBOM.Items = append([]AgentActionBOMItem(nil), in.Items...)
	for idx := range copyBOM.Items {
		item := &copyBOM.Items[idx]
		item.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(item.EndpointRefGroupProjection, item.MutableEndpointSemanticRefs, item.MutableEndpointSemantics)
		if len(item.MutableEndpointSemanticRefs) > 0 {
			item.MutableEndpointSemanticRefs = agginventory.BoundedMutableEndpointSemanticRefs(item.MutableEndpointSemanticRefs, item.MutableEndpointSemantics)
			item.MutableEndpointSemantics = nil
		}
		if item.CredentialAuthorityRef != "" {
			item.CredentialAuthority = nil
		}
		if len(item.AuthorityBindingRefs) > 0 {
			item.AuthorityBindings = nil
		}
	}
	return &copyBOM
}

func firstAssessmentPath(in *risk.ActionPath) risk.ActionPath {
	if in == nil {
		return risk.ActionPath{}
	}
	return *in
}

func stripAssessmentActionPath(in *risk.ActionPath) *risk.ActionPath {
	if in == nil {
		return nil
	}
	choice := risk.StripActionPathToControlFirstCanonicalProjectionDetails(&risk.ActionPathToControlFirst{
		Summary: risk.ActionPathSummary{},
		Path:    firstAssessmentPath(in),
	})
	if choice == nil {
		return nil
	}
	path := choice.Path
	if path.PathID == "" && path.Org == "" && path.Repo == "" && path.ToolType == "" && path.Location == "" {
		return nil
	}
	return &path
}

func attachSummaryOutputMetadata(summary *Summary) {
	if summary == nil {
		return
	}
	summary.ArtifactBudget = &ArtifactBudget{
		MaxActionPaths:         defaultMaxActionPaths,
		MaxBacklogItems:        defaultMaxBacklogItems,
		MaxGraphNodes:          defaultMaxGraphNodes,
		MaxGraphEdges:          defaultMaxGraphEdges,
		MaxWorkflowChains:      defaultMaxWorkflowChains,
		MaxExposureGroups:      defaultMaxExposureGroups,
		MaxAgentActionBOM:      defaultMaxAgentActionBOM,
		MarkdownLineCap:        defaultMarkdownLineCap,
		MarkdownLeadLineCap:    defaultBOMLeadLineCap,
		MarkdownLeadSectionCap: defaultBOMLeadSectionCap,
	}
	summary.AppendixAvailable = len(summary.Sections) > 0 || len(summary.ActionPaths) > 0 || summary.AgentActionBOM != nil
	summary.FocusedBundleAvailable = summary.AgentActionBOM != nil && len(summary.AgentActionBOM.Items) > 0
	summary.FullExportAvailable = false
}
