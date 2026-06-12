package report

import (
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func FinalizeSummaryForShareProfile(summary Summary) Summary {
	profile, ok := ParseShareProfile(summary.ShareProfile)
	if !ok || profile == ShareProfileInternal {
		return summary
	}
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
		if len(copyItem.MutableEndpointSemanticRefs) > 0 {
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
		if len(item.MutableEndpointSemanticRefs) > 0 {
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
