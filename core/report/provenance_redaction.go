package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func sanitizeIntroducedByPublic(in *attribution.Result) *attribution.Result {
	if in == nil {
		return nil
	}
	out := attribution.Merge(in, nil)
	out.Author = redactValue("author", out.Author, 8)
	out.ChangedFile = redactValue("file", out.ChangedFile, 8)
	out.ProviderURL = redactValue("provider", out.ProviderURL, 8)
	out.Provider = redactValue("provider", out.Provider, 8)
	if strings.TrimSpace(out.Reference) != "" {
		out.Reference = redactValue("pr", out.Reference, 8)
		out.PRNumber = 0
	}
	if strings.TrimSpace(out.CommitSHA) != "" {
		out.CommitSHA = redactValue("commit", out.CommitSHA, 8)
	}
	if out.Provenance != nil {
		out.Provenance = sanitizeProvenancePublic(out.Provenance)
	}
	return out
}

func sanitizeIntroducedByWithConfig(in *attribution.Result, config RedactionConfig) *attribution.Result {
	if in == nil {
		return nil
	}
	out := attribution.Merge(in, nil)
	out.Author = maybeRedactAuthor(out.Author, config)
	out.ChangedFile = maybeRedactLocationLike(out.ChangedFile, config)
	out.ProviderURL = maybeRedactProvider(out.ProviderURL, config)
	out.Provider = maybeRedactProvider(out.Provider, config)
	if config.Has(RedactionProviders) {
		out.Reference = redactValue("pr", out.Reference, 8)
		out.PRNumber = 0
		out.CommitSHA = redactValue("commit", out.CommitSHA, 8)
	}
	if out.Provenance != nil {
		out.Provenance = sanitizeProvenanceWithConfig(out.Provenance, config)
	}
	return out
}

func sanitizeProvenancePublic(in *attribution.Provenance) *attribution.Provenance {
	if in == nil {
		return nil
	}
	out := attribution.CloneProvenance(in)
	out.Provider = redactValue("provider", out.Provider, 8)
	out.Reference = redactValue("pr", out.Reference, 8)
	out.Number = 0
	out.Title = redactValue("title", out.Title, 8)
	out.ProviderURL = redactValue("provider", out.ProviderURL, 8)
	out.HeadSHA = redactValue("commit", out.HeadSHA, 8)
	out.MergeCommitSHA = redactValue("commit", out.MergeCommitSHA, 8)
	out.Author = redactValue("author", out.Author, 8)
	out.BaseBranch = redactValue("branch", out.BaseBranch, 8)
	out.HeadBranch = redactValue("branch", out.HeadBranch, 8)
	out.MergedBy = redactValue("author", out.MergedBy, 8)
	out.ChangedFiles = redactStringSlice(out.ChangedFiles, "file")
	out.EvidenceRefs = redactStringSlice(out.EvidenceRefs, "evidence")
	for idx := range out.Reviewers {
		out.Reviewers[idx].Name = redactValue("author", out.Reviewers[idx].Name, 8)
		out.Reviewers[idx].ProviderURL = redactValue("provider", out.Reviewers[idx].ProviderURL, 8)
	}
	for idx := range out.Approvals {
		out.Approvals[idx].Name = redactValue("author", out.Approvals[idx].Name, 8)
		out.Approvals[idx].ProviderURL = redactValue("provider", out.Approvals[idx].ProviderURL, 8)
	}
	for idx := range out.Checks {
		out.Checks[idx].ProviderURL = redactValue("provider", out.Checks[idx].ProviderURL, 8)
	}
	for idx := range out.Deployments {
		out.Deployments[idx].ProviderURL = redactValue("provider", out.Deployments[idx].ProviderURL, 8)
	}
	for idx := range out.BranchProtections {
		out.BranchProtections[idx].Branch = redactValue("branch", out.BranchProtections[idx].Branch, 8)
		out.BranchProtections[idx].EvidenceRefs = redactStringSlice(out.BranchProtections[idx].EvidenceRefs, "evidence")
	}
	for idx := range out.EnvironmentGates {
		out.EnvironmentGates[idx].RequiredReviewers = redactStringSlice(out.EnvironmentGates[idx].RequiredReviewers, "author")
		out.EnvironmentGates[idx].DeploymentIDs = redactStringSlice(out.EnvironmentGates[idx].DeploymentIDs, "deploy")
	}
	return out
}

func sanitizeProvenanceWithConfig(in *attribution.Provenance, config RedactionConfig) *attribution.Provenance {
	if in == nil {
		return nil
	}
	out := attribution.CloneProvenance(in)
	out.Provider = maybeRedactProvider(out.Provider, config)
	if config.Has(RedactionProviders) {
		out.Reference = redactValue("pr", out.Reference, 8)
		out.Number = 0
		out.HeadSHA = redactValue("commit", out.HeadSHA, 8)
		out.MergeCommitSHA = redactValue("commit", out.MergeCommitSHA, 8)
	}
	out.Title = maybeRedactCompositeLabel(out.Title, config)
	out.ProviderURL = maybeRedactProvider(out.ProviderURL, config)
	out.Author = maybeRedactAuthor(out.Author, config)
	out.BaseBranch = maybeRedactLocationLike(out.BaseBranch, config)
	out.HeadBranch = maybeRedactLocationLike(out.HeadBranch, config)
	out.MergedBy = maybeRedactAuthor(out.MergedBy, config)
	for idx := range out.ChangedFiles {
		out.ChangedFiles[idx] = maybeRedactLocationLike(out.ChangedFiles[idx], config)
	}
	out.EvidenceRefs = maybeRedactStringSlice(out.EvidenceRefs, "evidence", config.Has(RedactionProviders) || config.Has(RedactionPaths))
	for idx := range out.Reviewers {
		out.Reviewers[idx].Name = maybeRedactAuthor(out.Reviewers[idx].Name, config)
		out.Reviewers[idx].ProviderURL = maybeRedactProvider(out.Reviewers[idx].ProviderURL, config)
	}
	for idx := range out.Approvals {
		out.Approvals[idx].Name = maybeRedactAuthor(out.Approvals[idx].Name, config)
		out.Approvals[idx].ProviderURL = maybeRedactProvider(out.Approvals[idx].ProviderURL, config)
	}
	for idx := range out.Checks {
		out.Checks[idx].ProviderURL = maybeRedactProvider(out.Checks[idx].ProviderURL, config)
	}
	for idx := range out.Deployments {
		out.Deployments[idx].ProviderURL = maybeRedactProvider(out.Deployments[idx].ProviderURL, config)
	}
	for idx := range out.BranchProtections {
		out.BranchProtections[idx].Branch = maybeRedactLocationLike(out.BranchProtections[idx].Branch, config)
		out.BranchProtections[idx].EvidenceRefs = maybeRedactStringSlice(out.BranchProtections[idx].EvidenceRefs, "evidence", config.Has(RedactionProviders) || config.Has(RedactionPaths))
	}
	for idx := range out.EnvironmentGates {
		out.EnvironmentGates[idx].RequiredReviewers = maybeRedactStringSlice(out.EnvironmentGates[idx].RequiredReviewers, "author", config.Has(RedactionAuthors))
		out.EnvironmentGates[idx].DeploymentIDs = maybeRedactStringSlice(out.EnvironmentGates[idx].DeploymentIDs, "deploy", config.Has(RedactionProviders))
	}
	return out
}

func sanitizeEvidencePacketSummaryPublic(in *ingest.EvidencePacketSummary, rawPaths []risk.ActionPath, sanitizedPaths []risk.ActionPath) *ingest.EvidencePacketSummary {
	if in == nil {
		return nil
	}
	pathIDMap := evidencePacketPathIDMap(rawPaths, sanitizedPaths)
	out := *in
	out.ArtifactPath = redactValue("artifact", out.ArtifactPath, 8)
	out.Correlations = append([]ingest.EvidencePacketCorrelation(nil), in.Correlations...)
	for idx := range out.Correlations {
		copyItem := out.Correlations[idx]
		copyItem.PacketID = redactValue("packet", copyItem.PacketID, 8)
		copyItem.PathID = redactedPathID(copyItem.PathID, pathIDMap)
		copyItem.AgentID = redactValue("agent", copyItem.AgentID, 8)
		copyItem.Repo = redactValue("repo", copyItem.Repo, 8)
		copyItem.Workflow = redactValue("file", copyItem.Workflow, 8)
		copyItem.PullRequestRef = redactValue("pr", copyItem.PullRequestRef, 8)
		copyItem.ProofRefs = redactStringSlice(copyItem.ProofRefs, "proof")
		copyItem.GraphNodeRefs = redactStringSlice(copyItem.GraphNodeRefs, "node")
		copyItem.GraphEdgeRefs = redactStringSlice(copyItem.GraphEdgeRefs, "edge")
		copyItem.EvidenceRefs = redactStringSlice(copyItem.EvidenceRefs, "evidence")
		out.Correlations[idx] = copyItem
	}
	return &out
}

func sanitizeEvidencePacketSummaryWithConfig(in *ingest.EvidencePacketSummary, rawPaths []risk.ActionPath, sanitizedPaths []risk.ActionPath, config RedactionConfig) *ingest.EvidencePacketSummary {
	if in == nil {
		return nil
	}
	pathIDMap := evidencePacketPathIDMap(rawPaths, sanitizedPaths)
	out := *in
	out.ArtifactPath = maybeRedactLocationLike(out.ArtifactPath, config)
	out.Correlations = append([]ingest.EvidencePacketCorrelation(nil), in.Correlations...)
	for idx := range out.Correlations {
		copyItem := out.Correlations[idx]
		copyItem.PacketID = firstNonEmptyValue(strings.TrimSpace(copyItem.PacketID), "")
		if config.Has(RedactionPaths) || config.Has(RedactionProofRefs) {
			copyItem.PacketID = redactValue("packet", copyItem.PacketID, 8)
		}
		copyItem.PathID = redactedPathIDWithConfig(copyItem.PathID, pathIDMap, config)
		copyItem.AgentID = maybeRedactPathID(copyItem.AgentID, config)
		copyItem.Repo = maybeRedactRepo(copyItem.Repo, config)
		copyItem.Workflow = maybeRedactLocationLike(copyItem.Workflow, config)
		if config.Has(RedactionProviders) {
			copyItem.PullRequestRef = redactValue("pr", copyItem.PullRequestRef, 8)
		}
		copyItem.ProofRefs = maybeRedactStringSlice(copyItem.ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyItem.GraphNodeRefs = maybeRedactStringSlice(copyItem.GraphNodeRefs, "node", config.Has(RedactionGraphRefs))
		copyItem.GraphEdgeRefs = maybeRedactStringSlice(copyItem.GraphEdgeRefs, "edge", config.Has(RedactionGraphRefs))
		copyItem.EvidenceRefs = maybeRedactStringSlice(copyItem.EvidenceRefs, "evidence", config.Has(RedactionProviders) || config.Has(RedactionPaths))
		out.Correlations[idx] = copyItem
	}
	return &out
}

func evidencePacketPathIDMap(rawPaths []risk.ActionPath, sanitizedPaths []risk.ActionPath) map[string]string {
	out := map[string]string{}
	for idx := range rawPaths {
		rawPathID := strings.TrimSpace(rawPaths[idx].PathID)
		if rawPathID == "" {
			continue
		}
		sanitizedPathID := redactValue("path", rawPathID, 8)
		if idx < len(sanitizedPaths) && strings.TrimSpace(sanitizedPaths[idx].PathID) != "" {
			sanitizedPathID = strings.TrimSpace(sanitizedPaths[idx].PathID)
		}
		out[rawPathID] = sanitizedPathID
	}
	return out
}

func redactedPathID(pathID string, mapping map[string]string) string {
	trimmed := strings.TrimSpace(pathID)
	if trimmed == "" {
		return ""
	}
	if redacted, ok := mapping[trimmed]; ok {
		return redacted
	}
	return redactValue("path", trimmed, 8)
}

func redactedPathIDWithConfig(pathID string, mapping map[string]string, config RedactionConfig) string {
	trimmed := strings.TrimSpace(pathID)
	if trimmed == "" {
		return ""
	}
	if config.Has(RedactionPaths) {
		return redactedPathID(trimmed, mapping)
	}
	return trimmed
}
