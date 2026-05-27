package agentresolver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
)

const WorkflowChainVersion = "1"

type WorkflowChainArtifact struct {
	Version string               `json:"version"`
	Summary WorkflowChainSummary `json:"summary"`
	Chains  []WorkflowChain      `json:"chains"`
}

type WorkflowChainSummary struct {
	TotalChains               int                   `json:"total_chains"`
	Workflows                 []WorkflowChainRollup `json:"workflows,omitempty"`
	Repos                     []WorkflowChainRollup `json:"repos,omitempty"`
	AutonomyTiers             []WorkflowChainRollup `json:"autonomy_tiers,omitempty"`
	DelegationReadinessStates []WorkflowChainRollup `json:"delegation_readiness_states,omitempty"`
	RecommendedControls       []WorkflowChainRollup `json:"recommended_controls,omitempty"`
	TargetClasses             []WorkflowChainRollup `json:"target_classes,omitempty"`
	EvidenceCompleteness      []WorkflowChainRollup `json:"evidence_completeness,omitempty"`
}

type WorkflowChainRollup struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type WorkflowChainDimension struct {
	Key          string   `json:"key"`
	Label        string   `json:"label,omitempty"`
	Status       string   `json:"status,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type WorkflowChain struct {
	ChainID                  string                 `json:"chain_id"`
	PathIDs                  []string               `json:"path_ids,omitempty"`
	GraphNodeRefs            []string               `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs            []string               `json:"graph_edge_refs,omitempty"`
	ProofRefs                []string               `json:"proof_refs,omitempty"`
	EvidenceRefs             []string               `json:"evidence_refs,omitempty"`
	SourceFindingKeys        []string               `json:"source_finding_keys,omitempty"`
	IntroducedBy             *attribution.Result    `json:"introduced_by,omitempty"`
	Repo                     WorkflowChainDimension `json:"repo"`
	PullRequest              WorkflowChainDimension `json:"pull_request"`
	Workflow                 WorkflowChainDimension `json:"workflow"`
	Task                     WorkflowChainDimension `json:"task"`
	Tool                     WorkflowChainDimension `json:"tool"`
	Credential               WorkflowChainDimension `json:"credential"`
	Owner                    WorkflowChainDimension `json:"owner"`
	Approval                 WorkflowChainDimension `json:"approval"`
	Target                   WorkflowChainDimension `json:"target"`
	Evidence                 WorkflowChainDimension `json:"evidence"`
	Outcome                  WorkflowChainDimension `json:"outcome"`
	AutonomyTier             string                 `json:"autonomy_tier,omitempty"`
	DelegationReadinessState string                 `json:"delegation_readiness_state,omitempty"`
	RecommendedControl       string                 `json:"recommended_control,omitempty"`
	TargetClass              string                 `json:"target_class,omitempty"`
	EvidenceCompleteness     string                 `json:"evidence_completeness,omitempty"`
}

type WorkflowChainInput struct {
	PathID                    string
	Org                       string
	Repo                      string
	AgentID                   string
	ToolFamilyID              string
	ToolInstanceID            string
	ToolType                  string
	Location                  string
	Purpose                   string
	PurposeSource             string
	OperationalOwner          string
	CredentialAccess          bool
	CredentialProvenance      *agginventory.CredentialProvenance
	CredentialAuthority       *agginventory.CredentialAuthority
	ApprovalEvidenceState     string
	ProofEvidenceState        string
	RuntimeEvidenceState      string
	TargetEvidenceState       string
	ControlResolutionState    string
	DeploymentStatus          string
	DeliveryChainStatus       string
	TargetClass               string
	IntroducedBy              *attribution.Result
	AutonomyTier              string
	DelegationReadinessState  string
	RecommendedControl        string
	MatchedProductionTargets  []string
	EvidenceCompletenessLabel string
	GraphNodeRefs             []string
	GraphEdgeRefs             []string
	ProofRefs                 []string
	EvidenceRefs              []string
	SourceFindingKeys         []string
}

func BuildWorkflowChains(inputs []WorkflowChainInput) *WorkflowChainArtifact {
	if len(inputs) == 0 {
		return nil
	}

	ordered := append([]WorkflowChainInput(nil), inputs...)
	sort.Slice(ordered, func(i, j int) bool {
		if strings.TrimSpace(ordered[i].Org) != strings.TrimSpace(ordered[j].Org) {
			return strings.TrimSpace(ordered[i].Org) < strings.TrimSpace(ordered[j].Org)
		}
		if strings.TrimSpace(ordered[i].Repo) != strings.TrimSpace(ordered[j].Repo) {
			return strings.TrimSpace(ordered[i].Repo) < strings.TrimSpace(ordered[j].Repo)
		}
		if strings.TrimSpace(ordered[i].Location) != strings.TrimSpace(ordered[j].Location) {
			return strings.TrimSpace(ordered[i].Location) < strings.TrimSpace(ordered[j].Location)
		}
		return strings.TrimSpace(ordered[i].PathID) < strings.TrimSpace(ordered[j].PathID)
	})

	byID := map[string]*WorkflowChain{}
	for _, input := range ordered {
		chain := buildWorkflowChain(input)
		if current, ok := byID[chain.ChainID]; ok {
			current.PathIDs = uniqueSortedStrings(append(current.PathIDs, chain.PathIDs...))
			current.GraphNodeRefs = uniqueSortedStrings(append(current.GraphNodeRefs, chain.GraphNodeRefs...))
			current.GraphEdgeRefs = uniqueSortedStrings(append(current.GraphEdgeRefs, chain.GraphEdgeRefs...))
			current.ProofRefs = uniqueSortedStrings(append(current.ProofRefs, chain.ProofRefs...))
			current.EvidenceRefs = uniqueSortedStrings(append(current.EvidenceRefs, chain.EvidenceRefs...))
			current.SourceFindingKeys = uniqueSortedStrings(append(current.SourceFindingKeys, chain.SourceFindingKeys...))
			current.IntroducedBy = attribution.Merge(current.IntroducedBy, chain.IntroducedBy)
			current.Repo.EvidenceRefs = uniqueSortedStrings(append(current.Repo.EvidenceRefs, chain.Repo.EvidenceRefs...))
			current.PullRequest.EvidenceRefs = uniqueSortedStrings(append(current.PullRequest.EvidenceRefs, chain.PullRequest.EvidenceRefs...))
			current.Workflow.EvidenceRefs = uniqueSortedStrings(append(current.Workflow.EvidenceRefs, chain.Workflow.EvidenceRefs...))
			current.Task.EvidenceRefs = uniqueSortedStrings(append(current.Task.EvidenceRefs, chain.Task.EvidenceRefs...))
			current.Tool.EvidenceRefs = uniqueSortedStrings(append(current.Tool.EvidenceRefs, chain.Tool.EvidenceRefs...))
			current.Credential.EvidenceRefs = uniqueSortedStrings(append(current.Credential.EvidenceRefs, chain.Credential.EvidenceRefs...))
			current.Owner.EvidenceRefs = uniqueSortedStrings(append(current.Owner.EvidenceRefs, chain.Owner.EvidenceRefs...))
			current.Approval.EvidenceRefs = uniqueSortedStrings(append(current.Approval.EvidenceRefs, chain.Approval.EvidenceRefs...))
			current.Target.EvidenceRefs = uniqueSortedStrings(append(current.Target.EvidenceRefs, chain.Target.EvidenceRefs...))
			current.Evidence.EvidenceRefs = uniqueSortedStrings(append(current.Evidence.EvidenceRefs, chain.Evidence.EvidenceRefs...))
			current.Outcome.EvidenceRefs = uniqueSortedStrings(append(current.Outcome.EvidenceRefs, chain.Outcome.EvidenceRefs...))
			continue
		}
		copyChain := chain
		byID[chain.ChainID] = &copyChain
	}

	chains := make([]WorkflowChain, 0, len(byID))
	for _, chain := range byID {
		chains = append(chains, cloneWorkflowChain(*chain))
	}
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].ChainID < chains[j].ChainID
	})

	return &WorkflowChainArtifact{
		Version: WorkflowChainVersion,
		Summary: summarizeWorkflowChains(chains),
		Chains:  chains,
	}
}

func WorkflowChainRefsByPath(artifact *WorkflowChainArtifact) map[string][]string {
	byPath := map[string][]string{}
	if artifact == nil {
		return byPath
	}
	for _, chain := range artifact.Chains {
		for _, pathID := range chain.PathIDs {
			trimmed := strings.TrimSpace(pathID)
			if trimmed == "" {
				continue
			}
			byPath[trimmed] = uniqueSortedStrings(append(byPath[trimmed], chain.ChainID))
		}
	}
	return byPath
}

func buildWorkflowChain(input WorkflowChainInput) WorkflowChain {
	repo := newWorkflowChainDimension(
		dimensionKey(input.Repo, "unknown_repo"),
		dimensionLabel(input.Repo, "unknown_repo"),
		presenceStatus(input.Repo),
		[]string{input.Repo},
	)
	pullRequest := pullRequestDimension(input.IntroducedBy)
	workflow := newWorkflowChainDimension(
		dimensionKey(input.Location, "unknown_workflow"),
		dimensionLabel(input.Location, "unknown_workflow"),
		presenceStatus(input.Location),
		[]string{input.Location},
	)
	task := taskDimension(input.Purpose, input.PurposeSource, input.Location)
	tool := toolDimension(input)
	credential := credentialDimension(input)
	owner := ownerDimension(input)
	approval := approvalDimension(input)
	target := targetDimension(input)
	evidence := evidenceDimension(input)
	outcome := outcomeDimension(input)

	autonomyTier := strings.TrimSpace(input.AutonomyTier)
	readiness := strings.TrimSpace(input.DelegationReadinessState)
	recommendedControl := strings.TrimSpace(input.RecommendedControl)
	targetClass := strings.TrimSpace(input.TargetClass)
	evidenceCompleteness := strings.TrimSpace(input.EvidenceCompletenessLabel)

	rawID := strings.Join([]string{
		repo.Key,
		pullRequest.Key,
		workflow.Key,
		task.Key,
		tool.Key,
		credential.Key,
		owner.Key,
		approval.Key,
		target.Key,
		evidence.Key,
		outcome.Key,
		autonomyTier,
		readiness,
		recommendedControl,
		targetClass,
		evidenceCompleteness,
	}, "|")

	return WorkflowChain{
		ChainID:                  stableWorkflowChainID(rawID),
		PathIDs:                  uniqueSortedStrings([]string{input.PathID}),
		GraphNodeRefs:            uniqueSortedStrings(input.GraphNodeRefs),
		GraphEdgeRefs:            uniqueSortedStrings(input.GraphEdgeRefs),
		ProofRefs:                uniqueSortedStrings(input.ProofRefs),
		EvidenceRefs:             uniqueSortedStrings(input.EvidenceRefs),
		SourceFindingKeys:        uniqueSortedStrings(input.SourceFindingKeys),
		IntroducedBy:             cloneIntroducedBy(input.IntroducedBy),
		Repo:                     repo,
		PullRequest:              pullRequest,
		Workflow:                 workflow,
		Task:                     task,
		Tool:                     tool,
		Credential:               credential,
		Owner:                    owner,
		Approval:                 approval,
		Target:                   target,
		Evidence:                 evidence,
		Outcome:                  outcome,
		AutonomyTier:             autonomyTier,
		DelegationReadinessState: readiness,
		RecommendedControl:       recommendedControl,
		TargetClass:              targetClass,
		EvidenceCompleteness:     evidenceCompleteness,
	}
}

func summarizeWorkflowChains(chains []WorkflowChain) WorkflowChainSummary {
	summary := WorkflowChainSummary{TotalChains: len(chains)}
	repoCounts := map[string]int{}
	workflowCounts := map[string]int{}
	autonomyCounts := map[string]int{}
	readinessCounts := map[string]int{}
	controlCounts := map[string]int{}
	targetClassCounts := map[string]int{}
	evidenceCounts := map[string]int{}

	for _, chain := range chains {
		repoCounts[dimensionKey(chain.Repo.Key, "unknown_repo")]++
		workflowCounts[dimensionKey(chain.Workflow.Key, "unknown_workflow")]++
		autonomyCounts[dimensionKey(chain.AutonomyTier, "unknown")]++
		readinessCounts[dimensionKey(chain.DelegationReadinessState, "unknown")]++
		controlCounts[dimensionKey(chain.RecommendedControl, "unknown")]++
		targetClassCounts[dimensionKey(chain.TargetClass, "unknown")]++
		evidenceCounts[dimensionKey(chain.EvidenceCompleteness, "unknown")]++
	}

	summary.Repos = summarizeWorkflowChainRollups(repoCounts)
	summary.Workflows = summarizeWorkflowChainRollups(workflowCounts)
	summary.AutonomyTiers = summarizeWorkflowChainRollups(autonomyCounts)
	summary.DelegationReadinessStates = summarizeWorkflowChainRollups(readinessCounts)
	summary.RecommendedControls = summarizeWorkflowChainRollups(controlCounts)
	summary.TargetClasses = summarizeWorkflowChainRollups(targetClassCounts)
	summary.EvidenceCompleteness = summarizeWorkflowChainRollups(evidenceCounts)
	return summary
}

func summarizeWorkflowChainRollups(counts map[string]int) []WorkflowChainRollup {
	if len(counts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]WorkflowChainRollup, 0, len(keys))
	for _, key := range keys {
		out = append(out, WorkflowChainRollup{Value: key, Count: counts[key]})
	}
	return out
}

func pullRequestDimension(result *attribution.Result) WorkflowChainDimension {
	if result == nil {
		return newWorkflowChainDimension("unknown_pr", "unknown_pr", "unknown", nil)
	}
	label := "unknown_pr"
	key := "unknown_pr"
	if result.PRNumber > 0 {
		label = fmt.Sprintf("PR #%d", result.PRNumber)
		key = fmt.Sprintf("pr:%d", result.PRNumber)
	}
	return newWorkflowChainDimension(key, label, attributionStatus(result), []string{result.ProviderURL, result.ChangedFile})
}

func taskDimension(purpose, purposeSource, location string) WorkflowChainDimension {
	if strings.TrimSpace(purpose) != "" {
		return newWorkflowChainDimension("task:"+strings.TrimSpace(purpose), strings.TrimSpace(purpose), "declared", []string{purposeSource})
	}
	if strings.TrimSpace(purposeSource) != "" {
		return newWorkflowChainDimension("task_source:"+strings.TrimSpace(purposeSource), "unknown_task", "unknown", []string{purposeSource, location})
	}
	return newWorkflowChainDimension("unknown_task", "unknown_task", "unknown", []string{location})
}

func toolDimension(input WorkflowChainInput) WorkflowChainDimension {
	label := firstNonEmpty(input.ToolInstanceID, input.ToolFamilyID, input.ToolType)
	if label == "" {
		return newWorkflowChainDimension("unknown_tool", "unknown_tool", "unknown", nil)
	}
	return newWorkflowChainDimension("tool:"+label, label, "present", []string{input.Location})
}

func credentialDimension(input WorkflowChainInput) WorkflowChainDimension {
	if input.CredentialAuthority != nil && strings.TrimSpace(input.CredentialAuthority.CredentialKind) != "" {
		status := "present"
		if !input.CredentialAuthority.CredentialUsableByPath {
			status = "declared"
		}
		label := strings.TrimSpace(input.CredentialAuthority.CredentialKind)
		return newWorkflowChainDimension("credential:"+label, label, status, append([]string(nil), input.CredentialAuthority.ReasonCodes...))
	}
	if input.CredentialProvenance != nil {
		label := firstNonEmpty(input.CredentialProvenance.CredentialKind, input.CredentialProvenance.Type)
		if label == "" {
			label = "credential_access"
		}
		return newWorkflowChainDimension("credential:"+label, label, "declared", append([]string(nil), input.CredentialProvenance.EvidenceBasis...))
	}
	if input.CredentialAccess {
		return newWorkflowChainDimension("credential_access", "credential_access", "unknown", nil)
	}
	return newWorkflowChainDimension("unknown_credential", "unknown_credential", "unknown", nil)
}

func ownerDimension(input WorkflowChainInput) WorkflowChainDimension {
	if strings.TrimSpace(input.OperationalOwner) == "" {
		return newWorkflowChainDimension("unknown_owner", "unknown_owner", "unknown", nil)
	}
	return newWorkflowChainDimension("owner:"+strings.TrimSpace(input.OperationalOwner), strings.TrimSpace(input.OperationalOwner), "declared", nil)
}

func approvalDimension(input WorkflowChainInput) WorkflowChainDimension {
	state := strongestWorkflowChainStatus(input.ApprovalEvidenceState, input.ControlResolutionState)
	if state == "" {
		state = "unknown"
	}
	label := "approval:" + state
	if state == "contradictory_control" {
		label = "approval:contradictory"
		state = "contradictory"
	}
	return newWorkflowChainDimension("approval:"+state, label, state, nil)
}

func targetDimension(input WorkflowChainInput) WorkflowChainDimension {
	targets := uniqueSortedStrings(input.MatchedProductionTargets)
	if len(targets) > 0 {
		status := firstNonEmpty(strings.TrimSpace(input.TargetEvidenceState), "present")
		label := strings.Join(targets, ",")
		return newWorkflowChainDimension("target:"+label, label, status, targets)
	}
	if strings.TrimSpace(input.TargetClass) != "" {
		return newWorkflowChainDimension("target_class:"+strings.TrimSpace(input.TargetClass), strings.TrimSpace(input.TargetClass), "unknown", nil)
	}
	return newWorkflowChainDimension("unknown_target", "unknown_target", "unknown", nil)
}

func evidenceDimension(input WorkflowChainInput) WorkflowChainDimension {
	label := firstNonEmpty(strings.TrimSpace(input.EvidenceCompletenessLabel), strongestWorkflowChainStatus(input.ProofEvidenceState, input.RuntimeEvidenceState, input.TargetEvidenceState), "unknown_evidence")
	status := strongestWorkflowChainStatus(input.ProofEvidenceState, input.RuntimeEvidenceState, input.TargetEvidenceState)
	if status == "" {
		status = "unknown"
	}
	return newWorkflowChainDimension("evidence:"+label, label, status, append(append([]string(nil), input.EvidenceRefs...), input.ProofRefs...))
}

func outcomeDimension(input WorkflowChainInput) WorkflowChainDimension {
	if strings.TrimSpace(input.DeliveryChainStatus) != "" {
		return newWorkflowChainDimension("outcome:"+strings.TrimSpace(input.DeliveryChainStatus), strings.TrimSpace(input.DeliveryChainStatus), "declared", nil)
	}
	if strings.TrimSpace(input.DeploymentStatus) != "" {
		return newWorkflowChainDimension("outcome:"+strings.TrimSpace(input.DeploymentStatus), strings.TrimSpace(input.DeploymentStatus), "declared", nil)
	}
	if len(input.MatchedProductionTargets) > 0 || strings.TrimSpace(input.TargetClass) != "" {
		status := strongestWorkflowChainStatus(input.ProofEvidenceState, input.RuntimeEvidenceState)
		if status == "" {
			status = "unknown"
		}
		return newWorkflowChainDimension("unknown_outcome", "unknown_outcome", status, append([]string(nil), input.ProofRefs...))
	}
	return newWorkflowChainDimension("unknown_outcome", "unknown_outcome", "unknown", nil)
}

func newWorkflowChainDimension(key, label, status string, evidenceRefs []string) WorkflowChainDimension {
	return WorkflowChainDimension{
		Key:          dimensionKey(key, "unknown"),
		Label:        strings.TrimSpace(label),
		Status:       dimensionKey(status, "unknown"),
		EvidenceRefs: uniqueSortedStrings(evidenceRefs),
	}
}

func stableWorkflowChainID(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return "wch-" + hex.EncodeToString(sum[:6])
}

func attributionStatus(result *attribution.Result) string {
	if result == nil {
		return "unknown"
	}
	switch strings.TrimSpace(result.Confidence) {
	case attribution.ConfidenceHigh:
		return "verified"
	case attribution.ConfidenceLow:
		return "inferred"
	default:
		return "unknown"
	}
}

func strongestWorkflowChainStatus(values ...string) string {
	bestRank := -1
	best := ""
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		rank := workflowChainStatusRank(normalized)
		if rank > bestRank {
			bestRank = rank
			best = normalized
		}
	}
	return best
}

func workflowChainStatusRank(value string) int {
	switch strings.TrimSpace(value) {
	case "contradictory", "contradictory_control":
		return 5
	case "verified":
		return 4
	case "declared", "present":
		return 3
	case "inferred":
		return 2
	case "unknown", "missing":
		return 1
	default:
		return 0
	}
}

func presenceStatus(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return "present"
}

func dimensionKey(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(value)
}

func dimensionLabel(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
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

func cloneWorkflowChain(in WorkflowChain) WorkflowChain {
	out := in
	out.PathIDs = append([]string(nil), in.PathIDs...)
	out.GraphNodeRefs = append([]string(nil), in.GraphNodeRefs...)
	out.GraphEdgeRefs = append([]string(nil), in.GraphEdgeRefs...)
	out.ProofRefs = append([]string(nil), in.ProofRefs...)
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	out.SourceFindingKeys = append([]string(nil), in.SourceFindingKeys...)
	out.IntroducedBy = cloneIntroducedBy(in.IntroducedBy)
	out.Repo = cloneWorkflowChainDimension(in.Repo)
	out.PullRequest = cloneWorkflowChainDimension(in.PullRequest)
	out.Workflow = cloneWorkflowChainDimension(in.Workflow)
	out.Task = cloneWorkflowChainDimension(in.Task)
	out.Tool = cloneWorkflowChainDimension(in.Tool)
	out.Credential = cloneWorkflowChainDimension(in.Credential)
	out.Owner = cloneWorkflowChainDimension(in.Owner)
	out.Approval = cloneWorkflowChainDimension(in.Approval)
	out.Target = cloneWorkflowChainDimension(in.Target)
	out.Evidence = cloneWorkflowChainDimension(in.Evidence)
	out.Outcome = cloneWorkflowChainDimension(in.Outcome)
	return out
}

func cloneWorkflowChainDimension(in WorkflowChainDimension) WorkflowChainDimension {
	out := in
	out.Key = strings.TrimSpace(out.Key)
	out.Label = strings.TrimSpace(out.Label)
	out.Status = strings.TrimSpace(out.Status)
	out.EvidenceRefs = append([]string(nil), in.EvidenceRefs...)
	return out
}

func cloneIntroducedBy(in *attribution.Result) *attribution.Result {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}
