package report

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

const AgentActionBOMSchemaVersion = "v1"

type AgentActionBOM struct {
	BOMID         string                  `json:"bom_id"`
	SchemaVersion string                  `json:"schema_version"`
	GeneratedAt   string                  `json:"generated_at"`
	Summary       AgentActionBOMSummary   `json:"summary"`
	Items         []AgentActionBOMItem    `json:"items,omitempty"`
	GraphRefs     AgentActionBOMGraphRefs `json:"graph_refs,omitempty"`
	EvidenceRefs  []string                `json:"evidence_refs,omitempty"`
	ProofRefs     []string                `json:"proof_refs,omitempty"`
}

type AgentActionBOMSummary struct {
	TotalItems             int `json:"total_items"`
	ControlFirstItems      int `json:"control_first_items"`
	StandingPrivilegeItems int `json:"standing_privilege_items"`
	StaticCredentialItems  int `json:"static_credential_items"`
	ProductionTargetItems  int `json:"production_target_items"`
	MissingApprovalItems   int `json:"missing_approval_items"`
	MissingPolicyItems     int `json:"missing_policy_items"`
	MissingProofItems      int `json:"missing_proof_items"`
	RuntimeProvenItems     int `json:"runtime_proven_items"`
	UnresolvedOwnerItems   int `json:"unresolved_owner_items"`
}

type AgentActionBOMItem struct {
	PathID                   string                             `json:"path_id"`
	AgentID                  string                             `json:"agent_id,omitempty"`
	Org                      string                             `json:"org"`
	Repo                     string                             `json:"repo"`
	ToolType                 string                             `json:"tool_type"`
	Location                 string                             `json:"location,omitempty"`
	Owner                    string                             `json:"owner,omitempty"`
	OwnerSource              string                             `json:"owner_source,omitempty"`
	OwnershipStatus          string                             `json:"ownership_status,omitempty"`
	OwnershipState           string                             `json:"ownership_state,omitempty"`
	CredentialAccess         bool                               `json:"credential_access"`
	CredentialProvenance     *agginventory.CredentialProvenance `json:"credential_provenance,omitempty"`
	StandingPrivilege        bool                               `json:"standing_privilege,omitempty"`
	StandingPrivilegeReasons []string                           `json:"standing_privilege_reasons,omitempty"`
	ActionClasses            []string                           `json:"action_classes,omitempty"`
	ActionReasons            []string                           `json:"action_reasons,omitempty"`
	ProductionWrite          bool                               `json:"production_write,omitempty"`
	ProductionTargetStatus   string                             `json:"production_target_status,omitempty"`
	MatchedProductionTargets []string                           `json:"matched_production_targets,omitempty"`
	ApprovalGap              bool                               `json:"approval_gap"`
	ApprovalGapReasons       []string                           `json:"approval_gap_reasons,omitempty"`
	PolicyStatus             string                             `json:"policy_status,omitempty"`
	PolicyRefs               []string                           `json:"policy_refs,omitempty"`
	PolicyMissingReasons     []string                           `json:"policy_missing_reasons,omitempty"`
	PolicyStatusReasons      []string                           `json:"policy_status_reasons,omitempty"`
	PolicyConfidence         string                             `json:"policy_confidence,omitempty"`
	PolicyEvidenceRefs       []string                           `json:"policy_evidence_refs,omitempty"`
	ProofCoverage            string                             `json:"proof_coverage,omitempty"`
	ProofRefs                []string                           `json:"proof_refs,omitempty"`
	RuntimeEvidenceStatus    string                             `json:"runtime_evidence_status,omitempty"`
	RuntimeEvidenceClasses   []string                           `json:"runtime_evidence_classes,omitempty"`
	RuntimeEvidenceRefs      []string                           `json:"runtime_evidence_refs,omitempty"`
	ControlPriority          string                             `json:"control_priority,omitempty"`
	RecommendedNextAction    string                             `json:"recommended_next_action,omitempty"`
	GraphRefs                AgentActionBOMGraphRefs            `json:"graph_refs,omitempty"`
	EvidenceRefs             []string                           `json:"evidence_refs,omitempty"`
	Reachability             []AgentActionBOMReachability       `json:"reachability,omitempty"`
	IntroducedBy             *attribution.Result                `json:"introduced_by,omitempty"`
}

type AgentActionBOMGraphRefs struct {
	NodeIDs []string `json:"node_ids,omitempty"`
	EdgeIDs []string `json:"edge_ids,omitempty"`
}

type AgentActionBOMReachability struct {
	Surface      string                   `json:"surface"`
	Name         string                   `json:"name,omitempty"`
	Capabilities []string                 `json:"capabilities,omitempty"`
	TrustDepth   *agginventory.TrustDepth `json:"trust_depth,omitempty"`
	EvidenceRefs []string                 `json:"evidence_refs,omitempty"`
}

func BuildAgentActionBOM(summary Summary) *AgentActionBOM {
	return buildAgentActionBOM(summary, nil)
}

func buildAgentActionBOM(summary Summary, findings []model.Finding) *AgentActionBOM {
	if len(summary.ActionPaths) == 0 {
		return nil
	}

	backlogByPath := backlogItemsByPath(summary.ControlBacklog)
	graphRefsByPath, graphRefs := controlPathGraphRefs(summary.ControlPathGraph)
	runtimeByPath := runtimeEvidenceByPath(summary.RuntimeEvidence)
	reachabilityByPath := reachabilityByPathID(summary.ActionPaths, findings)
	proofRefs := proofRefs(summary.Proof)

	items := make([]AgentActionBOMItem, 0, len(summary.ActionPaths))
	counts := AgentActionBOMSummary{}
	for _, path := range summary.ActionPaths {
		itemGraphRefs := graphRefsByPath[strings.TrimSpace(path.PathID)]
		runtimeItem := runtimeByPath[strings.TrimSpace(path.PathID)]
		backlogItem := backlogByPath[strings.TrimSpace(path.PathID)]
		item := AgentActionBOMItem{
			PathID:                   strings.TrimSpace(path.PathID),
			AgentID:                  strings.TrimSpace(path.AgentID),
			Org:                      strings.TrimSpace(path.Org),
			Repo:                     strings.TrimSpace(path.Repo),
			ToolType:                 strings.TrimSpace(path.ToolType),
			Location:                 strings.TrimSpace(path.Location),
			Owner:                    strings.TrimSpace(path.OperationalOwner),
			OwnerSource:              strings.TrimSpace(path.OwnerSource),
			OwnershipStatus:          strings.TrimSpace(path.OwnershipStatus),
			OwnershipState:           strings.TrimSpace(path.OwnershipState),
			CredentialAccess:         path.CredentialAccess,
			CredentialProvenance:     agginventory.CloneCredentialProvenance(path.CredentialProvenance),
			StandingPrivilege:        path.StandingPrivilege,
			StandingPrivilegeReasons: append([]string(nil), path.StandingPrivilegeReasons...),
			ActionClasses:            append([]string(nil), path.ActionClasses...),
			ActionReasons:            append([]string(nil), path.ActionReasons...),
			ProductionWrite:          path.ProductionWrite,
			ProductionTargetStatus:   strings.TrimSpace(path.ProductionTargetStatus),
			MatchedProductionTargets: append([]string(nil), path.MatchedProductionTargets...),
			ApprovalGap:              path.ApprovalGap,
			ApprovalGapReasons:       append([]string(nil), path.ApprovalGapReasons...),
			PolicyStatus:             firstNonEmptyValue(path.PolicyCoverageStatus, risk.PolicyCoverageStatusNone),
			ProofCoverage:            proofCoverage(summary.Proof),
			ProofRefs:                append([]string(nil), proofRefs...),
			RuntimeEvidenceStatus:    runtimeItem.Status,
			RuntimeEvidenceClasses:   append([]string(nil), runtimeItem.EvidenceClasses...),
			RuntimeEvidenceRefs:      append([]string(nil), runtimeItem.RecordIDs...),
			ControlPriority:          strings.TrimSpace(path.RecommendedAction),
			RecommendedNextAction:    strings.TrimSpace(path.RecommendedAction),
			GraphRefs:                itemGraphRefs,
			Reachability:             append([]AgentActionBOMReachability(nil), reachabilityByPath[strings.TrimSpace(path.PathID)]...),
			PolicyRefs:               append([]string(nil), path.PolicyRefs...),
			PolicyMissingReasons:     append([]string(nil), path.PolicyMissingReasons...),
			PolicyStatusReasons:      append([]string(nil), path.PolicyStatusReasons...),
			PolicyConfidence:         strings.TrimSpace(path.PolicyConfidence),
			PolicyEvidenceRefs:       append([]string(nil), path.PolicyEvidenceRefs...),
			IntroducedBy:             attribution.Merge(path.IntroducedBy, nil),
		}
		item.EvidenceRefs = itemEvidenceRefs(path, backlogItem, runtimeItem, itemGraphRefs)
		items = append(items, item)

		counts.TotalItems++
		if summary.ActionPathToControlFirst != nil && strings.TrimSpace(summary.ActionPathToControlFirst.Path.PathID) == item.PathID {
			counts.ControlFirstItems++
		}
		if item.StandingPrivilege {
			counts.StandingPrivilegeItems++
		}
		if isStaticCredentialItem(item.CredentialProvenance) {
			counts.StaticCredentialItems++
		}
		if item.ProductionWrite || len(item.MatchedProductionTargets) > 0 {
			counts.ProductionTargetItems++
		}
		if item.ApprovalGap {
			counts.MissingApprovalItems++
		}
		if item.PolicyStatus == "none" {
			counts.MissingPolicyItems++
		}
		if item.ProofCoverage == "missing" {
			counts.MissingProofItems++
		}
		if item.PolicyStatus == risk.PolicyCoverageStatusRuntimeProven || item.RuntimeEvidenceStatus == ingest.CorrelationStatusMatched {
			counts.RuntimeProvenItems++
		}
		if bomItemHasWeakOwnership(path) {
			counts.UnresolvedOwnerItems++
		}
	}

	return &AgentActionBOM{
		BOMID:         agentActionBOMID(summary, items),
		SchemaVersion: AgentActionBOMSchemaVersion,
		GeneratedAt:   summary.GeneratedAt,
		Summary:       counts,
		Items:         items,
		GraphRefs:     graphRefs,
		EvidenceRefs:  summaryEvidenceRefs(items),
		ProofRefs:     proofRefs,
	}
}

func buildAgentActionBOMFromSnapshot(summary Summary, snapshot state.Snapshot) *AgentActionBOM {
	return buildAgentActionBOM(summary, snapshot.Findings)
}

func agentActionBOMID(summary Summary, items []AgentActionBOMItem) string {
	parts := []string{SummaryVersion, strings.TrimSpace(summary.Proof.HeadHash)}
	for _, item := range items {
		parts = append(parts, strings.TrimSpace(item.PathID), strings.TrimSpace(item.Org), strings.TrimSpace(item.Repo))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "bom-" + hex.EncodeToString(sum[:6])
}

func backlogItemsByPath(backlog *controlbacklog.Backlog) map[string]controlbacklog.Item {
	out := map[string]controlbacklog.Item{}
	if backlog == nil {
		return out
	}
	for _, item := range backlog.Items {
		if strings.TrimSpace(item.LinkedActionPathID) == "" {
			continue
		}
		out[strings.TrimSpace(item.LinkedActionPathID)] = item
	}
	return out
}

func controlPathGraphRefs(graph *aggattack.ControlPathGraph) (map[string]AgentActionBOMGraphRefs, AgentActionBOMGraphRefs) {
	byPath := map[string]AgentActionBOMGraphRefs{}
	if graph == nil {
		return byPath, AgentActionBOMGraphRefs{}
	}
	all := AgentActionBOMGraphRefs{}
	for _, node := range graph.Nodes {
		key := strings.TrimSpace(node.PathID)
		item := byPath[key]
		item.NodeIDs = append(item.NodeIDs, strings.TrimSpace(node.NodeID))
		byPath[key] = item
		all.NodeIDs = append(all.NodeIDs, strings.TrimSpace(node.NodeID))
	}
	for _, edge := range graph.Edges {
		key := strings.TrimSpace(edge.PathID)
		item := byPath[key]
		item.EdgeIDs = append(item.EdgeIDs, strings.TrimSpace(edge.EdgeID))
		byPath[key] = item
		all.EdgeIDs = append(all.EdgeIDs, strings.TrimSpace(edge.EdgeID))
	}
	for key, refs := range byPath {
		refs.NodeIDs = uniqueSortedStrings(refs.NodeIDs)
		refs.EdgeIDs = uniqueSortedStrings(refs.EdgeIDs)
		byPath[key] = refs
	}
	all.NodeIDs = uniqueSortedStrings(all.NodeIDs)
	all.EdgeIDs = uniqueSortedStrings(all.EdgeIDs)
	return byPath, all
}

func runtimeEvidenceByPath(summary *ingest.Summary) map[string]ingest.Correlation {
	out := map[string]ingest.Correlation{}
	if summary == nil {
		return out
	}
	for _, item := range summary.Correlations {
		if strings.TrimSpace(item.PathID) == "" {
			continue
		}
		out[strings.TrimSpace(item.PathID)] = item
	}
	return out
}

func proofRefs(proof ProofReference) []string {
	refs := []string{}
	if strings.TrimSpace(proof.HeadHash) != "" {
		refs = append(refs, "proof_head:"+strings.TrimSpace(proof.HeadHash))
	}
	if strings.TrimSpace(proof.ChainPath) != "" {
		refs = append(refs, "proof_chain:"+strings.TrimSpace(proof.ChainPath))
	}
	for _, key := range proof.CanonicalFindingKeys {
		refs = append(refs, "finding:"+strings.TrimSpace(key))
	}
	return uniqueSortedStrings(refs)
}

func proofCoverage(proof ProofReference) string {
	if strings.TrimSpace(proof.HeadHash) == "" {
		return "missing"
	}
	return "chain_attached"
}

func itemEvidenceRefs(path risk.ActionPath, backlog controlbacklog.Item, runtime ingest.Correlation, graphRefs AgentActionBOMGraphRefs) []string {
	refs := []string{}
	refs = append(refs, path.ApprovalGapReasons...)
	refs = append(refs, path.PolicyEvidenceRefs...)
	if path.CredentialProvenance != nil {
		refs = append(refs, path.CredentialProvenance.EvidenceBasis...)
		refs = append(refs, path.CredentialProvenance.ClassificationReasons...)
	}
	refs = append(refs, backlog.EvidenceBasis...)
	refs = append(refs, runtime.RecordIDs...)
	refs = append(refs, runtime.Sources...)
	refs = append(refs, graphRefs.NodeIDs...)
	refs = append(refs, graphRefs.EdgeIDs...)
	return uniqueSortedStrings(refs)
}

func isStaticCredentialItem(provenance *agginventory.CredentialProvenance) bool {
	normalized := agginventory.NormalizeCredentialProvenance(provenance)
	if normalized == nil {
		return false
	}
	switch normalized.CredentialKind {
	case agginventory.CredentialKindGitHubPAT,
		agginventory.CredentialKindGitHubAppKey,
		agginventory.CredentialKindDeployKey,
		agginventory.CredentialKindCloudAdminKey,
		agginventory.CredentialKindCloudAccessKey,
		agginventory.CredentialKindStaticSecret,
		agginventory.CredentialKindUnknownDurable:
		return true
	default:
		return normalized.Type == agginventory.CredentialProvenanceStaticSecret
	}
}

func summaryEvidenceRefs(items []AgentActionBOMItem) []string {
	refs := []string{}
	for _, item := range items {
		refs = append(refs, item.EvidenceRefs...)
	}
	return uniqueSortedStrings(refs)
}

func bomItemHasWeakOwnership(path risk.ActionPath) bool {
	return strings.TrimSpace(path.OwnerSource) == "multi_repo_conflict" ||
		strings.TrimSpace(path.OwnershipState) == "conflicting" ||
		strings.TrimSpace(path.OwnershipState) == "missing" ||
		strings.TrimSpace(path.OwnershipStatus) == "" ||
		strings.TrimSpace(path.OwnershipStatus) == "unresolved"
}

func reachabilityByPathID(paths []risk.ActionPath, findings []model.Finding) map[string][]AgentActionBOMReachability {
	if len(paths) == 0 || len(findings) == 0 {
		return map[string][]AgentActionBOMReachability{}
	}
	findingsByRepoLocation := map[string][]model.Finding{}
	for _, finding := range findings {
		key := strings.Join([]string{strings.TrimSpace(finding.Org), strings.TrimSpace(finding.Repo), strings.TrimSpace(finding.Location)}, "|")
		findingsByRepoLocation[key] = append(findingsByRepoLocation[key], finding)
	}

	out := map[string][]AgentActionBOMReachability{}
	for _, path := range paths {
		key := strings.Join([]string{strings.TrimSpace(path.Org), strings.TrimSpace(path.Repo), strings.TrimSpace(path.Location)}, "|")
		items := []AgentActionBOMReachability{}
		for _, finding := range findingsByRepoLocation[key] {
			switch strings.TrimSpace(finding.FindingType) {
			case "mcp_server":
				items = append(items, AgentActionBOMReachability{
					Surface:      "mcp_server",
					Name:         firstEvidenceValue(finding, "server"),
					Capabilities: append([]string(nil), finding.Permissions...),
					TrustDepth:   agginventory.TrustDepthFromFinding(finding),
					EvidenceRefs: findingEvidenceRefs(finding),
				})
			case "a2a_agent_card":
				items = append(items, AgentActionBOMReachability{
					Surface:      "a2a_agent",
					Name:         firstEvidenceValue(finding, "agent_name"),
					Capabilities: splitEvidenceList(firstEvidenceValue(finding, "capabilities")),
					TrustDepth:   agginventory.TrustDepthFromFinding(finding),
					EvidenceRefs: findingEvidenceRefs(finding),
				})
			}
		}
		if len(items) > 0 {
			sort.Slice(items, func(i, j int) bool {
				if items[i].Surface != items[j].Surface {
					return items[i].Surface < items[j].Surface
				}
				return items[i].Name < items[j].Name
			})
			out[strings.TrimSpace(path.PathID)] = items
		}
	}
	return out
}

func firstEvidenceValue(finding model.Finding, key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) == key {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func splitEvidenceList(value string) []string {
	parts := strings.Split(strings.TrimSpace(value), ",")
	out := make([]string, 0, len(parts))
	for _, item := range parts {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return uniqueSortedStrings(out)
}

func findingEvidenceRefs(finding model.Finding) []string {
	out := []string{}
	for _, item := range finding.Evidence {
		if strings.TrimSpace(item.Key) == "" || strings.TrimSpace(item.Value) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(item.Key)+":"+strings.TrimSpace(item.Value))
	}
	return uniqueSortedStrings(out)
}

func firstNonEmptyValue(values ...string) string {
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
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
