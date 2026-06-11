package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const EvidencePacketSchemaVersion = "v1"

type EvidencePacketBundle struct {
	SchemaVersion string           `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Packets       []EvidencePacket `json:"packets"`
}

type EvidencePacket struct {
	PacketID                 string   `json:"packet_id,omitempty"`
	Source                   string   `json:"source"`
	SourceType               string   `json:"source_type,omitempty"`
	Provider                 string   `json:"provider,omitempty"`
	ProviderURL              string   `json:"provider_url,omitempty"`
	Repo                     string   `json:"repo,omitempty"`
	Workflow                 string   `json:"workflow,omitempty"`
	PathID                   string   `json:"path_id,omitempty"`
	AgentID                  string   `json:"agent_id,omitempty"`
	PullRequestRef           string   `json:"pull_request_ref,omitempty"`
	Owner                    string   `json:"owner,omitempty"`
	Task                     string   `json:"task,omitempty"`
	Title                    string   `json:"title,omitempty"`
	FilesTouched             []string `json:"files_touched,omitempty"`
	DiffRefs                 []string `json:"diff_refs,omitempty"`
	DiffDigests              []string `json:"diff_digests,omitempty"`
	AutonomyTier             string   `json:"autonomy_tier,omitempty"`
	DelegationReadinessState string   `json:"delegation_readiness_state,omitempty"`
	Permissions              []string `json:"permissions,omitempty"`
	Credentials              []string `json:"credentials,omitempty"`
	Tests                    []string `json:"tests,omitempty"`
	Reviewers                []string `json:"reviewers,omitempty"`
	Approvals                []string `json:"approvals,omitempty"`
	DeploymentEnvironments   []string `json:"deployment_environments,omitempty"`
	PolicyVerdict            string   `json:"policy_verdict,omitempty"`
	ExceptionRefs            []string `json:"exception_refs,omitempty"`
	Result                   string   `json:"result,omitempty"`
	MissingEvidenceState     string   `json:"missing_evidence_state,omitempty"`
	MissingEvidence          []string `json:"missing_evidence,omitempty"`
	RuntimeProvider          string   `json:"runtime_provider,omitempty"`
	RuntimeHost              string   `json:"runtime_host,omitempty"`
	RuntimeKind              string   `json:"runtime_kind,omitempty"`
	ModelProvider            string   `json:"model_provider,omitempty"`
	ModelVersion             string   `json:"model_version,omitempty"`
	ExecutionEnvironment     string   `json:"execution_environment,omitempty"`
	StateRetentionStatus     string   `json:"state_retention_status,omitempty"`
	RetainedStateTypes       []string `json:"retained_state_types,omitempty"`
	StateLocationRefs        []string `json:"state_location_refs,omitempty"`
	StateDigestRefs          []string `json:"state_digest_refs,omitempty"`
	ProofRefs                []string `json:"proof_refs,omitempty"`
	GraphNodeRefs            []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs            []string `json:"graph_edge_refs,omitempty"`
	EvidenceRefs             []string `json:"evidence_refs,omitempty"`
	ObservedAt               string   `json:"observed_at"`
	RedactionHints           []string `json:"redaction_hints,omitempty"`
}

type EvidencePacketCorrelation struct {
	PacketID             string   `json:"packet_id"`
	PathID               string   `json:"path_id,omitempty"`
	AgentID              string   `json:"agent_id,omitempty"`
	Repo                 string   `json:"repo,omitempty"`
	Workflow             string   `json:"workflow,omitempty"`
	PullRequestRef       string   `json:"pull_request_ref,omitempty"`
	BoundaryLabel        string   `json:"boundary_label,omitempty"`
	Status               string   `json:"status"`
	Result               string   `json:"result,omitempty"`
	MissingEvidenceState string   `json:"missing_evidence_state,omitempty"`
	RuntimeProvider      string   `json:"runtime_provider,omitempty"`
	RuntimeHost          string   `json:"runtime_host,omitempty"`
	RuntimeKind          string   `json:"runtime_kind,omitempty"`
	ModelProvider        string   `json:"model_provider,omitempty"`
	ModelVersion         string   `json:"model_version,omitempty"`
	ExecutionEnvironment string   `json:"execution_environment,omitempty"`
	StateRetentionStatus string   `json:"state_retention_status,omitempty"`
	RetainedStateTypes   []string `json:"retained_state_types,omitempty"`
	StateLocationRefs    []string `json:"state_location_refs,omitempty"`
	StateDigestRefs      []string `json:"state_digest_refs,omitempty"`
	ProofRefs            []string `json:"proof_refs,omitempty"`
	GraphNodeRefs        []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs        []string `json:"graph_edge_refs,omitempty"`
	EvidenceRefs         []string `json:"evidence_refs,omitempty"`
	MissingEvidence      []string `json:"missing_evidence,omitempty"`
}

type EvidencePacketSummary struct {
	ArtifactPath     string                      `json:"artifact_path,omitempty"`
	BoundaryLabel    string                      `json:"boundary_label,omitempty"`
	TotalPackets     int                         `json:"total_packets"`
	MatchedPackets   int                         `json:"matched_packets"`
	UnmatchedPackets int                         `json:"unmatched_packets"`
	Correlations     []EvidencePacketCorrelation `json:"correlations,omitempty"`
}

type evidencePacketPathMatch struct {
	PathID          string
	AgentID         string
	Repo            string
	Location        string
	PullRequestRefs []string
	ProofRefs       []string
	GraphRefs       []string
	KnownFiles      []string
}

func DefaultEvidencePacketPath(statePath string) string {
	resolved := state.ResolvePath(strings.TrimSpace(statePath))
	return filepath.Join(filepath.Dir(resolved), "agentic-evidence-packets.json")
}

func LoadEvidencePacketBundle(path string) (EvidencePacketBundle, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller chooses explicit local ingest artifact path.
	if err != nil {
		return EvidencePacketBundle{}, fmt.Errorf("read evidence packet bundle: %w", err)
	}
	var bundle EvidencePacketBundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return EvidencePacketBundle{}, fmt.Errorf("parse evidence packet bundle: %w", err)
	}
	return NormalizeEvidencePacketBundle(bundle)
}

func LoadOptionalEvidencePacketBundle(statePath string) (EvidencePacketBundle, string, error) {
	path := DefaultEvidencePacketPath(statePath)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return EvidencePacketBundle{}, "", nil
		}
		return EvidencePacketBundle{}, "", fmt.Errorf("stat evidence packet bundle: %w", err)
	}
	bundle, err := LoadEvidencePacketBundle(path)
	if err != nil {
		return EvidencePacketBundle{}, "", err
	}
	return bundle, path, nil
}

func SaveEvidencePacketBundle(path string, bundle EvidencePacketBundle) error {
	normalized, err := NormalizeEvidencePacketBundle(bundle)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal evidence packet bundle: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write evidence packet bundle: %w", err)
	}
	return nil
}

func NormalizeEvidencePacketBundle(bundle EvidencePacketBundle) (EvidencePacketBundle, error) {
	if strings.TrimSpace(bundle.SchemaVersion) == "" {
		bundle.SchemaVersion = EvidencePacketSchemaVersion
	}
	if strings.TrimSpace(bundle.SchemaVersion) != EvidencePacketSchemaVersion {
		return EvidencePacketBundle{}, fmt.Errorf("unsupported evidence packet schema_version %q", bundle.SchemaVersion)
	}
	if strings.TrimSpace(bundle.GeneratedAt) == "" {
		bundle.GeneratedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	generatedAt, err := time.Parse(time.RFC3339, bundle.GeneratedAt)
	if err != nil {
		return EvidencePacketBundle{}, fmt.Errorf("evidence packet generated_at must be RFC3339")
	}
	packets := make([]EvidencePacket, 0, len(bundle.Packets))
	for _, packet := range bundle.Packets {
		normalized, err := normalizeEvidencePacket(packet, generatedAt)
		if err != nil {
			return EvidencePacketBundle{}, err
		}
		packets = append(packets, normalized)
	}
	sort.Slice(packets, func(i, j int) bool {
		if packets[i].Repo != packets[j].Repo {
			return packets[i].Repo < packets[j].Repo
		}
		if packets[i].Workflow != packets[j].Workflow {
			return packets[i].Workflow < packets[j].Workflow
		}
		if packets[i].ObservedAt != packets[j].ObservedAt {
			return packets[i].ObservedAt < packets[j].ObservedAt
		}
		return packets[i].PacketID < packets[j].PacketID
	})
	bundle.Packets = packets
	return bundle, nil
}

func normalizeEvidencePacket(packet EvidencePacket, _ time.Time) (EvidencePacket, error) {
	packet.PacketID = strings.TrimSpace(packet.PacketID)
	packet.Source = strings.TrimSpace(packet.Source)
	packet.SourceType = normalizeSourceType(packet.SourceType)
	packet.Provider = strings.TrimSpace(packet.Provider)
	packet.ProviderURL = strings.TrimSpace(packet.ProviderURL)
	packet.Repo = strings.TrimSpace(packet.Repo)
	packet.Workflow = filepath.ToSlash(strings.TrimSpace(packet.Workflow))
	packet.PathID = strings.TrimSpace(packet.PathID)
	packet.AgentID = strings.TrimSpace(packet.AgentID)
	packet.PullRequestRef = strings.TrimSpace(packet.PullRequestRef)
	packet.Owner = normalizeOwnerValue(packet.Owner)
	packet.Task = strings.TrimSpace(packet.Task)
	packet.Title = strings.TrimSpace(packet.Title)
	packet.FilesTouched = mergeStrings(packet.FilesTouched...)
	packet.DiffRefs = mergeStrings(packet.DiffRefs...)
	packet.DiffDigests = mergeStrings(packet.DiffDigests...)
	packet.AutonomyTier = strings.TrimSpace(packet.AutonomyTier)
	packet.DelegationReadinessState = strings.TrimSpace(packet.DelegationReadinessState)
	packet.Permissions = mergeStrings(packet.Permissions...)
	packet.Credentials = mergeStrings(packet.Credentials...)
	packet.Tests = mergeStrings(packet.Tests...)
	packet.Reviewers = mergeStrings(packet.Reviewers...)
	packet.Approvals = mergeStrings(packet.Approvals...)
	packet.DeploymentEnvironments = mergeStrings(packet.DeploymentEnvironments...)
	packet.PolicyVerdict = strings.TrimSpace(packet.PolicyVerdict)
	packet.ExceptionRefs = mergeStrings(packet.ExceptionRefs...)
	packet.MissingEvidence = mergeStrings(packet.MissingEvidence...)
	packet.RuntimeProvider = normalizeRuntimeContextValue(packet.RuntimeProvider)
	packet.RuntimeHost = normalizeRuntimeContextValue(packet.RuntimeHost)
	packet.RuntimeKind = normalizeRuntimeContextValue(packet.RuntimeKind)
	packet.ModelProvider = normalizeRuntimeContextValue(packet.ModelProvider)
	packet.ModelVersion = normalizeRuntimeContextValue(packet.ModelVersion)
	packet.ExecutionEnvironment = normalizeRuntimeContextValue(packet.ExecutionEnvironment)
	packet.StateRetentionStatus = normalizeStateRetentionStatus(packet.StateRetentionStatus)
	packet.RetainedStateTypes = normalizeRetainedStateTypes(packet.RetainedStateTypes)
	packet.StateLocationRefs = normalizeStateLocationRefs(packet.StateLocationRefs)
	packet.StateDigestRefs = normalizeStateDigestRefs(packet.StateDigestRefs)
	packet.Result = normalizePacketResult(packet.Result, len(packet.MissingEvidence))
	packet.MissingEvidenceState = normalizePacketMissingEvidenceState(packet.MissingEvidenceState, len(packet.MissingEvidence))
	packet.ProofRefs = mergeStrings(packet.ProofRefs...)
	packet.GraphNodeRefs = mergeStrings(packet.GraphNodeRefs...)
	packet.GraphEdgeRefs = mergeStrings(packet.GraphEdgeRefs...)
	packet.EvidenceRefs = mergeStrings(packet.EvidenceRefs...)
	packet.ObservedAt = strings.TrimSpace(packet.ObservedAt)
	packet.RedactionHints = mergeStrings(packet.RedactionHints...)
	if packet.Source == "" {
		return EvidencePacket{}, fmt.Errorf("evidence packet source is required")
	}
	if packet.ObservedAt == "" {
		return EvidencePacket{}, fmt.Errorf("evidence packet observed_at is required for %s", fallbackRecordLabel(firstNonEmpty(packet.PacketID, packet.PathID, packet.Repo, packet.Source)))
	}
	if _, err := time.Parse(time.RFC3339, packet.ObservedAt); err != nil {
		return EvidencePacket{}, fmt.Errorf("evidence packet observed_at must be RFC3339 for %s", fallbackRecordLabel(firstNonEmpty(packet.PacketID, packet.PathID, packet.Repo, packet.Source)))
	}
	if !evidencePacketHasCorrelationKey(packet) {
		return EvidencePacket{}, fmt.Errorf("evidence packet requires at least one correlation key (path_id, agent_id, repo+workflow, pull_request_ref, files_touched, proof_refs, or graph refs)")
	}
	if err := rejectSecretLikeEvidencePacketValues(packet); err != nil {
		return EvidencePacket{}, err
	}
	if err := validateEnterpriseContext(
		fmt.Sprintf("evidence packet %s", fallbackRecordLabel(firstNonEmpty(packet.PacketID, packet.PathID, packet.Repo, packet.Source))),
		packet.StateRetentionStatus,
		packet.RetainedStateTypes,
		packet.StateLocationRefs,
		packet.StateDigestRefs,
	); err != nil {
		return EvidencePacket{}, err
	}
	if packet.PacketID == "" {
		packet.PacketID = strings.Join([]string{
			firstNonEmpty(packet.PathID, packet.AgentID, repoScopedKey(packet.Repo, packet.Workflow), packet.PullRequestRef, packet.Source),
			packet.Result,
			packet.ObservedAt,
		}, ":")
	}
	return packet, nil
}

func CorrelateEvidencePackets(snapshot state.Snapshot, artifactPath string, bundle EvidencePacketBundle) EvidencePacketSummary {
	if normalized, err := NormalizeEvidencePacketBundle(bundle); err == nil {
		bundle = normalized
	}
	if len(bundle.Packets) == 0 {
		return EvidencePacketSummary{ArtifactPath: artifactPath}
	}
	index := buildEvidencePacketMatchIndex(snapshot)
	correlations := make([]EvidencePacketCorrelation, 0, len(bundle.Packets))
	matched := 0
	for _, packet := range bundle.Packets {
		pathID, status := matchEvidencePacket(index, packet)
		if status == CorrelationStatusMatched {
			matched++
		}
		correlations = append(correlations, EvidencePacketCorrelation{
			PacketID:             packet.PacketID,
			PathID:               pathID,
			AgentID:              packet.AgentID,
			Repo:                 packet.Repo,
			Workflow:             packet.Workflow,
			PullRequestRef:       packet.PullRequestRef,
			Status:               status,
			Result:               packet.Result,
			MissingEvidenceState: packet.MissingEvidenceState,
			RuntimeProvider:      packet.RuntimeProvider,
			RuntimeHost:          packet.RuntimeHost,
			RuntimeKind:          packet.RuntimeKind,
			ModelProvider:        packet.ModelProvider,
			ModelVersion:         packet.ModelVersion,
			ExecutionEnvironment: packet.ExecutionEnvironment,
			StateRetentionStatus: firstNonEmpty(packet.StateRetentionStatus, StateRetentionUnknown),
			RetainedStateTypes:   append([]string(nil), packet.RetainedStateTypes...),
			StateLocationRefs:    append([]string(nil), packet.StateLocationRefs...),
			StateDigestRefs:      append([]string(nil), packet.StateDigestRefs...),
			ProofRefs:            append([]string(nil), packet.ProofRefs...),
			GraphNodeRefs:        append([]string(nil), packet.GraphNodeRefs...),
			GraphEdgeRefs:        append([]string(nil), packet.GraphEdgeRefs...),
			EvidenceRefs:         append([]string(nil), packet.EvidenceRefs...),
			MissingEvidence:      append([]string(nil), packet.MissingEvidence...),
		})
	}
	sort.Slice(correlations, func(i, j int) bool {
		if correlations[i].Status != correlations[j].Status {
			return correlations[i].Status < correlations[j].Status
		}
		if correlations[i].PathID != correlations[j].PathID {
			return correlations[i].PathID < correlations[j].PathID
		}
		return correlations[i].PacketID < correlations[j].PacketID
	})
	return EvidencePacketSummary{
		ArtifactPath:     artifactPath,
		TotalPackets:     len(bundle.Packets),
		MatchedPackets:   matched,
		UnmatchedPackets: len(bundle.Packets) - matched,
		Correlations:     correlations,
	}
}

func evidencePacketHasCorrelationKey(packet EvidencePacket) bool {
	return strings.TrimSpace(packet.PathID) != "" ||
		strings.TrimSpace(packet.AgentID) != "" ||
		(strings.TrimSpace(packet.Repo) != "" && strings.TrimSpace(packet.Workflow) != "") ||
		strings.TrimSpace(packet.PullRequestRef) != "" ||
		len(packet.FilesTouched) > 0 ||
		len(packet.ProofRefs) > 0 ||
		len(packet.GraphNodeRefs) > 0 ||
		len(packet.GraphEdgeRefs) > 0
}

func rejectSecretLikeEvidencePacketValues(packet EvidencePacket) error {
	values := []string{
		packet.Source,
		packet.ProviderURL,
		packet.Owner,
		packet.Workflow,
		packet.PullRequestRef,
	}
	values = append(values, packet.FilesTouched...)
	values = append(values, packet.DiffRefs...)
	values = append(values, packet.ExceptionRefs...)
	values = append(values, packet.StateLocationRefs...)
	values = append(values, packet.EvidenceRefs...)
	for _, value := range values {
		if looksSecretLike(value) {
			return fmt.Errorf("evidence packet contains secret-like value for %s", fallbackRecordLabel(firstNonEmpty(packet.PacketID, packet.PathID, packet.Repo, packet.Source)))
		}
	}
	return nil
}

func normalizePacketResult(value string, missingCount int) string {
	switch strings.TrimSpace(value) {
	case "complete", "partial", "failed":
		return strings.TrimSpace(value)
	}
	if missingCount > 0 {
		return "partial"
	}
	return "complete"
}

func normalizePacketMissingEvidenceState(value string, missingCount int) string {
	switch strings.TrimSpace(value) {
	case "complete", "partial", "missing":
		return strings.TrimSpace(value)
	}
	if missingCount == 0 {
		return "complete"
	}
	if missingCount < 3 {
		return "partial"
	}
	return "missing"
}

func buildEvidencePacketMatchIndex(snapshot state.Snapshot) []evidencePacketPathMatch {
	if snapshot.RiskReport == nil {
		return nil
	}
	out := make([]evidencePacketPathMatch, 0, len(snapshot.RiskReport.ActionPaths))
	graphByPath := map[string][]string{}
	if snapshot.RiskReport.ControlPathGraph != nil {
		for _, node := range snapshot.RiskReport.ControlPathGraph.Nodes {
			pathID := strings.TrimSpace(node.PathID)
			if pathID == "" {
				continue
			}
			graphByPath[pathID] = append(graphByPath[pathID], strings.TrimSpace(node.NodeID))
		}
		for _, edge := range snapshot.RiskReport.ControlPathGraph.Edges {
			pathID := strings.TrimSpace(edge.PathID)
			if pathID == "" {
				continue
			}
			graphByPath[pathID] = append(graphByPath[pathID], strings.TrimSpace(edge.EdgeID))
		}
	}
	for _, path := range snapshot.RiskReport.ActionPaths {
		match := evidencePacketPathMatch{
			PathID:    strings.TrimSpace(path.PathID),
			AgentID:   strings.TrimSpace(path.AgentID),
			Repo:      strings.TrimSpace(path.Repo),
			Location:  filepath.ToSlash(strings.TrimSpace(path.Location)),
			ProofRefs: mergeStrings(path.PolicyEvidenceRefs...),
			GraphRefs: mergeStrings(graphByPath[strings.TrimSpace(path.PathID)]...),
		}
		if path.IntroducedBy != nil {
			if strings.TrimSpace(path.IntroducedBy.Reference) != "" {
				match.PullRequestRefs = append(match.PullRequestRefs, strings.TrimSpace(path.IntroducedBy.Reference))
			}
			if path.IntroducedBy.PRNumber > 0 {
				match.PullRequestRefs = append(match.PullRequestRefs, fmt.Sprintf("pr/%d", path.IntroducedBy.PRNumber))
			}
			if strings.TrimSpace(path.IntroducedBy.ChangedFile) != "" {
				match.KnownFiles = append(match.KnownFiles, filepath.ToSlash(strings.TrimSpace(path.IntroducedBy.ChangedFile)))
			}
			if path.IntroducedBy.Provenance != nil {
				if strings.TrimSpace(path.IntroducedBy.Provenance.Reference) != "" {
					match.PullRequestRefs = append(match.PullRequestRefs, strings.TrimSpace(path.IntroducedBy.Provenance.Reference))
				}
				match.KnownFiles = append(match.KnownFiles, path.IntroducedBy.Provenance.ChangedFiles...)
			}
		}
		match.PullRequestRefs = mergeStrings(match.PullRequestRefs...)
		match.KnownFiles = mergeStrings(append(match.KnownFiles, match.Location)...)
		out = append(out, match)
	}
	return out
}

func matchEvidencePacket(index []evidencePacketPathMatch, packet EvidencePacket) (string, string) {
	bestID := ""
	bestScore := -1
	conflict := false
	for _, candidate := range index {
		score := 0
		if packet.PathID != "" && packet.PathID == candidate.PathID {
			score += 10
		}
		if packet.AgentID != "" && packet.AgentID == candidate.AgentID {
			score += 6
		}
		if packet.Repo != "" && packet.Repo == candidate.Repo {
			score += 2
		}
		if packet.Workflow != "" && packet.Workflow == candidate.Location {
			score += 5
		}
		if packet.PullRequestRef != "" && containsString(candidate.PullRequestRefs, packet.PullRequestRef) {
			score += 5
		}
		if len(packet.ProofRefs) > 0 && anyStringOverlap(candidate.ProofRefs, packet.ProofRefs) {
			score += 4
		}
		packetGraphRefs := append(append([]string(nil), packet.GraphNodeRefs...), packet.GraphEdgeRefs...)
		if len(packetGraphRefs) > 0 && anyStringOverlap(candidate.GraphRefs, packetGraphRefs) {
			score += 4
		}
		if len(packet.FilesTouched) > 0 && anyStringOverlap(candidate.KnownFiles, packet.FilesTouched) {
			score += 4
		}
		switch {
		case score > bestScore:
			bestID = candidate.PathID
			bestScore = score
			conflict = false
		case score == bestScore && score > 0:
			conflict = true
		}
	}
	if bestScore <= 0 {
		return "", CorrelationStatusUnmatched
	}
	if conflict {
		return "", CorrelationStatusConflict
	}
	return bestID, CorrelationStatusMatched
}
