package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const SchemaVersion = "v1"

const (
	RecordKindRuntime         = "runtime"
	RecordKindExternalControl = "external_control"

	EvidenceClassPolicyDecision       = "policy_decision"
	EvidenceClassApproval             = "approval"
	EvidenceClassJITCredential        = "jit_credential" // #nosec G101 -- Deterministic runtime evidence label, not credential material.
	EvidenceClassFreezeWindow         = "freeze_window"
	EvidenceClassKillSwitch           = "kill_switch"
	EvidenceClassActionOutcome        = "action_outcome"
	EvidenceClassProofVerify          = "proof_verification"
	EvidenceClassOwnerAssignment      = "owner_assignment"
	EvidenceClassPolicyRecord         = "policy_record"
	EvidenceClassBranchProtection     = "branch_protection"
	EvidenceClassProtectedEnvironment = "protected_environment"
	EvidenceClassDeploymentApproval   = "deployment_approval"
	EvidenceClassRequiredCheck        = "required_check"
	EvidenceClassSecurityGate         = "security_gate"
	EvidenceClassOther                = "other"
	CorrelationStatusMatched          = "matched"
	CorrelationStatusUnmatched        = "unmatched"
	CorrelationStatusStale            = "stale"
	CorrelationStatusConflict         = "conflict"
)

type Bundle struct {
	SchemaVersion string   `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Records       []Record `json:"records"`
}

type Record struct {
	RecordKind          string   `json:"record_kind,omitempty"`
	SourceType          string   `json:"source_type,omitempty"`
	SourcePrecedenceKey string   `json:"source_precedence_key,omitempty"`
	RecordID            string   `json:"record_id"`
	PathID              string   `json:"path_id,omitempty"`
	AgentID             string   `json:"agent_id,omitempty"`
	Tool                string   `json:"tool,omitempty"`
	Repo                string   `json:"repo,omitempty"`
	Service             string   `json:"service,omitempty"`
	Workflow            string   `json:"workflow,omitempty"`
	Environment         string   `json:"environment,omitempty"`
	Path                string   `json:"path,omitempty"`
	Location            string   `json:"location,omitempty"`
	Target              string   `json:"target,omitempty"`
	ActionClasses       []string `json:"action_classes,omitempty"`
	PolicyRef           string   `json:"policy_ref,omitempty"`
	ProofRef            string   `json:"proof_ref,omitempty"`
	GraphNodeRefs       []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs       []string `json:"graph_edge_refs,omitempty"`
	Source              string   `json:"source"`
	Issuer              string   `json:"issuer,omitempty"`
	ObservedAt          string   `json:"observed_at"`
	ValidUntil          string   `json:"valid_until,omitempty"`
	MaxAge              string   `json:"max_age,omitempty"`
	Confidence          string   `json:"confidence,omitempty"`
	FreshnessState      string   `json:"freshness_state,omitempty"`
	RedactionHints      []string `json:"redaction_hints,omitempty"`
	EvidenceClass       string   `json:"evidence_class"`
	Status              string   `json:"status,omitempty"`
	EvidenceRefs        []string `json:"evidence_refs,omitempty"`
	Owner               string   `json:"owner,omitempty"`
	RequiredChecks      []string `json:"required_checks,omitempty"`
	Branch              string   `json:"branch,omitempty"`
}

type Correlation struct {
	PathID           string   `json:"path_id"`
	AgentID          string   `json:"agent_id,omitempty"`
	RecordKinds      []string `json:"record_kinds,omitempty"`
	SourceTypes      []string `json:"source_types,omitempty"`
	Tool             string   `json:"tool,omitempty"`
	Repo             string   `json:"repo,omitempty"`
	Service          string   `json:"service,omitempty"`
	Workflow         string   `json:"workflow,omitempty"`
	Environment      string   `json:"environment,omitempty"`
	Path             string   `json:"path,omitempty"`
	Location         string   `json:"location,omitempty"`
	Target           string   `json:"target,omitempty"`
	Status           string   `json:"status"`
	EvidenceClasses  []string `json:"evidence_classes,omitempty"`
	ActionClasses    []string `json:"action_classes,omitempty"`
	Sources          []string `json:"sources,omitempty"`
	PolicyRefs       []string `json:"policy_refs,omitempty"`
	ProofRefs        []string `json:"proof_refs,omitempty"`
	GraphNodeRefs    []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs    []string `json:"graph_edge_refs,omitempty"`
	RecordIDs        []string `json:"record_ids,omitempty"`
	RequiredChecks   []string `json:"required_checks,omitempty"`
	Owners           []string `json:"owners,omitempty"`
	UnmatchedReasons []string `json:"unmatched_reasons,omitempty"`
	LatestObservedAt string   `json:"latest_observed_at,omitempty"`
	FreshnessState   string   `json:"freshness_state,omitempty"`
	FreshnessStates  []string `json:"freshness_states,omitempty"`
	BoundaryLabel    string   `json:"boundary_label,omitempty"`
}

type Summary struct {
	ArtifactPath           string        `json:"artifact_path,omitempty"`
	BoundaryLabel          string        `json:"boundary_label,omitempty"`
	TotalRecords           int           `json:"total_records"`
	RuntimeRecords         int           `json:"runtime_records,omitempty"`
	ExternalControlRecords int           `json:"external_control_records,omitempty"`
	MatchedRecords         int           `json:"matched_records"`
	UnmatchedRecords       int           `json:"unmatched_records"`
	Correlations           []Correlation `json:"correlations,omitempty"`
}

func DefaultPath(statePath string) string {
	resolved := state.ResolvePath(strings.TrimSpace(statePath))
	return filepath.Join(filepath.Dir(resolved), "runtime-evidence.json")
}

func Load(path string) (Bundle, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller chooses explicit local ingest artifact path.
	if err != nil {
		return Bundle{}, fmt.Errorf("read runtime evidence: %w", err)
	}
	var bundle Bundle
	if err := json.Unmarshal(payload, &bundle); err != nil {
		return Bundle{}, fmt.Errorf("parse runtime evidence: %w", err)
	}
	return Normalize(bundle)
}

func LoadOptional(statePath string) (Bundle, string, error) {
	path := DefaultPath(statePath)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return Bundle{}, "", nil
		}
		return Bundle{}, "", fmt.Errorf("stat runtime evidence: %w", err)
	}
	bundle, err := Load(path)
	if err != nil {
		return Bundle{}, "", err
	}
	return bundle, path, nil
}

func Save(path string, bundle Bundle) error {
	normalized, err := Normalize(bundle)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime evidence: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write runtime evidence: %w", err)
	}
	return nil
}

func Normalize(bundle Bundle) (Bundle, error) {
	if strings.TrimSpace(bundle.SchemaVersion) == "" {
		bundle.SchemaVersion = SchemaVersion
	}
	if strings.TrimSpace(bundle.SchemaVersion) != SchemaVersion {
		return Bundle{}, fmt.Errorf("unsupported runtime evidence schema_version %q", bundle.SchemaVersion)
	}
	if strings.TrimSpace(bundle.GeneratedAt) == "" {
		bundle.GeneratedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	generatedAt, err := time.Parse(time.RFC3339, bundle.GeneratedAt)
	if err != nil {
		return Bundle{}, fmt.Errorf("runtime evidence generated_at must be RFC3339")
	}
	records := make([]Record, 0, len(bundle.Records))
	for _, record := range bundle.Records {
		normalized, err := normalizeRecord(record, generatedAt)
		if err != nil {
			return Bundle{}, err
		}
		records = append(records, normalized)
	}
	sort.Slice(records, func(i, j int) bool {
		if sourcePrecedenceSortKey(records[i]) != sourcePrecedenceSortKey(records[j]) {
			return sourcePrecedenceSortKey(records[i]) < sourcePrecedenceSortKey(records[j])
		}
		if records[i].PathID != records[j].PathID {
			return records[i].PathID < records[j].PathID
		}
		if records[i].AgentID != records[j].AgentID {
			return records[i].AgentID < records[j].AgentID
		}
		if records[i].Repo != records[j].Repo {
			return records[i].Repo < records[j].Repo
		}
		if records[i].Service != records[j].Service {
			return records[i].Service < records[j].Service
		}
		if records[i].Workflow != records[j].Workflow {
			return records[i].Workflow < records[j].Workflow
		}
		if records[i].Environment != records[j].Environment {
			return records[i].Environment < records[j].Environment
		}
		if records[i].Path != records[j].Path {
			return records[i].Path < records[j].Path
		}
		if records[i].Location != records[j].Location {
			return records[i].Location < records[j].Location
		}
		if records[i].EvidenceClass != records[j].EvidenceClass {
			return records[i].EvidenceClass < records[j].EvidenceClass
		}
		if records[i].ObservedAt != records[j].ObservedAt {
			return records[i].ObservedAt < records[j].ObservedAt
		}
		return records[i].RecordID < records[j].RecordID
	})
	bundle.Records = records
	return bundle, nil
}

func Correlate(snapshot state.Snapshot, artifactPath string, bundle Bundle) Summary {
	if normalized, err := Normalize(bundle); err == nil {
		bundle = normalized
	}
	if len(bundle.Records) == 0 {
		return Summary{ArtifactPath: artifactPath}
	}
	index := buildPathIndex(snapshot)

	byPath := map[string]*Correlation{}
	matched := 0
	runtimeRecords := 0
	externalControlRecords := 0
	for _, record := range bundle.Records {
		if normalizeRecordKind(record.RecordKind, record) == RecordKindExternalControl {
			externalControlRecords++
		} else {
			runtimeRecords++
		}
		matchPathID, matchedPath := index.match(record)
		key := strings.TrimSpace(matchPathID)
		if key == "" {
			key = fallbackCorrelationKey(record)
		}
		item := byPath[key]
		if item == nil {
			item = &Correlation{
				PathID:      firstNonEmpty(matchPathID, record.PathID, fallbackCorrelationKey(record)),
				AgentID:     firstNonEmpty(record.AgentID, matchedPath.AgentID),
				Workflow:    firstNonEmpty(record.Workflow, matchedPath.Workflow, record.Path, record.Location),
				Environment: firstNonEmpty(record.Environment, firstPathEnvironment(matchedPath)),
				Tool:        firstNonEmpty(record.Tool, matchedPath.ToolType),
				Repo:        firstNonEmpty(record.Repo, matchedPath.Repo),
				Service:     firstNonEmpty(record.Service, firstPathService(matchedPath)),
				Path:        firstNonEmpty(record.Path, matchedPath.Location, record.Workflow, record.Location),
				Location:    firstNonEmpty(record.Location, matchedPath.Location),
				Target:      firstNonEmpty(record.Target, firstPathTarget(matchedPath)),
			}
			byPath[key] = item
		}
		item.RecordKinds = mergeStrings(append(append([]string(nil), item.RecordKinds...), record.RecordKind)...)
		item.SourceTypes = mergeStrings(append(append([]string(nil), item.SourceTypes...), record.SourceType)...)
		item.EvidenceClasses = mergeStrings(append(append([]string(nil), item.EvidenceClasses...), record.EvidenceClass)...)
		item.ActionClasses = mergeStrings(append(append([]string(nil), item.ActionClasses...), record.ActionClasses...)...)
		item.Sources = mergeStrings(append(append([]string(nil), item.Sources...), record.Source)...)
		item.PolicyRefs = mergeStrings(append(append([]string(nil), item.PolicyRefs...), record.PolicyRef)...)
		item.ProofRefs = mergeStrings(append(append([]string(nil), item.ProofRefs...), record.ProofRef)...)
		item.GraphNodeRefs = mergeStrings(append(append([]string(nil), item.GraphNodeRefs...), record.GraphNodeRefs...)...)
		item.GraphEdgeRefs = mergeStrings(append(append([]string(nil), item.GraphEdgeRefs...), record.GraphEdgeRefs...)...)
		item.RecordIDs = mergeStrings(append(append([]string(nil), item.RecordIDs...), record.RecordID)...)
		item.RequiredChecks = mergeStrings(append(append([]string(nil), item.RequiredChecks...), record.RequiredChecks...)...)
		item.Owners = mergeStrings(append(append([]string(nil), item.Owners...), record.Owner)...)
		item.FreshnessStates = mergeStrings(append(append([]string(nil), item.FreshnessStates...), record.FreshnessState)...)
		item.FreshnessState = mergeFreshnessState(item.FreshnessState, record.FreshnessState)
		if item.LatestObservedAt == "" || strings.TrimSpace(record.ObservedAt) > item.LatestObservedAt {
			item.LatestObservedAt = strings.TrimSpace(record.ObservedAt)
		}
		status := correlationStatusForRecord(record, matchPathID != "")
		item.Status = mergeCorrelationStatus(item.Status, status)
		if status == CorrelationStatusUnmatched {
			item.UnmatchedReasons = mergeStrings(append(append([]string(nil), item.UnmatchedReasons...), unmatchedReasonsForRecord(record)...)...)
		}
		if status == CorrelationStatusMatched {
			matched++
		}
	}

	correlations := make([]Correlation, 0, len(byPath))
	for _, item := range byPath {
		correlations = append(correlations, *item)
	}
	sort.Slice(correlations, func(i, j int) bool {
		if correlations[i].Status != correlations[j].Status {
			return correlations[i].Status < correlations[j].Status
		}
		if correlations[i].PathID != correlations[j].PathID {
			return correlations[i].PathID < correlations[j].PathID
		}
		return correlations[i].AgentID < correlations[j].AgentID
	})

	return Summary{
		ArtifactPath:           artifactPath,
		TotalRecords:           len(bundle.Records),
		RuntimeRecords:         runtimeRecords,
		ExternalControlRecords: externalControlRecords,
		MatchedRecords:         matched,
		UnmatchedRecords:       len(bundle.Records) - matched,
		Correlations:           correlations,
	}
}

func normalizeRecord(record Record, generatedAt time.Time) (Record, error) {
	record.RecordKind = normalizeRecordKind(record.RecordKind, record)
	record.SourceType = normalizeSourceType(record.SourceType)
	record.PathID = strings.TrimSpace(record.PathID)
	record.AgentID = strings.TrimSpace(record.AgentID)
	record.Tool = strings.TrimSpace(record.Tool)
	record.Repo = strings.TrimSpace(record.Repo)
	record.Service = strings.TrimSpace(record.Service)
	record.Workflow = filepath.ToSlash(strings.TrimSpace(record.Workflow))
	record.Environment = strings.TrimSpace(record.Environment)
	record.Path = filepath.ToSlash(strings.TrimSpace(record.Path))
	record.Location = filepath.ToSlash(strings.TrimSpace(record.Location))
	if record.Location == "" {
		record.Location = firstNonEmpty(record.Path, record.Workflow)
	}
	record.Target = strings.TrimSpace(record.Target)
	record.ActionClasses = mergeStrings(record.ActionClasses...)
	record.PolicyRef = strings.TrimSpace(record.PolicyRef)
	record.ProofRef = strings.TrimSpace(record.ProofRef)
	record.GraphNodeRefs = mergeStrings(record.GraphNodeRefs...)
	record.GraphEdgeRefs = mergeStrings(record.GraphEdgeRefs...)
	record.Source = strings.TrimSpace(record.Source)
	record.Issuer = strings.TrimSpace(record.Issuer)
	record.ObservedAt = strings.TrimSpace(record.ObservedAt)
	record.ValidUntil = strings.TrimSpace(record.ValidUntil)
	record.MaxAge = strings.TrimSpace(record.MaxAge)
	record.Confidence = strings.TrimSpace(record.Confidence)
	record.FreshnessState = strings.TrimSpace(record.FreshnessState)
	record.RedactionHints = mergeStrings(record.RedactionHints...)
	record.EvidenceClass = normalizeEvidenceClass(record.EvidenceClass)
	record.Status = normalizeRecordStatus(record.Status)
	record.EvidenceRefs = mergeStrings(record.EvidenceRefs...)
	record.Owner = normalizeOwnerValue(record.Owner)
	record.RequiredChecks = mergeStrings(record.RequiredChecks...)
	record.Branch = strings.TrimSpace(record.Branch)
	record.SourcePrecedenceKey = sourcePrecedenceSortKey(record)
	label := firstNonEmpty(record.PathID, record.AgentID, record.Repo, record.Service, record.Workflow, record.Path, record.PolicyRef, record.ProofRef, record.Source)
	if record.Source == "" {
		return Record{}, fmt.Errorf("runtime evidence record source is required for %s", fallbackRecordLabel(label))
	}
	if record.RecordKind == RecordKindExternalControl && record.SourceType == "" {
		return Record{}, fmt.Errorf("external control evidence record source_type is required for %s", fallbackRecordLabel(label))
	}
	if record.ObservedAt == "" {
		return Record{}, fmt.Errorf("runtime evidence record observed_at is required for %s", fallbackRecordLabel(label))
	}
	observedAt, err := time.Parse(time.RFC3339, record.ObservedAt)
	if err != nil {
		return Record{}, fmt.Errorf("runtime evidence record observed_at must be RFC3339 for %s", fallbackRecordLabel(label))
	}
	if record.ValidUntil != "" {
		validUntil, err := time.Parse(time.RFC3339, record.ValidUntil)
		if err != nil {
			return Record{}, fmt.Errorf("external control evidence record valid_until must be RFC3339 for %s", fallbackRecordLabel(label))
		}
		if validUntil.Before(observedAt) {
			return Record{}, fmt.Errorf("external control evidence record valid_until must not precede observed_at for %s", fallbackRecordLabel(label))
		}
	}
	if record.MaxAge != "" {
		if _, err := time.ParseDuration(record.MaxAge); err != nil {
			return Record{}, fmt.Errorf("external control evidence record max_age must be a valid duration for %s", fallbackRecordLabel(label))
		}
	}
	freshnessState, _, err := evidencepolicy.EvaluateFreshness(generatedAt, record.ObservedAt, record.ValidUntil, record.MaxAge, record.Status)
	if err != nil {
		return Record{}, fmt.Errorf("external control evidence record freshness is invalid for %s: %w", fallbackRecordLabel(label), err)
	}
	record.FreshnessState = freshnessState
	if record.EvidenceClass == "" {
		return Record{}, fmt.Errorf("runtime evidence record evidence_class is required for %s", fallbackRecordLabel(label))
	}
	if !recordHasCorrelationKey(record) {
		return Record{}, fmt.Errorf("runtime evidence record requires at least one correlation key (path_id, agent_id, repo+location, repo+workflow, repo+environment, service, policy_ref, proof_ref, target, or graph refs)")
	}
	if record.RecordKind == RecordKindExternalControl {
		if err := rejectSecretLikeValues(record); err != nil {
			return Record{}, err
		}
	}
	if record.RecordID == "" {
		if record.RecordKind == RecordKindExternalControl {
			record.RecordID = strings.Join([]string{
				record.RecordKind,
				record.SourcePrecedenceKey,
				firstNonEmpty(record.PathID, record.AgentID, record.Repo, record.Service, record.Workflow, record.Path, record.PolicyRef, record.ProofRef, record.Source),
				record.EvidenceClass,
				record.ObservedAt,
			}, ":")
		} else {
			record.RecordID = firstNonEmpty(record.PathID, record.AgentID, record.Repo, record.PolicyRef, record.ProofRef, record.Source) + ":" + record.EvidenceClass + ":" + record.ObservedAt
		}
	}
	return record, nil
}

type pathMatchIndex struct {
	byPathID       map[string]statePathMatch
	byAgentID      map[string][]statePathMatch
	byRepoLocation map[string][]statePathMatch
	byEnvironment  map[string][]statePathMatch
	byService      map[string][]statePathMatch
	byServiceOnly  map[string][]statePathMatch
	byPolicyRef    map[string][]statePathMatch
	byGraphRef     map[string][]statePathMatch
}

type statePathMatch struct {
	PathID                   string
	AgentID                  string
	ToolType                 string
	Repo                     string
	Location                 string
	Workflow                 string
	ServiceCandidates        []string
	EnvironmentNames         []string
	ActionClasses            []string
	PolicyRefs               []string
	MatchedProductionTargets []string
}

type workflowMetadata struct {
	EnvironmentNames []string
}

func buildPathIndex(snapshot state.Snapshot) pathMatchIndex {
	index := pathMatchIndex{
		byPathID:       map[string]statePathMatch{},
		byAgentID:      map[string][]statePathMatch{},
		byRepoLocation: map[string][]statePathMatch{},
		byEnvironment:  map[string][]statePathMatch{},
		byService:      map[string][]statePathMatch{},
		byServiceOnly:  map[string][]statePathMatch{},
		byPolicyRef:    map[string][]statePathMatch{},
		byGraphRef:     map[string][]statePathMatch{},
	}
	if snapshot.RiskReport == nil {
		return index
	}
	workflowByRepoLocation := buildWorkflowMetadataIndex(snapshot.Findings)
	for _, path := range snapshot.RiskReport.ActionPaths {
		workflowMeta := workflowByRepoLocation[repoLocationKey(path.Repo, path.Location)]
		match := statePathMatch{
			PathID:                   strings.TrimSpace(path.PathID),
			AgentID:                  strings.TrimSpace(path.AgentID),
			ToolType:                 strings.TrimSpace(path.ToolType),
			Repo:                     strings.TrimSpace(path.Repo),
			Location:                 filepath.ToSlash(strings.TrimSpace(path.Location)),
			Workflow:                 filepath.ToSlash(strings.TrimSpace(path.Location)),
			ServiceCandidates:        serviceCandidatesForPath(path.Repo, path.Location),
			EnvironmentNames:         mergeStrings(append(append([]string(nil), workflowMeta.EnvironmentNames...), path.MatchedProductionTargets...)...),
			ActionClasses:            mergeStrings(path.ActionClasses...),
			PolicyRefs:               mergeStrings(path.PolicyRefs...),
			MatchedProductionTargets: mergeStrings(path.MatchedProductionTargets...),
		}
		if match.PathID == "" {
			continue
		}
		index.byPathID[match.PathID] = match
		if match.AgentID != "" {
			index.byAgentID[match.AgentID] = append(index.byAgentID[match.AgentID], match)
		}
		if match.Repo != "" || match.Location != "" {
			index.byRepoLocation[repoLocationKey(match.Repo, match.Location)] = append(index.byRepoLocation[repoLocationKey(match.Repo, match.Location)], match)
		}
		for _, environment := range match.EnvironmentNames {
			index.byEnvironment[repoScopedKey(match.Repo, environment)] = append(index.byEnvironment[repoScopedKey(match.Repo, environment)], match)
		}
		for _, service := range match.ServiceCandidates {
			index.byService[repoScopedKey(match.Repo, service)] = append(index.byService[repoScopedKey(match.Repo, service)], match)
			index.byServiceOnly[service] = append(index.byServiceOnly[service], match)
		}
		for _, ref := range match.PolicyRefs {
			index.byPolicyRef[ref] = append(index.byPolicyRef[ref], match)
		}
	}
	if snapshot.RiskReport.ControlPathGraph != nil {
		for _, node := range snapshot.RiskReport.ControlPathGraph.Nodes {
			ref := strings.TrimSpace(node.NodeID)
			pathID := strings.TrimSpace(node.PathID)
			if ref == "" || pathID == "" {
				continue
			}
			if match, ok := index.byPathID[pathID]; ok {
				index.byGraphRef[ref] = append(index.byGraphRef[ref], match)
			}
		}
		for _, edge := range snapshot.RiskReport.ControlPathGraph.Edges {
			ref := strings.TrimSpace(edge.EdgeID)
			pathID := strings.TrimSpace(edge.PathID)
			if ref == "" || pathID == "" {
				continue
			}
			if match, ok := index.byPathID[pathID]; ok {
				index.byGraphRef[ref] = append(index.byGraphRef[ref], match)
			}
		}
	}
	return index
}

func (index pathMatchIndex) match(record Record) (string, statePathMatch) {
	if matched, ok := index.byPathID[record.PathID]; ok && strings.TrimSpace(record.PathID) != "" {
		return matched.PathID, matched
	}
	candidates := []statePathMatch{}
	if record.AgentID != "" {
		candidates = append(candidates, index.byAgentID[record.AgentID]...)
	}
	if record.Repo != "" || record.Location != "" {
		candidates = append(candidates, index.byRepoLocation[repoLocationKey(record.Repo, record.Location)]...)
	}
	if record.Repo != "" && record.Environment != "" {
		candidates = append(candidates, index.byEnvironment[repoScopedKey(record.Repo, record.Environment)]...)
	}
	if record.Repo != "" && record.Service != "" {
		candidates = append(candidates, index.byService[repoScopedKey(record.Repo, record.Service)]...)
	}
	if record.Service != "" {
		candidates = append(candidates, index.byServiceOnly[strings.TrimSpace(record.Service)]...)
	}
	if record.PolicyRef != "" {
		candidates = append(candidates, index.byPolicyRef[record.PolicyRef]...)
	}
	for _, ref := range append(append([]string(nil), record.GraphNodeRefs...), record.GraphEdgeRefs...) {
		candidates = append(candidates, index.byGraphRef[strings.TrimSpace(ref)]...)
	}
	if len(candidates) == 0 {
		return "", statePathMatch{}
	}
	unique := uniqueMatches(candidates)
	if len(unique) == 1 {
		return unique[0].PathID, unique[0]
	}
	best, ok := bestMatch(unique, record)
	if !ok {
		return "", statePathMatch{}
	}
	return best.PathID, best
}

func bestMatch(candidates []statePathMatch, record Record) (statePathMatch, bool) {
	best := statePathMatch{}
	bestScore := -1
	conflict := false
	for _, candidate := range candidates {
		score := 0
		if record.AgentID != "" && record.AgentID == candidate.AgentID {
			score += 4
		}
		if record.Repo != "" && record.Repo == candidate.Repo {
			score += 2
		}
		if record.Location != "" && record.Location == candidate.Location {
			score += 4
		}
		if record.Workflow != "" && record.Workflow == candidate.Workflow {
			score += 4
		}
		if record.Tool != "" && record.Tool == candidate.ToolType {
			score += 2
		}
		if record.PolicyRef != "" && containsString(candidate.PolicyRefs, record.PolicyRef) {
			score += 3
		}
		if record.Target != "" && containsString(candidate.MatchedProductionTargets, record.Target) {
			score += 2
		}
		if record.Environment != "" && containsString(candidate.EnvironmentNames, record.Environment) {
			score += 3
		}
		if record.Service != "" && containsString(candidate.ServiceCandidates, record.Service) {
			score += 2
		}
		if len(record.ActionClasses) > 0 && anyStringOverlap(candidate.ActionClasses, record.ActionClasses) {
			score += 2
		}
		switch {
		case score > bestScore:
			best = candidate
			bestScore = score
			conflict = false
		case score == bestScore:
			conflict = true
		}
	}
	if bestScore <= 0 || conflict {
		return statePathMatch{}, false
	}
	return best, true
}

func uniqueMatches(values []statePathMatch) []statePathMatch {
	seen := map[string]statePathMatch{}
	for _, value := range values {
		if strings.TrimSpace(value.PathID) == "" {
			continue
		}
		seen[value.PathID] = value
	}
	out := make([]statePathMatch, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PathID < out[j].PathID })
	return out
}

func correlationStatusForRecord(record Record, matched bool) string {
	switch normalizeRecordStatus(record.Status) {
	case CorrelationStatusConflict:
		return CorrelationStatusConflict
	case CorrelationStatusStale:
		return CorrelationStatusStale
	case CorrelationStatusMatched:
		return CorrelationStatusMatched
	case CorrelationStatusUnmatched:
		return CorrelationStatusUnmatched
	}
	if matched {
		return CorrelationStatusMatched
	}
	return CorrelationStatusUnmatched
}

func normalizeEvidenceClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case EvidenceClassPolicyDecision, "policy_enforced", "policy_match":
		return EvidenceClassPolicyDecision
	case EvidenceClassApproval, "manual_approval":
		return EvidenceClassApproval
	case EvidenceClassJITCredential, "jit_receipt":
		return EvidenceClassJITCredential
	case EvidenceClassFreezeWindow, "freeze":
		return EvidenceClassFreezeWindow
	case EvidenceClassKillSwitch, "killswitch":
		return EvidenceClassKillSwitch
	case EvidenceClassActionOutcome, "action_result":
		return EvidenceClassActionOutcome
	case EvidenceClassProofVerify, "proof_verified":
		return EvidenceClassProofVerify
	case EvidenceClassOwnerAssignment:
		return EvidenceClassOwnerAssignment
	case EvidenceClassPolicyRecord:
		return EvidenceClassPolicyRecord
	case EvidenceClassBranchProtection:
		return EvidenceClassBranchProtection
	case EvidenceClassProtectedEnvironment:
		return EvidenceClassProtectedEnvironment
	case EvidenceClassDeploymentApproval:
		return EvidenceClassDeploymentApproval
	case EvidenceClassRequiredCheck:
		return EvidenceClassRequiredCheck
	case EvidenceClassSecurityGate:
		return EvidenceClassSecurityGate
	case EvidenceClassOther:
		return EvidenceClassOther
	default:
		if strings.TrimSpace(value) == "" {
			return ""
		}
		return EvidenceClassOther
	}
}

func normalizeRecordStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case CorrelationStatusMatched:
		return CorrelationStatusMatched
	case CorrelationStatusUnmatched:
		return CorrelationStatusUnmatched
	case CorrelationStatusStale:
		return CorrelationStatusStale
	case CorrelationStatusConflict:
		return CorrelationStatusConflict
	default:
		return ""
	}
}

func mergeCorrelationStatus(current, incoming string) string {
	if correlationStatusRank(incoming) > correlationStatusRank(current) {
		return incoming
	}
	if strings.TrimSpace(current) != "" {
		return current
	}
	return incoming
}

func correlationStatusRank(value string) int {
	switch strings.TrimSpace(value) {
	case CorrelationStatusConflict:
		return 4
	case CorrelationStatusStale:
		return 3
	case CorrelationStatusMatched:
		return 2
	default:
		return 1
	}
}

func recordHasCorrelationKey(record Record) bool {
	return strings.TrimSpace(record.PathID) != "" ||
		strings.TrimSpace(record.AgentID) != "" ||
		(strings.TrimSpace(record.Repo) != "" && strings.TrimSpace(record.Location) != "") ||
		(strings.TrimSpace(record.Repo) != "" && strings.TrimSpace(record.Workflow) != "") ||
		(strings.TrimSpace(record.Repo) != "" && strings.TrimSpace(record.Environment) != "") ||
		strings.TrimSpace(record.Service) != "" ||
		strings.TrimSpace(record.PolicyRef) != "" ||
		strings.TrimSpace(record.ProofRef) != "" ||
		strings.TrimSpace(record.Target) != "" ||
		len(record.GraphNodeRefs) > 0 ||
		len(record.GraphEdgeRefs) > 0
}

func fallbackCorrelationKey(record Record) string {
	return firstNonEmpty(
		strings.TrimSpace(record.PathID),
		strings.TrimSpace(record.AgentID),
		repoLocationKey(record.Repo, record.Location),
		repoScopedKey(record.Repo, record.Workflow),
		repoScopedKey(record.Repo, record.Environment),
		repoScopedKey(record.Repo, record.Service),
		strings.TrimSpace(record.PolicyRef),
		strings.TrimSpace(record.ProofRef),
		strings.TrimSpace(record.RecordID),
	)
}

func fallbackRecordLabel(label string) string {
	if strings.TrimSpace(label) == "" {
		return "runtime evidence record"
	}
	return label
}

func repoLocationKey(repo, location string) string {
	return strings.TrimSpace(repo) + "::" + strings.TrimSpace(location)
}

func repoScopedKey(repo, value string) string {
	return strings.TrimSpace(repo) + "::" + strings.TrimSpace(value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func anyStringOverlap(left, right []string) bool {
	for _, item := range left {
		if containsString(right, item) {
			return true
		}
	}
	return false
}

func firstPathTarget(path statePathMatch) string {
	if len(path.MatchedProductionTargets) == 0 {
		return ""
	}
	return path.MatchedProductionTargets[0]
}

func firstPathEnvironment(path statePathMatch) string {
	if len(path.EnvironmentNames) == 0 {
		return ""
	}
	return path.EnvironmentNames[0]
}

func firstPathService(path statePathMatch) string {
	if len(path.ServiceCandidates) == 0 {
		return ""
	}
	return path.ServiceCandidates[0]
}

func buildWorkflowMetadataIndex(findings []model.Finding) map[string]workflowMetadata {
	if len(findings) == 0 {
		return nil
	}
	out := map[string]workflowMetadata{}
	for _, finding := range findings {
		key := repoLocationKey(finding.Repo, finding.Location)
		if strings.TrimSpace(key) == "::" {
			continue
		}
		current := out[key]
		for _, item := range finding.Evidence {
			if strings.TrimSpace(item.Key) != "workflow_environment" {
				continue
			}
			values := strings.Split(strings.TrimSpace(item.Value), ",")
			normalized := make([]string, 0, len(values))
			for _, value := range values {
				normalized = append(normalized, strings.TrimSpace(value))
			}
			current.EnvironmentNames = mergeStrings(append(append([]string(nil), current.EnvironmentNames...), normalized...)...)
		}
		out[key] = current
	}
	return out
}

func serviceCandidatesForPath(repo, location string) []string {
	candidates := []string{}
	repo = strings.TrimSpace(repo)
	if repo != "" {
		if slash := strings.LastIndex(repo, "/"); slash >= 0 && slash < len(repo)-1 {
			candidates = append(candidates, repo[slash+1:])
		} else {
			candidates = append(candidates, repo)
		}
	}
	location = filepath.ToSlash(strings.TrimSpace(location))
	if location != "" {
		base := filepath.Base(location)
		base = strings.TrimSuffix(base, filepath.Ext(base))
		if base != "" && base != "." {
			candidates = append(candidates, base)
		}
	}
	return mergeStrings(candidates...)
}

func normalizeRecordKind(value string, record Record) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case RecordKindExternalControl:
		return RecordKindExternalControl
	case RecordKindRuntime:
		return RecordKindRuntime
	}
	switch normalizeEvidenceClass(record.EvidenceClass) {
	case EvidenceClassOwnerAssignment,
		EvidenceClassPolicyRecord,
		EvidenceClassBranchProtection,
		EvidenceClassProtectedEnvironment,
		EvidenceClassDeploymentApproval,
		EvidenceClassRequiredCheck,
		EvidenceClassSecurityGate:
		return RecordKindExternalControl
	}
	if strings.TrimSpace(record.SourceType) != "" ||
		strings.TrimSpace(record.Service) != "" ||
		strings.TrimSpace(record.Workflow) != "" ||
		strings.TrimSpace(record.Environment) != "" ||
		strings.TrimSpace(record.Path) != "" ||
		strings.TrimSpace(record.Owner) != "" ||
		len(record.RequiredChecks) > 0 {
		return RecordKindExternalControl
	}
	return RecordKindRuntime
}

func normalizeSourceType(value string) string {
	return evidencepolicy.NormalizeSourceType(value)
}

func sourcePrecedenceSortKey(record Record) string {
	sourceType := normalizeSourceType(record.SourceType)
	if sourceType == evidencepolicy.SourceTypeUnknown && normalizeRecordKind(record.RecordKind, record) == RecordKindRuntime {
		sourceType = evidencepolicy.SourceTypeRuntime
	}
	return evidencepolicy.SourcePrecedenceKey(sourceType)
}

func normalizeOwnerValue(value string) string {
	return strings.TrimSpace(value)
}

func unmatchedReasonsForRecord(record Record) []string {
	reasons := []string{"no_unique_path_match"}
	if strings.TrimSpace(record.Service) != "" {
		reasons = append(reasons, "service:"+strings.TrimSpace(record.Service))
	}
	if strings.TrimSpace(record.Environment) != "" {
		reasons = append(reasons, "environment:"+strings.TrimSpace(record.Environment))
	}
	if strings.TrimSpace(record.Workflow) != "" {
		reasons = append(reasons, "workflow:"+strings.TrimSpace(record.Workflow))
	}
	if strings.TrimSpace(record.Path) != "" {
		reasons = append(reasons, "path:"+strings.TrimSpace(record.Path))
	}
	return mergeStrings(reasons...)
}

func rejectSecretLikeValues(record Record) error {
	for _, value := range append([]string{
		record.Owner,
		record.Source,
		record.Issuer,
		record.Path,
		record.Workflow,
		record.Environment,
		record.Branch,
	}, append(append([]string(nil), record.EvidenceRefs...), record.RequiredChecks...)...) {
		if looksSecretLike(value) {
			return fmt.Errorf("external control evidence record contains secret-like value for %s", fallbackRecordLabel(firstNonEmpty(record.RecordID, record.Repo, record.Source)))
		}
	}
	return nil
}

func looksSecretLike(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	for _, needle := range []string{
		"ghp_",
		"github_pat_",
		"AKIA",
		"-----BEGIN",
		"xoxb-",
		"sk_live_",
		"glpat-",
		"eyJhbGci",
	} {
		if strings.Contains(trimmed, needle) {
			return true
		}
	}
	return false
}

func mergeStrings(values ...string) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
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

func mergeFreshnessState(current, incoming string) string {
	switch normalizeFreshnessState(current) {
	case evidencepolicy.FreshnessStateExpired:
		return evidencepolicy.FreshnessStateExpired
	case evidencepolicy.FreshnessStateStale:
		if normalizeFreshnessState(incoming) == evidencepolicy.FreshnessStateExpired {
			return evidencepolicy.FreshnessStateExpired
		}
		return evidencepolicy.FreshnessStateStale
	case evidencepolicy.FreshnessStateUnknown:
		switch normalizeFreshnessState(incoming) {
		case evidencepolicy.FreshnessStateExpired, evidencepolicy.FreshnessStateStale:
			return normalizeFreshnessState(incoming)
		default:
			return evidencepolicy.FreshnessStateUnknown
		}
	case evidencepolicy.FreshnessStateFresh:
		switch normalizeFreshnessState(incoming) {
		case evidencepolicy.FreshnessStateExpired, evidencepolicy.FreshnessStateStale, evidencepolicy.FreshnessStateUnknown:
			return normalizeFreshnessState(incoming)
		default:
			return evidencepolicy.FreshnessStateFresh
		}
	default:
		return normalizeFreshnessState(incoming)
	}
}

func normalizeFreshnessState(value string) string {
	switch strings.TrimSpace(value) {
	case evidencepolicy.FreshnessStateFresh:
		return evidencepolicy.FreshnessStateFresh
	case evidencepolicy.FreshnessStateStale:
		return evidencepolicy.FreshnessStateStale
	case evidencepolicy.FreshnessStateExpired:
		return evidencepolicy.FreshnessStateExpired
	case evidencepolicy.FreshnessStateUnknown:
		return evidencepolicy.FreshnessStateUnknown
	default:
		return ""
	}
}
