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

const SchemaVersion = "v1"

const (
	EvidenceClassPolicyDecision = "policy_decision"
	EvidenceClassApproval       = "approval"
	EvidenceClassJITCredential  = "jit_credential"
	EvidenceClassFreezeWindow   = "freeze_window"
	EvidenceClassKillSwitch     = "kill_switch"
	EvidenceClassActionOutcome  = "action_outcome"
	EvidenceClassProofVerify    = "proof_verification"
	EvidenceClassOther          = "other"
	CorrelationStatusMatched    = "matched"
	CorrelationStatusUnmatched  = "unmatched"
	CorrelationStatusStale      = "stale"
	CorrelationStatusConflict   = "conflict"
)

type Bundle struct {
	SchemaVersion string   `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Records       []Record `json:"records"`
}

type Record struct {
	RecordID      string   `json:"record_id"`
	PathID        string   `json:"path_id,omitempty"`
	AgentID       string   `json:"agent_id,omitempty"`
	Tool          string   `json:"tool,omitempty"`
	Repo          string   `json:"repo,omitempty"`
	Location      string   `json:"location,omitempty"`
	Target        string   `json:"target,omitempty"`
	ActionClasses []string `json:"action_classes,omitempty"`
	PolicyRef     string   `json:"policy_ref,omitempty"`
	ProofRef      string   `json:"proof_ref,omitempty"`
	GraphNodeRefs []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs []string `json:"graph_edge_refs,omitempty"`
	Source        string   `json:"source"`
	ObservedAt    string   `json:"observed_at"`
	EvidenceClass string   `json:"evidence_class"`
	Status        string   `json:"status,omitempty"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
}

type Correlation struct {
	PathID           string   `json:"path_id"`
	AgentID          string   `json:"agent_id,omitempty"`
	Tool             string   `json:"tool,omitempty"`
	Repo             string   `json:"repo,omitempty"`
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
	LatestObservedAt string   `json:"latest_observed_at,omitempty"`
}

type Summary struct {
	ArtifactPath     string        `json:"artifact_path,omitempty"`
	TotalRecords     int           `json:"total_records"`
	MatchedRecords   int           `json:"matched_records"`
	UnmatchedRecords int           `json:"unmatched_records"`
	Correlations     []Correlation `json:"correlations,omitempty"`
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
	records := make([]Record, 0, len(bundle.Records))
	for _, record := range bundle.Records {
		normalized, err := normalizeRecord(record)
		if err != nil {
			return Bundle{}, err
		}
		records = append(records, normalized)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].PathID != records[j].PathID {
			return records[i].PathID < records[j].PathID
		}
		if records[i].AgentID != records[j].AgentID {
			return records[i].AgentID < records[j].AgentID
		}
		if records[i].Repo != records[j].Repo {
			return records[i].Repo < records[j].Repo
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
	if len(bundle.Records) == 0 {
		return Summary{ArtifactPath: artifactPath}
	}
	index := buildPathIndex(snapshot)

	byPath := map[string]*Correlation{}
	matched := 0
	for _, record := range bundle.Records {
		matchPathID, matchedPath := index.match(record)
		key := strings.TrimSpace(matchPathID)
		if key == "" {
			key = fallbackCorrelationKey(record)
		}
		item := byPath[key]
		if item == nil {
			item = &Correlation{
				PathID:   firstNonEmpty(matchPathID, record.PathID, fallbackCorrelationKey(record)),
				AgentID:  firstNonEmpty(record.AgentID, matchedPath.AgentID),
				Tool:     firstNonEmpty(record.Tool, matchedPath.ToolType),
				Repo:     firstNonEmpty(record.Repo, matchedPath.Repo),
				Location: firstNonEmpty(record.Location, matchedPath.Location),
				Target:   firstNonEmpty(record.Target, firstPathTarget(matchedPath)),
			}
			byPath[key] = item
		}
		item.EvidenceClasses = mergeStrings(append(append([]string(nil), item.EvidenceClasses...), record.EvidenceClass)...)
		item.ActionClasses = mergeStrings(append(append([]string(nil), item.ActionClasses...), record.ActionClasses...)...)
		item.Sources = mergeStrings(append(append([]string(nil), item.Sources...), record.Source)...)
		item.PolicyRefs = mergeStrings(append(append([]string(nil), item.PolicyRefs...), record.PolicyRef)...)
		item.ProofRefs = mergeStrings(append(append([]string(nil), item.ProofRefs...), record.ProofRef)...)
		item.GraphNodeRefs = mergeStrings(append(append([]string(nil), item.GraphNodeRefs...), record.GraphNodeRefs...)...)
		item.GraphEdgeRefs = mergeStrings(append(append([]string(nil), item.GraphEdgeRefs...), record.GraphEdgeRefs...)...)
		item.RecordIDs = mergeStrings(append(append([]string(nil), item.RecordIDs...), record.RecordID)...)
		if item.LatestObservedAt == "" || strings.TrimSpace(record.ObservedAt) > item.LatestObservedAt {
			item.LatestObservedAt = strings.TrimSpace(record.ObservedAt)
		}
		status := correlationStatusForRecord(record, matchPathID != "")
		item.Status = mergeCorrelationStatus(item.Status, status)
		if matchPathID != "" {
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
		ArtifactPath:     artifactPath,
		TotalRecords:     len(bundle.Records),
		MatchedRecords:   matched,
		UnmatchedRecords: len(bundle.Records) - matched,
		Correlations:     correlations,
	}
}

func normalizeRecord(record Record) (Record, error) {
	record.PathID = strings.TrimSpace(record.PathID)
	record.AgentID = strings.TrimSpace(record.AgentID)
	record.Tool = strings.TrimSpace(record.Tool)
	record.Repo = strings.TrimSpace(record.Repo)
	record.Location = strings.TrimSpace(record.Location)
	record.Target = strings.TrimSpace(record.Target)
	record.ActionClasses = mergeStrings(record.ActionClasses...)
	record.PolicyRef = strings.TrimSpace(record.PolicyRef)
	record.ProofRef = strings.TrimSpace(record.ProofRef)
	record.GraphNodeRefs = mergeStrings(record.GraphNodeRefs...)
	record.GraphEdgeRefs = mergeStrings(record.GraphEdgeRefs...)
	record.Source = strings.TrimSpace(record.Source)
	record.ObservedAt = strings.TrimSpace(record.ObservedAt)
	record.EvidenceClass = normalizeEvidenceClass(record.EvidenceClass)
	record.Status = normalizeRecordStatus(record.Status)
	record.EvidenceRefs = mergeStrings(record.EvidenceRefs...)
	label := firstNonEmpty(record.PathID, record.AgentID, record.Repo, record.PolicyRef, record.ProofRef, record.Source)
	if record.Source == "" {
		return Record{}, fmt.Errorf("runtime evidence record source is required for %s", fallbackRecordLabel(label))
	}
	if record.ObservedAt == "" {
		return Record{}, fmt.Errorf("runtime evidence record observed_at is required for %s", fallbackRecordLabel(label))
	}
	if _, err := time.Parse(time.RFC3339, record.ObservedAt); err != nil {
		return Record{}, fmt.Errorf("runtime evidence record observed_at must be RFC3339 for %s", fallbackRecordLabel(label))
	}
	if record.EvidenceClass == "" {
		return Record{}, fmt.Errorf("runtime evidence record evidence_class is required for %s", fallbackRecordLabel(label))
	}
	if !recordHasCorrelationKey(record) {
		return Record{}, fmt.Errorf("runtime evidence record requires at least one correlation key (path_id, agent_id, repo+location, policy_ref, proof_ref, target, or graph refs)")
	}
	if record.RecordID == "" {
		record.RecordID = firstNonEmpty(record.PathID, record.AgentID, record.Repo, record.PolicyRef, record.ProofRef, record.Source) + ":" + record.EvidenceClass + ":" + record.ObservedAt
	}
	return record, nil
}

type pathMatchIndex struct {
	byPathID       map[string]statePathMatch
	byAgentID      map[string][]statePathMatch
	byRepoLocation map[string][]statePathMatch
	byPolicyRef    map[string][]statePathMatch
	byGraphRef     map[string][]statePathMatch
}

type statePathMatch struct {
	PathID                   string
	AgentID                  string
	ToolType                 string
	Repo                     string
	Location                 string
	ActionClasses            []string
	PolicyRefs               []string
	MatchedProductionTargets []string
}

func buildPathIndex(snapshot state.Snapshot) pathMatchIndex {
	index := pathMatchIndex{
		byPathID:       map[string]statePathMatch{},
		byAgentID:      map[string][]statePathMatch{},
		byRepoLocation: map[string][]statePathMatch{},
		byPolicyRef:    map[string][]statePathMatch{},
		byGraphRef:     map[string][]statePathMatch{},
	}
	if snapshot.RiskReport == nil {
		return index
	}
	for _, path := range snapshot.RiskReport.ActionPaths {
		match := statePathMatch{
			PathID:                   strings.TrimSpace(path.PathID),
			AgentID:                  strings.TrimSpace(path.AgentID),
			ToolType:                 strings.TrimSpace(path.ToolType),
			Repo:                     strings.TrimSpace(path.Repo),
			Location:                 strings.TrimSpace(path.Location),
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
		if record.Tool != "" && record.Tool == candidate.ToolType {
			score += 2
		}
		if record.PolicyRef != "" && containsString(candidate.PolicyRefs, record.PolicyRef) {
			score += 3
		}
		if record.Target != "" && containsString(candidate.MatchedProductionTargets, record.Target) {
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
