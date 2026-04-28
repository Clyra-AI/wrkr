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

type Bundle struct {
	SchemaVersion string   `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Records       []Record `json:"records"`
}

type Record struct {
	RecordID      string   `json:"record_id"`
	PathID        string   `json:"path_id"`
	AgentID       string   `json:"agent_id,omitempty"`
	Tool          string   `json:"tool,omitempty"`
	Repo          string   `json:"repo,omitempty"`
	PolicyRef     string   `json:"policy_ref,omitempty"`
	ProofRef      string   `json:"proof_ref,omitempty"`
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
	Status           string   `json:"status"`
	EvidenceClasses  []string `json:"evidence_classes,omitempty"`
	Sources          []string `json:"sources,omitempty"`
	PolicyRefs       []string `json:"policy_refs,omitempty"`
	ProofRefs        []string `json:"proof_refs,omitempty"`
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
	pathIDs := map[string]struct{}{}
	agentIDs := map[string]struct{}{}
	if snapshot.RiskReport != nil {
		for _, path := range snapshot.RiskReport.ActionPaths {
			if strings.TrimSpace(path.PathID) != "" {
				pathIDs[strings.TrimSpace(path.PathID)] = struct{}{}
			}
			if strings.TrimSpace(path.AgentID) != "" {
				agentIDs[strings.TrimSpace(path.AgentID)] = struct{}{}
			}
		}
	}
	if snapshot.Inventory != nil {
		for _, entry := range snapshot.Inventory.AgentPrivilegeMap {
			if strings.TrimSpace(entry.AgentID) != "" {
				agentIDs[strings.TrimSpace(entry.AgentID)] = struct{}{}
			}
		}
	}

	byPath := map[string]*Correlation{}
	matched := 0
	for _, record := range bundle.Records {
		key := strings.TrimSpace(record.PathID)
		if key == "" {
			key = strings.TrimSpace(record.RecordID)
		}
		item := byPath[key]
		if item == nil {
			item = &Correlation{
				PathID:  strings.TrimSpace(record.PathID),
				AgentID: strings.TrimSpace(record.AgentID),
				Tool:    strings.TrimSpace(record.Tool),
				Repo:    strings.TrimSpace(record.Repo),
			}
			byPath[key] = item
		}
		item.EvidenceClasses = mergeStrings(append(append([]string(nil), item.EvidenceClasses...), record.EvidenceClass)...)
		item.Sources = mergeStrings(append(append([]string(nil), item.Sources...), record.Source)...)
		item.PolicyRefs = mergeStrings(append(append([]string(nil), item.PolicyRefs...), record.PolicyRef)...)
		item.ProofRefs = mergeStrings(append(append([]string(nil), item.ProofRefs...), record.ProofRef)...)
		item.RecordIDs = mergeStrings(append(append([]string(nil), item.RecordIDs...), record.RecordID)...)
		if item.LatestObservedAt == "" || strings.TrimSpace(record.ObservedAt) > item.LatestObservedAt {
			item.LatestObservedAt = strings.TrimSpace(record.ObservedAt)
		}
		if _, ok := pathIDs[strings.TrimSpace(record.PathID)]; ok {
			item.Status = "matched"
			matched++
			continue
		}
		if strings.TrimSpace(record.AgentID) != "" {
			if _, ok := agentIDs[strings.TrimSpace(record.AgentID)]; ok {
				item.Status = "matched"
				matched++
				continue
			}
		}
		if item.Status == "" {
			item.Status = "unmatched"
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
	record.PolicyRef = strings.TrimSpace(record.PolicyRef)
	record.ProofRef = strings.TrimSpace(record.ProofRef)
	record.Source = strings.TrimSpace(record.Source)
	record.ObservedAt = strings.TrimSpace(record.ObservedAt)
	record.EvidenceClass = strings.TrimSpace(record.EvidenceClass)
	record.Status = strings.TrimSpace(record.Status)
	record.EvidenceRefs = mergeStrings(record.EvidenceRefs...)
	if record.PathID == "" {
		return Record{}, fmt.Errorf("runtime evidence record path_id is required")
	}
	if record.Source == "" {
		return Record{}, fmt.Errorf("runtime evidence record source is required for path_id %s", record.PathID)
	}
	if record.ObservedAt == "" {
		return Record{}, fmt.Errorf("runtime evidence record observed_at is required for path_id %s", record.PathID)
	}
	if _, err := time.Parse(time.RFC3339, record.ObservedAt); err != nil {
		return Record{}, fmt.Errorf("runtime evidence record observed_at must be RFC3339 for path_id %s", record.PathID)
	}
	if record.EvidenceClass == "" {
		return Record{}, fmt.Errorf("runtime evidence record evidence_class is required for path_id %s", record.PathID)
	}
	if record.RecordID == "" {
		record.RecordID = record.PathID + ":" + record.EvidenceClass + ":" + record.ObservedAt
	}
	if record.Status == "" {
		record.Status = "observed"
	}
	return record, nil
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
