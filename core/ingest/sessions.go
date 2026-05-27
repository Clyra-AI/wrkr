package ingest

import (
	"crypto/sha256"
	"encoding/hex"
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

const SessionSchemaVersion = "v1"

const (
	SessionProviderCodex      = "codex"
	SessionProviderClaudeCode = "claude_code"
	SessionProviderCursor     = "cursor"
	SessionProviderCopilot    = "copilot"
	SessionProviderGait       = "gait"
	SessionProviderUnknown    = "unknown"
)

type SessionBundle struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	Sessions      []SessionRecord `json:"sessions"`
}

type SessionRecord struct {
	SessionID          string   `json:"session_id,omitempty"`
	Provider           string   `json:"provider"`
	RunID              string   `json:"run_id,omitempty"`
	Status             string   `json:"status,omitempty"`
	PathID             string   `json:"path_id,omitempty"`
	AgentID            string   `json:"agent_id,omitempty"`
	Repo               string   `json:"repo,omitempty"`
	Workflow           string   `json:"workflow,omitempty"`
	PullRequestRef     string   `json:"pull_request_ref,omitempty"`
	MergeRequestRef    string   `json:"merge_request_ref,omitempty"`
	AuthorRefs         []string `json:"author_refs,omitempty"`
	ReviewerRefs       []string `json:"reviewer_refs,omitempty"`
	Tool               string   `json:"tool,omitempty"`
	ProviderURL        string   `json:"provider_url,omitempty"`
	PromptRef          string   `json:"prompt_ref,omitempty"`
	ResponseRef        string   `json:"response_ref,omitempty"`
	ChangedFiles       []string `json:"changed_files,omitempty"`
	Commands           []string `json:"commands,omitempty"`
	Actions            []string `json:"actions,omitempty"`
	FileWrites         []string `json:"file_writes,omitempty"`
	Approvals          []string `json:"approvals,omitempty"`
	PolicyDecisions    []string `json:"policy_decisions,omitempty"`
	CredentialSubjects []string `json:"credential_subjects,omitempty"`
	Declarations       []string `json:"declarations,omitempty"`
	ProofRefs          []string `json:"proof_refs,omitempty"`
	GraphNodeRefs      []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs      []string `json:"graph_edge_refs,omitempty"`
	Outcome            string   `json:"outcome,omitempty"`
	StartedAt          string   `json:"started_at,omitempty"`
	CompletedAt        string   `json:"completed_at,omitempty"`
	SourceArtifactRefs []string `json:"source_artifact_refs,omitempty"`
	RedactionHints     []string `json:"redaction_hints,omitempty"`
}

type SessionCorrelation struct {
	SessionID          string   `json:"session_id"`
	PathID             string   `json:"path_id,omitempty"`
	AgentID            string   `json:"agent_id,omitempty"`
	Provider           string   `json:"provider,omitempty"`
	RunID              string   `json:"run_id,omitempty"`
	Repo               string   `json:"repo,omitempty"`
	Workflow           string   `json:"workflow,omitempty"`
	PullRequestRef     string   `json:"pull_request_ref,omitempty"`
	MergeRequestRef    string   `json:"merge_request_ref,omitempty"`
	BoundaryLabel      string   `json:"boundary_label,omitempty"`
	Status             string   `json:"status"`
	Outcome            string   `json:"outcome,omitempty"`
	PromptRef          string   `json:"prompt_ref,omitempty"`
	ResponseRef        string   `json:"response_ref,omitempty"`
	ObservedActions    []string `json:"observed_actions,omitempty"`
	ChangedFiles       []string `json:"changed_files,omitempty"`
	FileWrites         []string `json:"file_writes,omitempty"`
	Approvals          []string `json:"approvals,omitempty"`
	PolicyDecisions    []string `json:"policy_decisions,omitempty"`
	ProofRefs          []string `json:"proof_refs,omitempty"`
	GraphNodeRefs      []string `json:"graph_node_refs,omitempty"`
	GraphEdgeRefs      []string `json:"graph_edge_refs,omitempty"`
	SourceArtifactRefs []string `json:"source_artifact_refs,omitempty"`
	RedactionHints     []string `json:"redaction_hints,omitempty"`
}

type SessionSummary struct {
	ArtifactPath       string               `json:"artifact_path,omitempty"`
	BoundaryLabel      string               `json:"boundary_label,omitempty"`
	TotalSessions      int                  `json:"total_sessions"`
	MatchedSessions    int                  `json:"matched_sessions"`
	UnmatchedSessions  int                  `json:"unmatched_sessions"`
	StaleSessions      int                  `json:"stale_sessions,omitempty"`
	ConflictingSession int                  `json:"conflicting_sessions,omitempty"`
	Correlations       []SessionCorrelation `json:"correlations,omitempty"`
}

type unrecognizedSessionArtifactError struct{}

func (e unrecognizedSessionArtifactError) Error() string {
	return "unsupported session artifact"
}

func IsUnrecognizedSessionArtifact(err error) bool {
	_, ok := err.(unrecognizedSessionArtifactError)
	return ok
}

func DefaultSessionPath(statePath string) string {
	resolved := state.ResolvePath(strings.TrimSpace(statePath))
	return filepath.Join(filepath.Dir(resolved), "runtime-sessions.json")
}

func LoadSessionBundle(path string) (SessionBundle, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller chooses explicit local ingest artifact path.
	if err != nil {
		return SessionBundle{}, fmt.Errorf("read runtime sessions: %w", err)
	}
	return ParseSessionBundleJSON(payload)
}

func LoadOptionalSessionBundle(statePath string) (SessionBundle, string, error) {
	path := DefaultSessionPath(statePath)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return SessionBundle{}, "", nil
		}
		return SessionBundle{}, "", fmt.Errorf("stat runtime sessions: %w", err)
	}
	bundle, err := LoadSessionBundle(path)
	if err != nil {
		return SessionBundle{}, "", err
	}
	return bundle, path, nil
}

func SaveSessionBundle(path string, bundle SessionBundle) error {
	normalized, err := NormalizeSessionBundle(bundle)
	if err != nil {
		return err
	}
	payload, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime sessions: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write runtime sessions: %w", err)
	}
	return nil
}

func ParseSessionBundleJSON(payload []byte) (SessionBundle, error) {
	top, err := topLevelKeys(payload)
	if err != nil {
		return SessionBundle{}, err
	}
	if _, ok := top["sessions"]; ok {
		if err := ValidateSessionJSON(payload); err != nil {
			return SessionBundle{}, err
		}
		var bundle SessionBundle
		if err := json.Unmarshal(payload, &bundle); err != nil {
			return SessionBundle{}, err
		}
		return NormalizeSessionBundle(bundle)
	}
	record, err := parseLooseSessionArtifact(top)
	if err != nil {
		return SessionBundle{}, err
	}
	return NormalizeSessionBundle(SessionBundle{Sessions: []SessionRecord{record}})
}

func NormalizeSessionBundle(bundle SessionBundle) (SessionBundle, error) {
	if strings.TrimSpace(bundle.SchemaVersion) == "" {
		bundle.SchemaVersion = SessionSchemaVersion
	}
	if strings.TrimSpace(bundle.SchemaVersion) != SessionSchemaVersion {
		return SessionBundle{}, fmt.Errorf("unsupported runtime sessions schema_version %q", bundle.SchemaVersion)
	}
	if strings.TrimSpace(bundle.GeneratedAt) == "" {
		bundle.GeneratedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	generatedAt, err := time.Parse(time.RFC3339, bundle.GeneratedAt)
	if err != nil {
		return SessionBundle{}, fmt.Errorf("runtime sessions generated_at must be RFC3339")
	}
	sessions := make([]SessionRecord, 0, len(bundle.Sessions))
	for _, session := range bundle.Sessions {
		normalized, err := normalizeSessionRecord(session, generatedAt)
		if err != nil {
			return SessionBundle{}, err
		}
		sessions = append(sessions, normalized)
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].Provider != sessions[j].Provider {
			return sessions[i].Provider < sessions[j].Provider
		}
		if sessions[i].Repo != sessions[j].Repo {
			return sessions[i].Repo < sessions[j].Repo
		}
		if sessions[i].Workflow != sessions[j].Workflow {
			return sessions[i].Workflow < sessions[j].Workflow
		}
		if sessions[i].CompletedAt != sessions[j].CompletedAt {
			return sessions[i].CompletedAt < sessions[j].CompletedAt
		}
		return sessions[i].SessionID < sessions[j].SessionID
	})
	bundle.Sessions = sessions
	return bundle, nil
}

func CorrelateSessions(snapshot state.Snapshot, artifactPath string, bundle SessionBundle) SessionSummary {
	if normalized, err := NormalizeSessionBundle(bundle); err == nil {
		bundle = normalized
	}
	if len(bundle.Sessions) == 0 {
		return SessionSummary{ArtifactPath: artifactPath}
	}
	index := buildEvidencePacketMatchIndex(snapshot)
	correlations := make([]SessionCorrelation, 0, len(bundle.Sessions))
	matched := 0
	unmatched := 0
	stale := 0
	conflict := 0
	for _, session := range bundle.Sessions {
		packet := sessionToEvidencePacket(session)
		pathID, derivedStatus := matchEvidencePacket(index, packet)
		status := normalizeSessionStatus(session.Status)
		if status == "" {
			status = derivedStatus
		} else if status == CorrelationStatusMatched && derivedStatus != CorrelationStatusMatched {
			status = derivedStatus
		}
		switch status {
		case CorrelationStatusMatched:
			matched++
		case CorrelationStatusStale:
			stale++
		case CorrelationStatusConflict:
			conflict++
		default:
			unmatched++
		}
		correlations = append(correlations, SessionCorrelation{
			SessionID:          session.SessionID,
			PathID:             pathID,
			AgentID:            session.AgentID,
			Provider:           session.Provider,
			RunID:              session.RunID,
			Repo:               session.Repo,
			Workflow:           session.Workflow,
			PullRequestRef:     session.PullRequestRef,
			MergeRequestRef:    session.MergeRequestRef,
			Status:             status,
			Outcome:            session.Outcome,
			PromptRef:          session.PromptRef,
			ResponseRef:        session.ResponseRef,
			ObservedActions:    append([]string(nil), session.Actions...),
			ChangedFiles:       append([]string(nil), session.ChangedFiles...),
			FileWrites:         append([]string(nil), session.FileWrites...),
			Approvals:          append([]string(nil), session.Approvals...),
			PolicyDecisions:    append([]string(nil), session.PolicyDecisions...),
			ProofRefs:          append([]string(nil), session.ProofRefs...),
			GraphNodeRefs:      append([]string(nil), session.GraphNodeRefs...),
			GraphEdgeRefs:      append([]string(nil), session.GraphEdgeRefs...),
			SourceArtifactRefs: append([]string(nil), session.SourceArtifactRefs...),
			RedactionHints:     append([]string(nil), session.RedactionHints...),
		})
	}
	sort.Slice(correlations, func(i, j int) bool {
		if correlations[i].Status != correlations[j].Status {
			return correlations[i].Status < correlations[j].Status
		}
		if correlations[i].PathID != correlations[j].PathID {
			return correlations[i].PathID < correlations[j].PathID
		}
		return correlations[i].SessionID < correlations[j].SessionID
	})
	return SessionSummary{
		ArtifactPath:       artifactPath,
		TotalSessions:      len(bundle.Sessions),
		MatchedSessions:    matched,
		UnmatchedSessions:  unmatched,
		StaleSessions:      stale,
		ConflictingSession: conflict,
		Correlations:       correlations,
	}
}

func ProjectSessionsToRuntimeBundle(bundle SessionBundle) Bundle {
	if normalized, err := NormalizeSessionBundle(bundle); err == nil {
		bundle = normalized
	}
	out := Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   bundle.GeneratedAt,
	}
	for _, session := range bundle.Sessions {
		records := sessionToRuntimeRecords(session)
		out.Records = append(out.Records, records...)
	}
	normalized, err := Normalize(out)
	if err != nil {
		return out
	}
	return normalized
}

func ProjectSessionsToEvidencePacketBundle(bundle SessionBundle) EvidencePacketBundle {
	if normalized, err := NormalizeSessionBundle(bundle); err == nil {
		bundle = normalized
	}
	out := EvidencePacketBundle{
		SchemaVersion: EvidencePacketSchemaVersion,
		GeneratedAt:   bundle.GeneratedAt,
	}
	for _, session := range bundle.Sessions {
		out.Packets = append(out.Packets, sessionToEvidencePacket(session))
	}
	normalized, err := NormalizeEvidencePacketBundle(out)
	if err != nil {
		return out
	}
	return normalized
}

func MergeRuntimeBundles(bundles ...Bundle) Bundle {
	out := Bundle{SchemaVersion: SchemaVersion}
	records := map[string]Record{}
	generatedAt := ""
	for _, bundle := range bundles {
		normalized, err := Normalize(bundle)
		if err != nil {
			continue
		}
		if generatedAt == "" || strings.TrimSpace(normalized.GeneratedAt) < generatedAt {
			generatedAt = strings.TrimSpace(normalized.GeneratedAt)
		}
		for _, record := range normalized.Records {
			records[record.RecordID] = record
		}
	}
	out.GeneratedAt = firstNonEmpty(generatedAt, time.Now().UTC().Truncate(time.Second).Format(time.RFC3339))
	for _, record := range records {
		out.Records = append(out.Records, record)
	}
	normalized, err := Normalize(out)
	if err != nil {
		return out
	}
	return normalized
}

func MergeEvidencePacketBundles(bundles ...EvidencePacketBundle) EvidencePacketBundle {
	out := EvidencePacketBundle{SchemaVersion: EvidencePacketSchemaVersion}
	packets := map[string]EvidencePacket{}
	generatedAt := ""
	for _, bundle := range bundles {
		normalized, err := NormalizeEvidencePacketBundle(bundle)
		if err != nil {
			continue
		}
		if generatedAt == "" || strings.TrimSpace(normalized.GeneratedAt) < generatedAt {
			generatedAt = strings.TrimSpace(normalized.GeneratedAt)
		}
		for _, packet := range normalized.Packets {
			packets[packet.PacketID] = packet
		}
	}
	out.GeneratedAt = firstNonEmpty(generatedAt, time.Now().UTC().Truncate(time.Second).Format(time.RFC3339))
	for _, packet := range packets {
		out.Packets = append(out.Packets, packet)
	}
	normalized, err := NormalizeEvidencePacketBundle(out)
	if err != nil {
		return out
	}
	return normalized
}

func normalizeSessionRecord(session SessionRecord, generatedAt time.Time) (SessionRecord, error) {
	session.Provider = normalizeSessionProvider(session.Provider)
	session.SessionID = strings.TrimSpace(session.SessionID)
	session.RunID = strings.TrimSpace(session.RunID)
	session.Status = normalizeSessionStatus(session.Status)
	session.PathID = strings.TrimSpace(session.PathID)
	session.AgentID = strings.TrimSpace(session.AgentID)
	session.Repo = strings.TrimSpace(session.Repo)
	session.Workflow = normalizeRepoRelativeSessionPath(session.Workflow)
	session.PullRequestRef = normalizeReviewRef(session.PullRequestRef, "pr")
	session.MergeRequestRef = normalizeReviewRef(session.MergeRequestRef, "mr")
	session.AuthorRefs = mergeStrings(session.AuthorRefs...)
	session.ReviewerRefs = mergeStrings(session.ReviewerRefs...)
	session.Tool = strings.TrimSpace(session.Tool)
	session.ProviderURL = strings.TrimSpace(session.ProviderURL)
	session.PromptRef = normalizeOpaqueRef(session.PromptRef)
	session.ResponseRef = normalizeOpaqueRef(session.ResponseRef)
	var err error
	session.ChangedFiles, err = normalizeSessionPathList(session.ChangedFiles)
	if err != nil {
		return SessionRecord{}, err
	}
	session.Commands = mergeStrings(session.Commands...)
	session.Actions = mergeStrings(session.Actions...)
	session.FileWrites, err = normalizeSessionPathList(session.FileWrites)
	if err != nil {
		return SessionRecord{}, err
	}
	session.Approvals = mergeStrings(session.Approvals...)
	session.PolicyDecisions = mergeStrings(session.PolicyDecisions...)
	session.CredentialSubjects = mergeStrings(session.CredentialSubjects...)
	session.Declarations = mergeStrings(session.Declarations...)
	session.ProofRefs = mergeStrings(session.ProofRefs...)
	session.GraphNodeRefs = mergeStrings(session.GraphNodeRefs...)
	session.GraphEdgeRefs = mergeStrings(session.GraphEdgeRefs...)
	session.Outcome = normalizeSessionOutcome(session.Outcome)
	session.StartedAt = normalizeOptionalRFC3339(session.StartedAt)
	session.CompletedAt = normalizeOptionalRFC3339(session.CompletedAt)
	session.SourceArtifactRefs, err = normalizeSessionPathList(session.SourceArtifactRefs)
	if err != nil {
		return SessionRecord{}, err
	}
	session.RedactionHints = mergeStrings(session.RedactionHints...)
	if session.Provider == "" {
		return SessionRecord{}, fmt.Errorf("runtime session provider is required")
	}
	if session.StartedAt == "" && session.CompletedAt == "" {
		return SessionRecord{}, fmt.Errorf("runtime session requires started_at or completed_at for %s", fallbackRecordLabel(firstNonEmpty(session.SessionID, session.RunID, session.Provider)))
	}
	if !sessionHasCorrelationKey(session) {
		return SessionRecord{}, fmt.Errorf("runtime session requires at least one correlation key (path_id, agent_id, repo+workflow, pull_request_ref, merge_request_ref, changed_files, proof_refs, or graph refs)")
	}
	if err := rejectSecretLikeSessionValues(session); err != nil {
		return SessionRecord{}, err
	}
	if session.SessionID == "" {
		session.SessionID = buildSessionID(session, generatedAt)
	}
	if session.Tool == "" {
		session.Tool = session.Provider
	}
	if session.CompletedAt == "" {
		session.CompletedAt = firstNonEmpty(session.StartedAt, generatedAt.UTC().Truncate(time.Second).Format(time.RFC3339))
	}
	if session.StartedAt == "" {
		session.StartedAt = session.CompletedAt
	}
	return session, nil
}

func parseLooseSessionArtifact(top map[string]json.RawMessage) (SessionRecord, error) {
	if len(top) == 0 {
		return SessionRecord{}, unrecognizedSessionArtifactError{}
	}
	provider := strings.TrimSpace(stringValueFromRaw(top, "provider"))
	if provider == "" {
		provider = inferSessionProvider(top)
	} else {
		provider = normalizeSessionProvider(provider)
	}
	if provider == "" {
		return SessionRecord{}, unrecognizedSessionArtifactError{}
	}
	loose, err := decodeLooseSession(top)
	if err != nil {
		return SessionRecord{}, err
	}
	loose.Provider = provider
	return loose, nil
}

func decodeLooseSession(top map[string]json.RawMessage) (SessionRecord, error) {
	aliasPrompt := firstNonEmptyStringValue(top, "prompt_ref", "prompt_digest")
	if aliasPrompt == "" {
		rawPrompt := firstNonEmptyStringValue(top, "prompt", "transcript", "request")
		if looksSecretLike(rawPrompt) {
			return SessionRecord{}, fmt.Errorf("runtime session contains secret-like value for prompt material")
		}
		aliasPrompt = digestRef("prompt", rawPrompt)
	}
	aliasResponse := firstNonEmptyStringValue(top, "response_ref", "response_digest")
	if aliasResponse == "" {
		rawResponse := firstNonEmptyStringValue(top, "response", "completion", "reply")
		if looksSecretLike(rawResponse) {
			return SessionRecord{}, fmt.Errorf("runtime session contains secret-like value for response material")
		}
		aliasResponse = digestRef("response", rawResponse)
	}
	record := SessionRecord{
		SessionID:          firstNonEmptyStringValue(top, "session_id", "conversation_id", "trace_id", "agent_session_id"),
		RunID:              firstNonEmptyStringValue(top, "run_id", "run_ref", "request_id"),
		Status:             firstNonEmptyStringValue(top, "status", "correlation_status"),
		PathID:             firstNonEmptyStringValue(top, "path_id"),
		AgentID:            firstNonEmptyStringValue(top, "agent_id"),
		Repo:               firstNonEmptyStringValue(top, "repo", "repository"),
		Workflow:           firstNonEmptyStringValue(top, "workflow", "workflow_ref", "location"),
		PullRequestRef:     firstNonEmptyStringValue(top, "pull_request_ref", "pr_ref", "review_ref"),
		MergeRequestRef:    firstNonEmptyStringValue(top, "merge_request_ref", "mr_ref"),
		AuthorRefs:         stringSliceValueFromRaw(top, "author_refs", "authors"),
		ReviewerRefs:       stringSliceValueFromRaw(top, "reviewer_refs", "reviewers"),
		Tool:               firstNonEmptyStringValue(top, "tool", "tool_type"),
		ProviderURL:        firstNonEmptyStringValue(top, "provider_url"),
		PromptRef:          aliasPrompt,
		ResponseRef:        aliasResponse,
		ChangedFiles:       stringSliceValueFromRaw(top, "changed_files", "files_touched"),
		Commands:           stringSliceValueFromRaw(top, "commands"),
		Actions:            stringSliceValueFromRaw(top, "actions", "action_classes"),
		FileWrites:         stringSliceValueFromRaw(top, "file_writes"),
		Approvals:          stringSliceValueFromRaw(top, "approvals"),
		PolicyDecisions:    stringSliceValueFromRaw(top, "policy_decisions"),
		CredentialSubjects: stringSliceValueFromRaw(top, "credential_subjects"),
		Declarations:       stringSliceValueFromRaw(top, "declarations"),
		ProofRefs:          stringSliceValueFromRaw(top, "proof_refs"),
		GraphNodeRefs:      stringSliceValueFromRaw(top, "graph_node_refs"),
		GraphEdgeRefs:      stringSliceValueFromRaw(top, "graph_edge_refs"),
		Outcome:            firstNonEmptyStringValue(top, "outcome", "result"),
		StartedAt:          firstNonEmptyStringValue(top, "started_at", "started", "created_at"),
		CompletedAt:        firstNonEmptyStringValue(top, "completed_at", "finished_at", "observed_at", "updated_at"),
		SourceArtifactRefs: stringSliceValueFromRaw(top, "source_artifact_refs", "artifacts"),
		RedactionHints:     stringSliceValueFromRaw(top, "redaction_hints"),
	}
	if record.SessionID == "" &&
		record.RunID == "" &&
		record.Repo == "" &&
		record.Workflow == "" &&
		record.PullRequestRef == "" &&
		record.MergeRequestRef == "" &&
		len(record.ChangedFiles) == 0 &&
		len(record.ProofRefs) == 0 &&
		len(record.GraphNodeRefs) == 0 &&
		len(record.GraphEdgeRefs) == 0 {
		return SessionRecord{}, unrecognizedSessionArtifactError{}
	}
	return record, nil
}

func inferSessionProvider(top map[string]json.RawMessage) string {
	switch {
	case hasAnyKey(top, "trace_id", "policy_decisions", "gait_trace"):
		return SessionProviderGait
	case hasAnyKey(top, "agent_session_id", "copilot_agent"):
		return SessionProviderCopilot
	case hasAnyKey(top, "conversation_id") && hasAnyKey(top, "cursor_workspace", "cursor_version"):
		return SessionProviderCursor
	case hasAnyKey(top, "conversation_id") && hasAnyKey(top, "transcript", "claude_code"):
		return SessionProviderClaudeCode
	case hasAnyKey(top, "session_id", "run_id") && hasAnyKey(top, "prompt", "response", "commands"):
		return SessionProviderCodex
	default:
		if hasAnyKey(top, "repo", "workflow", "changed_files", "proof_refs") {
			return SessionProviderUnknown
		}
		return ""
	}
}

func hasAnyKey(top map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		if _, ok := top[key]; ok {
			return true
		}
	}
	return false
}

func topLevelKeys(payload []byte) (map[string]json.RawMessage, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(payload, &top); err != nil {
		return nil, err
	}
	if top == nil {
		return nil, json.Unmarshal(payload, &top)
	}
	return top, nil
}

func stringValueFromRaw(top map[string]json.RawMessage, key string) string {
	raw, ok := top[key]
	if !ok {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err == nil {
		return strings.TrimSpace(value)
	}
	return ""
}

func firstNonEmptyStringValue(top map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		if value := stringValueFromRaw(top, key); value != "" {
			return value
		}
	}
	return ""
}

func stringSliceValueFromRaw(top map[string]json.RawMessage, keys ...string) []string {
	for _, key := range keys {
		raw, ok := top[key]
		if !ok {
			continue
		}
		var values []string
		if err := json.Unmarshal(raw, &values); err == nil {
			return mergeStrings(values...)
		}
		var single string
		if err := json.Unmarshal(raw, &single); err == nil {
			if strings.TrimSpace(single) == "" {
				return nil
			}
			parts := strings.Split(single, ",")
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				out = append(out, strings.TrimSpace(part))
			}
			return mergeStrings(out...)
		}
	}
	return nil
}

func normalizeSessionProvider(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SessionProviderCodex, "codex_cli", "codex_session":
		return SessionProviderCodex
	case SessionProviderClaudeCode, "claude", "claude-code", "claude_code_session":
		return SessionProviderClaudeCode
	case SessionProviderCursor:
		return SessionProviderCursor
	case SessionProviderCopilot, "github_copilot", "copilot_coding_agent":
		return SessionProviderCopilot
	case SessionProviderGait, "gait_trace":
		return SessionProviderGait
	case SessionProviderUnknown, "":
		return SessionProviderUnknown
	default:
		return SessionProviderUnknown
	}
}

func normalizeSessionStatus(value string) string {
	return normalizeRecordStatus(value)
}

func normalizeSessionOutcome(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "complete", "completed", "success", "succeeded":
		return "complete"
	case "partial", "warning":
		return "partial"
	case "failed", "error", "blocked":
		return "failed"
	case "stale":
		return "stale"
	default:
		return strings.TrimSpace(value)
	}
}

func normalizeOptionalRFC3339(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return ""
	}
	return parsed.UTC().Truncate(time.Second).Format(time.RFC3339)
}

func normalizeReviewRef(value string, prefix string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "/") {
		return trimmed
	}
	return prefix + "/" + trimmed
}

func normalizeOpaqueRef(value string) string {
	return strings.TrimSpace(value)
}

func normalizeRepoRelativeSessionPath(value string) string {
	trimmed := filepath.ToSlash(strings.TrimSpace(value))
	if trimmed == "" {
		return ""
	}
	return strings.TrimPrefix(trimmed, "./")
}

func normalizeSessionPathList(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := filepath.ToSlash(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "../") || strings.Contains(trimmed, "/../") || strings.Contains(trimmed, "\\..\\") {
			return nil, fmt.Errorf("runtime session path must stay repo-relative: %s", value)
		}
		out = append(out, strings.TrimPrefix(trimmed, "./"))
	}
	return mergeStrings(out...), nil
}

func sessionHasCorrelationKey(session SessionRecord) bool {
	return strings.TrimSpace(session.PathID) != "" ||
		strings.TrimSpace(session.AgentID) != "" ||
		(strings.TrimSpace(session.Repo) != "" && strings.TrimSpace(session.Workflow) != "") ||
		strings.TrimSpace(session.PullRequestRef) != "" ||
		strings.TrimSpace(session.MergeRequestRef) != "" ||
		len(session.ChangedFiles) > 0 ||
		len(session.ProofRefs) > 0 ||
		len(session.GraphNodeRefs) > 0 ||
		len(session.GraphEdgeRefs) > 0
}

func buildSessionID(session SessionRecord, generatedAt time.Time) string {
	seed := strings.Join([]string{
		firstNonEmpty(session.Provider, SessionProviderUnknown),
		firstNonEmpty(session.Repo, "local"),
		firstNonEmpty(session.Workflow, "workflow"),
		firstNonEmpty(session.RunID, "run"),
		firstNonEmpty(
			session.SessionID,
			session.PullRequestRef,
			session.MergeRequestRef,
			strings.Join(session.SourceArtifactRefs, ","),
			strings.Join(session.ChangedFiles, ","),
			strings.Join(session.FileWrites, ","),
			session.CompletedAt,
			session.StartedAt,
			generatedAt.UTC().Format(time.RFC3339),
		),
	}, "|")
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("session-%s", hex.EncodeToString(sum[:])[:12])
}

func rejectSecretLikeSessionValues(session SessionRecord) error {
	values := []string{
		session.ProviderURL,
		session.PullRequestRef,
		session.MergeRequestRef,
		session.PromptRef,
		session.ResponseRef,
	}
	values = append(values, session.ChangedFiles...)
	values = append(values, session.FileWrites...)
	values = append(values, session.Declarations...)
	values = append(values, session.CredentialSubjects...)
	values = append(values, session.SourceArtifactRefs...)
	for _, value := range values {
		if looksSecretLike(value) {
			return fmt.Errorf("runtime session contains secret-like value for %s", fallbackRecordLabel(firstNonEmpty(session.SessionID, session.RunID, session.Provider)))
		}
	}
	return nil
}

func digestRef(prefix, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return fmt.Sprintf("%s:sha256:%s", prefix, hex.EncodeToString(sum[:]))
}

func sessionToRuntimeRecords(session SessionRecord) []Record {
	observedAt := firstNonEmpty(session.CompletedAt, session.StartedAt)
	records := []Record{}
	appendRecord := func(class string, status string, refs []string, actionClasses []string) {
		record := Record{
			RecordKind:     RecordKindRuntime,
			SourceType:     SessionProviderUnknown,
			RecordID:       buildSessionProjectionID(session, class, observedAt),
			PathID:         session.PathID,
			AgentID:        session.AgentID,
			Tool:           firstNonEmpty(session.Tool, session.Provider),
			Repo:           session.Repo,
			Workflow:       session.Workflow,
			Location:       firstNonEmpty(session.Workflow, firstPathLike(session.ChangedFiles)),
			ActionClasses:  mergeStrings(actionClasses...),
			ProofRef:       firstNonEmpty(refs...),
			GraphNodeRefs:  append([]string(nil), session.GraphNodeRefs...),
			GraphEdgeRefs:  append([]string(nil), session.GraphEdgeRefs...),
			Source:         firstNonEmpty(session.Provider, SessionProviderUnknown),
			ObservedAt:     observedAt,
			RedactionHints: append([]string(nil), session.RedactionHints...),
			EvidenceClass:  class,
			Status:         firstNonEmpty(status, session.Status),
			EvidenceRefs:   append([]string(nil), session.SourceArtifactRefs...),
		}
		records = append(records, record)
	}
	if len(session.PolicyDecisions) > 0 {
		appendRecord(EvidenceClassPolicyDecision, session.Status, session.ProofRefs, session.Actions)
	}
	if len(session.Approvals) > 0 {
		appendRecord(EvidenceClassApproval, session.Status, session.ProofRefs, session.Actions)
	}
	if len(session.Actions) > 0 || len(session.FileWrites) > 0 || len(session.ChangedFiles) > 0 || strings.TrimSpace(session.Outcome) != "" {
		appendRecord(EvidenceClassActionOutcome, session.Status, session.ProofRefs, append([]string{"session_observed"}, session.Actions...))
	}
	if len(session.ProofRefs) > 0 {
		appendRecord(EvidenceClassProofVerify, session.Status, session.ProofRefs, session.Actions)
	}
	if len(records) == 0 {
		appendRecord(EvidenceClassOther, session.Status, session.ProofRefs, session.Actions)
	}
	return records
}

func sessionToEvidencePacket(session SessionRecord) EvidencePacket {
	result := "complete"
	switch normalizeSessionOutcome(session.Outcome) {
	case "failed":
		result = "failed"
	case "partial", "stale":
		result = "partial"
	}
	packet := EvidencePacket{
		PacketID:                 buildSessionProjectionID(session, "packet", firstNonEmpty(session.CompletedAt, session.StartedAt)),
		Source:                   firstNonEmpty(session.Provider, SessionProviderUnknown),
		SourceType:               "runtime_session",
		Provider:                 session.Provider,
		ProviderURL:              session.ProviderURL,
		Repo:                     session.Repo,
		Workflow:                 session.Workflow,
		PathID:                   session.PathID,
		AgentID:                  session.AgentID,
		PullRequestRef:           firstNonEmpty(session.PullRequestRef, session.MergeRequestRef),
		Task:                     firstNonEmpty(session.PromptRef, session.ResponseRef),
		Title:                    firstNonEmpty(session.Outcome, session.Status),
		FilesTouched:             append([]string(nil), session.ChangedFiles...),
		DiffRefs:                 append([]string(nil), session.SourceArtifactRefs...),
		AutonomyTier:             "",
		DelegationReadinessState: "",
		Reviewers:                append([]string(nil), session.ReviewerRefs...),
		Approvals:                append([]string(nil), session.Approvals...),
		PolicyVerdict:            firstNonEmpty(session.PolicyDecisions...),
		Result:                   result,
		MissingEvidenceState:     sessionMissingEvidenceState(session),
		ProofRefs:                append([]string(nil), session.ProofRefs...),
		GraphNodeRefs:            append([]string(nil), session.GraphNodeRefs...),
		GraphEdgeRefs:            append([]string(nil), session.GraphEdgeRefs...),
		EvidenceRefs:             append([]string(nil), session.SourceArtifactRefs...),
		ObservedAt:               firstNonEmpty(session.CompletedAt, session.StartedAt),
		RedactionHints:           append([]string(nil), session.RedactionHints...),
	}
	return packet
}

func sessionMissingEvidenceState(session SessionRecord) string {
	missing := 0
	if strings.TrimSpace(session.Outcome) == "" {
		missing++
	}
	if len(session.ProofRefs) == 0 {
		missing++
	}
	if len(session.ChangedFiles) == 0 && len(session.FileWrites) == 0 {
		missing++
	}
	switch missing {
	case 0:
		return "complete"
	case 1:
		return "partial"
	default:
		return "missing"
	}
}

func buildSessionProjectionID(session SessionRecord, kind, observedAt string) string {
	seed := strings.Join([]string{
		firstNonEmpty(kind, "session"),
		firstNonEmpty(session.SessionID, session.RunID),
		firstNonEmpty(session.Provider, SessionProviderUnknown),
		firstNonEmpty(session.Repo, "local"),
		firstNonEmpty(observedAt, session.CompletedAt, session.StartedAt),
	}, "|")
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%s-%s", kind, hex.EncodeToString(sum[:])[:12])
}

func firstPathLike(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
