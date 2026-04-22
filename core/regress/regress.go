package regress

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const BaselineVersion = "v1"

const (
	ReasonNewUnapprovedTool        = "new_unapproved_tool"
	ReasonRevokedToolReappeared    = "revoked_tool_reappeared"
	ReasonDeprecatedToolReappeared = "deprecated_tool_reappeared"
	ReasonPermissionExpansion      = "unapproved_permission_expansion"
	ReasonCriticalAttackPath       = "critical_attack_path_drift"
	defaultApprovalState           = "missing"
	defaultLifecycleState          = identity.StateUnderReview
	criticalAttackPathMinScore     = 8.0
	attackPathScoreDeltaMin        = 1.0
	attackPathDriftMinAbsolute     = 2
	attackPathDriftMinRelative     = 0.25
	attackPathExampleLimit         = 5
)

type Baseline struct {
	Version     string            `json:"version"`
	GeneratedAt string            `json:"generated_at"`
	Tools       []ToolState       `json:"tools"`
	AttackPaths []AttackPathState `json:"attack_paths,omitempty"`
}

type ToolState struct {
	AgentID         string   `json:"agent_id"`
	AgentInstanceID string   `json:"agent_instance_id,omitempty"`
	ToolID          string   `json:"tool_id"`
	Org             string   `json:"org"`
	Status          string   `json:"status"`
	ApprovalStatus  string   `json:"approval_status"`
	Present         bool     `json:"present"`
	Permissions     []string `json:"permissions"`
	LegacyAgentID   string   `json:"-"`
}

type AttackPathState struct {
	PathID string  `json:"path_id"`
	Org    string  `json:"org"`
	Repo   string  `json:"repo"`
	Score  float64 `json:"score"`
}

type Reason struct {
	Code             string                  `json:"code"`
	AgentID          string                  `json:"agent_id"`
	AgentInstanceID  string                  `json:"agent_instance_id,omitempty"`
	ToolID           string                  `json:"tool_id"`
	Org              string                  `json:"org"`
	Message          string                  `json:"message"`
	AddedPermissions []string                `json:"added_permissions,omitempty"`
	AttackPathDrift  *AttackPathDriftSummary `json:"attack_path_drift,omitempty"`
}

type AttackPathScoreChange struct {
	PathID        string  `json:"path_id"`
	Org           string  `json:"org"`
	Repo          string  `json:"repo"`
	BaselineScore float64 `json:"baseline_score"`
	CurrentScore  float64 `json:"current_score"`
	ScoreDelta    float64 `json:"score_delta"`
}

type AttackPathDriftSummary struct {
	BaselineCriticalCount int                     `json:"baseline_critical_count"`
	CurrentCriticalCount  int                     `json:"current_critical_count"`
	Added                 []AttackPathState       `json:"added,omitempty"`
	Removed               []AttackPathState       `json:"removed,omitempty"`
	ScoreChanged          []AttackPathScoreChange `json:"score_changed,omitempty"`
	DriftCount            int                     `json:"drift_count"`
	DriftRatio            float64                 `json:"drift_ratio"`
	MinAbsolute           int                     `json:"min_absolute"`
	MinRelative           float64                 `json:"min_relative"`
}

type Result struct {
	Status        string   `json:"status"`
	Drift         bool     `json:"drift_detected"`
	ReasonCount   int      `json:"reason_count"`
	Reasons       []Reason `json:"reasons"`
	BaselinePath  string   `json:"baseline_path,omitempty"`
	SummaryMDPath string   `json:"summary_md_path,omitempty"`
}

func BuildBaseline(snapshot state.Snapshot, generatedAt time.Time) Baseline {
	now := generatedAt.UTC().Truncate(time.Second)
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Second)
	}
	tools := SnapshotTools(snapshot)
	return Baseline{
		Version:     BaselineVersion,
		GeneratedAt: now.Format(time.RFC3339),
		Tools:       tools,
		AttackPaths: snapshotAttackPaths(snapshot),
	}
}

func SnapshotTools(snapshot state.Snapshot) []ToolState {
	byAgent := map[string]*ToolState{}
	useInstanceIDs := false
	for _, item := range snapshot.Identities {
		if !model.IsLegacyArtifactIdentityCandidate(item.ToolType, item.ToolID, item.AgentID) {
			continue
		}
		agentID := strings.TrimSpace(item.AgentID)
		if agentID == "" {
			continue
		}
		useInstanceIDs = true
		tool := &ToolState{
			AgentID:         agentID,
			AgentInstanceID: strings.TrimSpace(item.ToolID),
			ToolID:          strings.TrimSpace(item.ToolID),
			Org:             fallback(item.Org, "local"),
			Status:          fallback(item.Status, defaultLifecycleState),
			ApprovalStatus:  fallback(item.ApprovalState, defaultApprovalState),
			Present:         item.Present,
			Permissions:     []string{},
		}
		byAgent[agentID] = tool
	}

	for _, finding := range snapshot.Findings {
		if !model.IsIdentityBearingFinding(finding) {
			continue
		}
		org := fallback(finding.Org, "local")
		toolID, agentID, legacyAgentID := snapshotFindingIdentity(finding, useInstanceIDs)
		item, exists := byAgent[agentID]
		if !exists {
			item = &ToolState{
				AgentID:         agentID,
				AgentInstanceID: toolID,
				ToolID:          toolID,
				Org:             org,
				Status:          defaultLifecycleState,
				ApprovalStatus:  defaultApprovalState,
				Present:         true,
				Permissions:     []string{},
				LegacyAgentID:   legacyAgentID,
			}
			byAgent[agentID] = item
		}
		if strings.TrimSpace(item.ToolID) == "" {
			item.ToolID = toolID
		}
		if strings.TrimSpace(item.AgentInstanceID) == "" {
			item.AgentInstanceID = toolID
		}
		if strings.TrimSpace(item.LegacyAgentID) == "" {
			item.LegacyAgentID = legacyAgentID
		}
		item.Present = true
		item.Permissions = append(item.Permissions, finding.Permissions...)
	}

	out := make([]ToolState, 0, len(byAgent))
	for _, item := range byAgent {
		item.Permissions = dedupeSortedPermissions(item.Permissions)
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentInstanceID != out[j].AgentInstanceID {
			return out[i].AgentInstanceID < out[j].AgentInstanceID
		}
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		if out[i].ToolID != out[j].ToolID {
			return out[i].ToolID < out[j].ToolID
		}
		return out[i].Org < out[j].Org
	})
	return out
}

func SaveBaseline(path string, baseline Baseline) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("baseline path is required")
	}
	baseline.Version = BaselineVersion
	sort.Slice(baseline.Tools, func(i, j int) bool {
		if baseline.Tools[i].AgentInstanceID != baseline.Tools[j].AgentInstanceID {
			return baseline.Tools[i].AgentInstanceID < baseline.Tools[j].AgentInstanceID
		}
		if baseline.Tools[i].AgentID != baseline.Tools[j].AgentID {
			return baseline.Tools[i].AgentID < baseline.Tools[j].AgentID
		}
		return baseline.Tools[i].ToolID < baseline.Tools[j].ToolID
	})
	for i := range baseline.Tools {
		baseline.Tools[i].Permissions = dedupeSortedPermissions(baseline.Tools[i].Permissions)
	}
	baseline.AttackPaths = sortAttackPaths(baseline.AttackPaths)

	payload, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return nil
}

func BuildBaselineFromSnapshot(snapshot state.Snapshot) Baseline {
	return normalizeBaseline(Baseline{
		Version:     BaselineVersion,
		Tools:       SnapshotTools(snapshot),
		AttackPaths: snapshotAttackPaths(snapshot),
	})
}

func LoadBaseline(path string) (Baseline, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller provides explicit local baseline path.
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	return loadBaselinePayload(payload)
}

func LoadComparableBaseline(path string) (Baseline, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller provides explicit local baseline path.
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	kind, err := detectBaselineInputKind(payload)
	if err != nil {
		return Baseline{}, err
	}
	switch kind {
	case "regress_baseline":
		return loadBaselinePayload(payload)
	case "scan_snapshot":
		snapshot, err := loadSnapshotPayload(payload)
		if err != nil {
			return Baseline{}, err
		}
		return BuildBaselineFromSnapshot(snapshot), nil
	default:
		return Baseline{}, fmt.Errorf("parse baseline: expected regress baseline artifact or scan snapshot")
	}
}

func Compare(baseline Baseline, current state.Snapshot) Result {
	currentTools := SnapshotTools(current)
	baseByAgent := map[string]ToolState{}
	baseByInstance := map[string]ToolState{}
	for _, item := range baseline.Tools {
		item.Permissions = dedupeSortedPermissions(item.Permissions)
		baseByAgent[item.AgentID] = item
		if instanceID := strings.TrimSpace(item.AgentInstanceID); instanceID != "" {
			baseByInstance[baselineInstanceKey(item.Org, instanceID)] = item
		}
	}
	reasons := make([]Reason, 0)
	legacyClaims := map[string]struct{}{}

	for _, currentTool := range currentTools {
		baseTool, exists := matchBaselineTool(baseByAgent, baseByInstance, legacyClaims, currentTool)
		if !exists {
			if currentTool.Present && !isApproved(currentTool) {
				reasons = append(reasons, Reason{
					Code:            ReasonNewUnapprovedTool,
					AgentID:         currentTool.AgentID,
					AgentInstanceID: currentTool.AgentInstanceID,
					ToolID:          currentTool.ToolID,
					Org:             currentTool.Org,
					Message:         "detected tool not present in approved baseline",
				})
			}
			continue
		}

		if strings.TrimSpace(baseTool.Status) == identity.StateRevoked && currentTool.Present {
			reasons = append(reasons, Reason{
				Code:            ReasonRevokedToolReappeared,
				AgentID:         currentTool.AgentID,
				AgentInstanceID: currentTool.AgentInstanceID,
				ToolID:          currentTool.ToolID,
				Org:             currentTool.Org,
				Message:         "revoked tool reappeared in current scan",
			})
		}
		if strings.TrimSpace(baseTool.Status) == identity.StateDeprecated && currentTool.Present {
			reasons = append(reasons, Reason{
				Code:            ReasonDeprecatedToolReappeared,
				AgentID:         currentTool.AgentID,
				AgentInstanceID: currentTool.AgentInstanceID,
				ToolID:          currentTool.ToolID,
				Org:             currentTool.Org,
				Message:         "deprecated tool reappeared in current scan",
			})
		}

		added := permissionDelta(baseTool.Permissions, currentTool.Permissions)
		if len(added) > 0 && !isApproved(currentTool) {
			reasons = append(reasons, Reason{
				Code:             ReasonPermissionExpansion,
				AgentID:          currentTool.AgentID,
				AgentInstanceID:  currentTool.AgentInstanceID,
				ToolID:           currentTool.ToolID,
				Org:              currentTool.Org,
				Message:          "tool permissions expanded without approval",
				AddedPermissions: added,
			})
		}
	}

	attackPathDrift := summarizeCriticalAttackPathDrift(baseline.AttackPaths, snapshotAttackPaths(current))
	if attackPathDrift != nil && shouldEmitCriticalAttackPathDrift(*attackPathDrift) {
		examples := topAttackPathDriftExamples(*attackPathDrift, attackPathExampleLimit)
		message := fmt.Sprintf(
			"critical attack path drift detected (added=%d removed=%d score_changed=%d drift=%d ratio=%.2f thresholds abs>=%d rel>=%.2f)",
			len(attackPathDrift.Added),
			len(attackPathDrift.Removed),
			len(attackPathDrift.ScoreChanged),
			attackPathDrift.DriftCount,
			attackPathDrift.DriftRatio,
			attackPathDrift.MinAbsolute,
			attackPathDrift.MinRelative,
		)
		if len(examples) > 0 {
			message = message + "; examples=" + strings.Join(examples, ",")
		}
		reasons = append(reasons, Reason{
			Code:            ReasonCriticalAttackPath,
			ToolID:          "attack_paths",
			Org:             attackPathDriftOrg(*attackPathDrift),
			Message:         message,
			AttackPathDrift: attackPathDrift,
		})
	}

	sort.Slice(reasons, func(i, j int) bool {
		if reasons[i].Code != reasons[j].Code {
			return reasons[i].Code < reasons[j].Code
		}
		if reasons[i].AgentID != reasons[j].AgentID {
			return reasons[i].AgentID < reasons[j].AgentID
		}
		return reasons[i].ToolID < reasons[j].ToolID
	})

	drift := len(reasons) > 0
	status := "ok"
	if drift {
		status = "drift"
	}
	return Result{
		Status:      status,
		Drift:       drift,
		ReasonCount: len(reasons),
		Reasons:     reasons,
	}
}

func matchBaselineTool(baseByAgent map[string]ToolState, baseByInstance map[string]ToolState, legacyClaims map[string]struct{}, currentTool ToolState) (ToolState, bool) {
	if instanceID := strings.TrimSpace(currentTool.AgentInstanceID); instanceID != "" {
		if baseTool, exists := baseByInstance[baselineInstanceKey(currentTool.Org, instanceID)]; exists {
			return baseTool, true
		}
	}
	if baseTool, exists := baseByAgent[currentTool.AgentID]; exists {
		return baseTool, true
	}
	legacyAgentID := strings.TrimSpace(currentTool.LegacyAgentID)
	if legacyAgentID == "" || legacyAgentID == currentTool.AgentID {
		return ToolState{}, false
	}
	if _, claimed := legacyClaims[legacyAgentID]; claimed {
		return ToolState{}, false
	}
	baseTool, exists := baseByAgent[legacyAgentID]
	if !exists {
		return ToolState{}, false
	}
	legacyClaims[legacyAgentID] = struct{}{}
	return baseTool, true
}

func baselineInstanceKey(org, instanceID string) string {
	return fallback(org, "local") + "::" + strings.TrimSpace(instanceID)
}

func dedupeSortedPermissions(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func loadBaselinePayload(payload []byte) (Baseline, error) {
	var baseline Baseline
	if err := json.Unmarshal(payload, &baseline); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline: %w", err)
	}
	return normalizeBaseline(baseline), nil
}

func loadSnapshotPayload(payload []byte) (state.Snapshot, error) {
	var snapshot state.Snapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return state.Snapshot{}, fmt.Errorf("parse baseline snapshot: %w", err)
	}
	if snapshot.Version == "" {
		snapshot.Version = state.SnapshotVersion
	}
	model.SortFindings(snapshot.Findings)
	return snapshot, nil
}

func normalizeBaseline(baseline Baseline) Baseline {
	if strings.TrimSpace(baseline.Version) == "" {
		baseline.Version = BaselineVersion
	}
	filtered := baseline.Tools[:0]
	for i := range baseline.Tools {
		if strings.TrimSpace(baseline.Tools[i].AgentInstanceID) == "" {
			baseline.Tools[i].AgentInstanceID = strings.TrimSpace(baseline.Tools[i].ToolID)
		}
		if !model.IsLegacyArtifactIdentityCandidate("", baseline.Tools[i].ToolID, baseline.Tools[i].AgentID) {
			continue
		}
		filtered = append(filtered, baseline.Tools[i])
	}
	baseline.Tools = filtered
	sort.Slice(baseline.Tools, func(i, j int) bool {
		if baseline.Tools[i].AgentInstanceID != baseline.Tools[j].AgentInstanceID {
			return baseline.Tools[i].AgentInstanceID < baseline.Tools[j].AgentInstanceID
		}
		if baseline.Tools[i].AgentID != baseline.Tools[j].AgentID {
			return baseline.Tools[i].AgentID < baseline.Tools[j].AgentID
		}
		return baseline.Tools[i].ToolID < baseline.Tools[j].ToolID
	})
	for i := range baseline.Tools {
		baseline.Tools[i].Permissions = dedupeSortedPermissions(baseline.Tools[i].Permissions)
	}
	baseline.AttackPaths = sortAttackPaths(baseline.AttackPaths)
	return baseline
}

func detectBaselineInputKind(payload []byte) (string, error) {
	var probe struct {
		Tools       json.RawMessage `json:"tools"`
		GeneratedAt json.RawMessage `json:"generated_at"`
		AttackPaths json.RawMessage `json:"attack_paths"`
		Findings    json.RawMessage `json:"findings"`
		Target      json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return "", fmt.Errorf("parse baseline: %w", err)
	}
	if len(probe.Findings) > 0 || len(probe.Target) > 0 {
		return "scan_snapshot", nil
	}
	if len(probe.Tools) > 0 || len(probe.GeneratedAt) > 0 || len(probe.AttackPaths) > 0 {
		return "regress_baseline", nil
	}
	return "", fmt.Errorf("parse baseline: expected regress baseline artifact or scan snapshot")
}

func permissionDelta(base, current []string) []string {
	baseSet := map[string]struct{}{}
	for _, value := range base {
		baseSet[value] = struct{}{}
	}
	added := make([]string, 0)
	for _, value := range current {
		if _, exists := baseSet[value]; exists {
			continue
		}
		added = append(added, value)
	}
	return dedupeSortedPermissions(added)
}

func isApproved(tool ToolState) bool {
	approval := strings.TrimSpace(tool.ApprovalStatus)
	status := strings.TrimSpace(tool.Status)
	if approval == "valid" {
		return true
	}
	return status == identity.StateApproved || status == identity.StateActive
}

func fallback(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return value
}

func snapshotFindingIdentity(finding model.Finding, useInstanceIDs bool) (toolID string, agentID string, legacyAgentID string) {
	org := fallback(finding.Org, "local")
	legacyAgentID = identity.LegacyAgentID(finding.ToolType, finding.Location, org)
	if !useInstanceIDs {
		toolID = identity.ToolID(finding.ToolType, finding.Location)
		return toolID, legacyAgentID, legacyAgentID
	}
	symbol := findingAgentSymbol(finding)
	startLine, endLine := findingRangeLines(finding)
	toolID = identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
	return toolID, identity.AgentID(toolID, org), legacyAgentID
}

func findingAgentSymbol(finding model.Finding) string {
	index := map[string]string{}
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "" {
			continue
		}
		index[key] = strings.TrimSpace(evidence.Value)
	}
	for _, key := range []string{
		"symbol",
		"name",
		"agent_name",
		"agent.symbol",
		"agent.name",
		"function",
		"class",
	} {
		if value := strings.TrimSpace(index[key]); value != "" {
			return value
		}
	}
	return ""
}

func findingRangeLines(finding model.Finding) (int, int) {
	if finding.LocationRange == nil {
		return 0, 0
	}
	return finding.LocationRange.StartLine, finding.LocationRange.EndLine
}

func snapshotAttackPaths(snapshot state.Snapshot) []AttackPathState {
	if snapshot.RiskReport == nil || len(snapshot.RiskReport.AttackPaths) == 0 {
		return nil
	}
	out := make([]AttackPathState, 0, len(snapshot.RiskReport.AttackPaths))
	for _, item := range snapshot.RiskReport.AttackPaths {
		out = append(out, AttackPathState{
			PathID: strings.TrimSpace(item.PathID),
			Org:    fallback(item.Org, "local"),
			Repo:   strings.TrimSpace(item.Repo),
			Score:  item.PathScore,
		})
	}
	return sortAttackPaths(out)
}

func sortAttackPaths(in []AttackPathState) []AttackPathState {
	out := append([]AttackPathState(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].PathID != out[j].PathID {
			return out[i].PathID < out[j].PathID
		}
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		return out[i].Repo < out[j].Repo
	})
	return out
}

type attackPathKey struct {
	PathID string
	Org    string
	Repo   string
}

func summarizeCriticalAttackPathDrift(baseline []AttackPathState, current []AttackPathState) *AttackPathDriftSummary {
	baseCritical := filterCriticalAttackPaths(baseline)
	currentCritical := filterCriticalAttackPaths(current)
	baseByKey := map[attackPathKey]AttackPathState{}
	currentByKey := map[attackPathKey]AttackPathState{}
	for _, item := range baseCritical {
		baseByKey[attackPathStateKey(item)] = item
	}
	for _, item := range currentCritical {
		currentByKey[attackPathStateKey(item)] = item
	}

	added := make([]AttackPathState, 0)
	removed := make([]AttackPathState, 0)
	changed := make([]AttackPathScoreChange, 0)
	for key, baseItem := range baseByKey {
		currentItem, exists := currentByKey[key]
		if !exists {
			removed = append(removed, baseItem)
			continue
		}
		delta := round2(currentItem.Score - baseItem.Score)
		if math.Abs(delta) >= attackPathScoreDeltaMin {
			changed = append(changed, AttackPathScoreChange{
				PathID:        key.PathID,
				Org:           key.Org,
				Repo:          key.Repo,
				BaselineScore: round2(baseItem.Score),
				CurrentScore:  round2(currentItem.Score),
				ScoreDelta:    delta,
			})
		}
	}
	for key, currentItem := range currentByKey {
		if _, exists := baseByKey[key]; exists {
			continue
		}
		added = append(added, currentItem)
	}

	added = sortAttackPaths(added)
	removed = sortAttackPaths(removed)
	sort.Slice(changed, func(i, j int) bool {
		if changed[i].PathID != changed[j].PathID {
			return changed[i].PathID < changed[j].PathID
		}
		if changed[i].Org != changed[j].Org {
			return changed[i].Org < changed[j].Org
		}
		return changed[i].Repo < changed[j].Repo
	})

	driftCount := len(added) + len(removed) + len(changed)
	if driftCount == 0 {
		return nil
	}
	scale := len(baseCritical)
	if len(currentCritical) > scale {
		scale = len(currentCritical)
	}
	if scale == 0 {
		scale = 1
	}
	return &AttackPathDriftSummary{
		BaselineCriticalCount: len(baseCritical),
		CurrentCriticalCount:  len(currentCritical),
		Added:                 added,
		Removed:               removed,
		ScoreChanged:          changed,
		DriftCount:            driftCount,
		DriftRatio:            round2(float64(driftCount) / float64(scale)),
		MinAbsolute:           attackPathDriftMinAbsolute,
		MinRelative:           attackPathDriftMinRelative,
	}
}

func filterCriticalAttackPaths(paths []AttackPathState) []AttackPathState {
	filtered := make([]AttackPathState, 0, len(paths))
	for _, item := range sortAttackPaths(paths) {
		if item.Score < criticalAttackPathMinScore {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func shouldEmitCriticalAttackPathDrift(drift AttackPathDriftSummary) bool {
	if drift.DriftCount < drift.MinAbsolute {
		return false
	}
	return drift.DriftRatio >= drift.MinRelative
}

func topAttackPathDriftExamples(drift AttackPathDriftSummary, limit int) []string {
	if limit <= 0 {
		return nil
	}
	out := make([]string, 0, limit)
	appendExamples := func(prefix string, values []AttackPathState) {
		for _, item := range values {
			if len(out) >= limit {
				return
			}
			out = append(out, prefix+":"+item.PathID)
		}
	}
	appendExamples("added", drift.Added)
	appendExamples("removed", drift.Removed)
	for _, item := range drift.ScoreChanged {
		if len(out) >= limit {
			break
		}
		out = append(out, fmt.Sprintf("changed:%s(%.2f->%.2f)", item.PathID, item.BaselineScore, item.CurrentScore))
	}
	return out
}

func attackPathDriftOrg(drift AttackPathDriftSummary) string {
	orgs := map[string]struct{}{}
	for _, item := range drift.Added {
		orgs[item.Org] = struct{}{}
	}
	for _, item := range drift.Removed {
		orgs[item.Org] = struct{}{}
	}
	for _, item := range drift.ScoreChanged {
		orgs[item.Org] = struct{}{}
	}
	keys := make([]string, 0, len(orgs))
	for org := range orgs {
		trimmed := strings.TrimSpace(org)
		if trimmed == "" {
			continue
		}
		keys = append(keys, trimmed)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return "local"
	}
	if len(keys) == 1 {
		return keys[0]
	}
	return "multi"
}

func attackPathStateKey(item AttackPathState) attackPathKey {
	return attackPathKey{
		PathID: strings.TrimSpace(item.PathID),
		Org:    fallback(item.Org, "local"),
		Repo:   strings.TrimSpace(item.Repo),
	}
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}
