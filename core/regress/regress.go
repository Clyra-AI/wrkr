package regress

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
)

const BaselineVersion = "v1"

const (
	ReasonNewUnapprovedTool     = "new_unapproved_tool"
	ReasonRevokedToolReappeared = "revoked_tool_reappeared"
	ReasonPermissionExpansion   = "unapproved_permission_expansion"
	ReasonCriticalAttackPath    = "critical_attack_path_drift"
	defaultApprovalState        = "missing"
	defaultLifecycleState       = identity.StateUnderReview
	criticalAttackPathMinScore  = 8.0
	attackPathScoreDeltaMin     = 1.0
	attackPathDriftMinAbsolute  = 2
	attackPathDriftMinRelative  = 0.25
	attackPathExampleLimit      = 5
)

type Baseline struct {
	Version     string            `json:"version"`
	GeneratedAt string            `json:"generated_at"`
	Tools       []ToolState       `json:"tools"`
	AttackPaths []AttackPathState `json:"attack_paths,omitempty"`
}

type ToolState struct {
	AgentID        string   `json:"agent_id"`
	ToolID         string   `json:"tool_id"`
	Org            string   `json:"org"`
	Status         string   `json:"status"`
	ApprovalStatus string   `json:"approval_status"`
	Present        bool     `json:"present"`
	Permissions    []string `json:"permissions"`
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
	for _, item := range snapshot.Identities {
		agentID := strings.TrimSpace(item.AgentID)
		if agentID == "" {
			continue
		}
		tool := &ToolState{
			AgentID:        agentID,
			ToolID:         strings.TrimSpace(item.ToolID),
			Org:            fallback(item.Org, "local"),
			Status:         fallback(item.Status, defaultLifecycleState),
			ApprovalStatus: fallback(item.ApprovalState, defaultApprovalState),
			Present:        item.Present,
			Permissions:    []string{},
		}
		byAgent[agentID] = tool
	}

	for _, finding := range snapshot.Findings {
		if !model.IsIdentityBearingFinding(finding) {
			continue
		}
		org := fallback(finding.Org, "local")
		toolID := identity.ToolID(finding.ToolType, finding.Location)
		agentID := identity.AgentID(toolID, org)
		item, exists := byAgent[agentID]
		if !exists {
			item = &ToolState{
				AgentID:        agentID,
				ToolID:         toolID,
				Org:            org,
				Status:         defaultLifecycleState,
				ApprovalStatus: defaultApprovalState,
				Present:        true,
				Permissions:    []string{},
			}
			byAgent[agentID] = item
		}
		if strings.TrimSpace(item.ToolID) == "" {
			item.ToolID = toolID
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
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir baseline dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "regress-baseline-*.json")
	if err != nil {
		return fmt.Errorf("create baseline temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write baseline temp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod baseline temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close baseline temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil { // #nosec G703 -- caller-selected baseline path is intentional for local deterministic artifact output.
		return fmt.Errorf("commit baseline: %w", err)
	}
	return nil
}

func LoadBaseline(path string) (Baseline, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- caller provides explicit local baseline path.
	if err != nil {
		return Baseline{}, fmt.Errorf("read baseline: %w", err)
	}
	var baseline Baseline
	if err := json.Unmarshal(payload, &baseline); err != nil {
		return Baseline{}, fmt.Errorf("parse baseline: %w", err)
	}
	if strings.TrimSpace(baseline.Version) == "" {
		baseline.Version = BaselineVersion
	}
	sort.Slice(baseline.Tools, func(i, j int) bool {
		if baseline.Tools[i].AgentID != baseline.Tools[j].AgentID {
			return baseline.Tools[i].AgentID < baseline.Tools[j].AgentID
		}
		return baseline.Tools[i].ToolID < baseline.Tools[j].ToolID
	})
	for i := range baseline.Tools {
		baseline.Tools[i].Permissions = dedupeSortedPermissions(baseline.Tools[i].Permissions)
	}
	baseline.AttackPaths = sortAttackPaths(baseline.AttackPaths)
	return baseline, nil
}

func Compare(baseline Baseline, current state.Snapshot) Result {
	currentTools := SnapshotTools(current)
	baseByAgent := map[string]ToolState{}
	for _, item := range baseline.Tools {
		item.Permissions = dedupeSortedPermissions(item.Permissions)
		baseByAgent[item.AgentID] = item
	}
	reasons := make([]Reason, 0)

	for _, currentTool := range currentTools {
		baseTool, exists := baseByAgent[currentTool.AgentID]
		if !exists {
			if currentTool.Present && !isApproved(currentTool) {
				reasons = append(reasons, Reason{
					Code:    ReasonNewUnapprovedTool,
					AgentID: currentTool.AgentID,
					ToolID:  currentTool.ToolID,
					Org:     currentTool.Org,
					Message: "detected tool not present in approved baseline",
				})
			}
			continue
		}

		if strings.TrimSpace(baseTool.Status) == identity.StateRevoked && currentTool.Present {
			reasons = append(reasons, Reason{
				Code:    ReasonRevokedToolReappeared,
				AgentID: currentTool.AgentID,
				ToolID:  currentTool.ToolID,
				Org:     currentTool.Org,
				Message: "revoked tool reappeared in current scan",
			})
		}

		added := permissionDelta(baseTool.Permissions, currentTool.Permissions)
		if len(added) > 0 && !isApproved(currentTool) {
			reasons = append(reasons, Reason{
				Code:             ReasonPermissionExpansion,
				AgentID:          currentTool.AgentID,
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
