package regress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/state"
)

const BaselineVersion = "v1"

const (
	ReasonNewUnapprovedTool     = "new_unapproved_tool"
	ReasonRevokedToolReappeared = "revoked_tool_reappeared"
	ReasonPermissionExpansion   = "unapproved_permission_expansion"
	defaultApprovalState        = "missing"
	defaultLifecycleState       = identity.StateUnderReview
)

type Baseline struct {
	Version     string      `json:"version"`
	GeneratedAt string      `json:"generated_at"`
	Tools       []ToolState `json:"tools"`
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

type Reason struct {
	Code             string   `json:"code"`
	AgentID          string   `json:"agent_id"`
	ToolID           string   `json:"tool_id"`
	Org              string   `json:"org"`
	Message          string   `json:"message"`
	AddedPermissions []string `json:"added_permissions,omitempty"`
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
	if err := os.Rename(tmpPath, path); err != nil {
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
