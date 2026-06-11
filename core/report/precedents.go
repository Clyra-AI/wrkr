package report

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func decorateActionPathsWithPrecedents(statePath string, now time.Time, paths []risk.ActionPath) []risk.ActionPath {
	if len(paths) == 0 {
		return nil
	}
	precedents, ok := loadDecisionPrecedents(statePath)
	if !ok {
		return paths
	}
	out := append([]risk.ActionPath(nil), paths...)
	for idx := range out {
		key := precedentKeyForPath(out[idx])
		record, found := precedents[key]
		if !found {
			continue
		}
		out[idx].DecisionPrecedent = buildDecisionPrecedent(record, now)
	}
	return out
}

func loadDecisionPrecedents(statePath string) (map[string]config.DecisionPrecedentRecord, bool) {
	if strings.TrimSpace(statePath) == "" {
		return nil, false
	}
	path := filepath.Join(filepath.Dir(state.ResolvePath(statePath)), "decision-precedents.json")
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}
	bundle, err := config.LoadDecisionPrecedents(path)
	if err != nil {
		return nil, false
	}
	out := make(map[string]config.DecisionPrecedentRecord, len(bundle.Precedents))
	for _, item := range bundle.Precedents {
		out[strings.TrimSpace(item.PrecedentKey)] = item
	}
	return out, true
}

func precedentKeyForPath(path risk.ActionPath) string {
	if pathID := strings.TrimSpace(path.PathID); pathID != "" {
		return "path:" + pathID
	}
	return strings.TrimSpace(path.AgentID) + "|" + strings.TrimSpace(path.Location)
}

func buildDecisionPrecedent(item config.DecisionPrecedentRecord, now time.Time) *risk.DecisionPrecedent {
	status := "active"
	reasons := []string{}
	if strings.TrimSpace(item.Confidence) == "low" {
		status = "low_confidence"
		reasons = append(reasons, "precedent_low_confidence")
	}
	ageDays := 0
	if observedAt := strings.TrimSpace(item.ObservedAt); observedAt != "" {
		if ts, err := time.Parse(time.RFC3339, observedAt); err == nil {
			ageDays = int(now.UTC().Sub(ts.UTC()).Hours() / 24)
		}
	}
	if expiresAt := strings.TrimSpace(item.ExpiresAt); expiresAt != "" {
		if ts, err := time.Parse(time.RFC3339, expiresAt); err == nil && now.UTC().After(ts.UTC()) {
			status = "expired"
			reasons = append(reasons, "precedent_expired")
		}
	}
	return &risk.DecisionPrecedent{
		PrecedentKey:     strings.TrimSpace(item.PrecedentKey),
		DecisionTraceRef: strings.TrimSpace(item.DecisionTraceRef),
		PriorDecision:    strings.TrimSpace(item.PriorDecision),
		DecisionSource:   strings.TrimSpace(item.DecisionSource),
		DecisionAgeDays:  ageDays,
		Confidence:       strings.TrimSpace(item.Confidence),
		ExpiresAt:        strings.TrimSpace(item.ExpiresAt),
		Status:           status,
		EvidenceRefs:     append([]string(nil), item.EvidenceRefs...),
		ReasonCodes:      append(append([]string(nil), item.ReasonCodes...), reasons...),
	}
}
