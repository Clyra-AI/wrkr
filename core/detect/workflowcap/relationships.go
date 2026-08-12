package workflowcap

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

func normalizedExecutionRelationships(evidence []model.Evidence) []model.ExecutionRelationship {
	type resolutionReceipt struct {
		kind, caller, callee, state string
		reasons                     []string
		ref                         string
	}
	stateOverrides := map[string]string{}
	truncation := map[string][]string{}
	receipts := make([]resolutionReceipt, 0)
	for _, item := range evidence {
		if item.Key != "execution_resolution" {
			continue
		}
		parts := strings.Split(strings.TrimSpace(item.Value), "|")
		if len(parts) < 4 {
			continue
		}
		kind, caller, callee, state := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3])
		key := strings.Join([]string{kind, caller, callee}, "|")
		stateOverrides[key] = state
		reasons := []string(nil)
		if isTruncationResolutionState(state) {
			reasons = append(reasons, state)
			truncation[key] = append(truncation[key], reasons...)
		}
		receipts = append(receipts, resolutionReceipt{kind: kind, caller: caller, callee: callee, state: state, reasons: reasons, ref: "execution_resolution:" + strings.TrimSpace(item.Value)})
	}

	relationships := make([]model.ExecutionRelationship, 0)
	for _, item := range evidence {
		if item.Key != "execution_relationship" {
			continue
		}
		parts := strings.Split(strings.TrimSpace(item.Value), "|")
		if len(parts) < 4 {
			continue
		}
		kind := strings.TrimSpace(parts[0])
		caller := strings.TrimSpace(parts[1])
		callee := strings.TrimSpace(parts[2])
		state := strings.TrimSpace(parts[3])
		key := strings.Join([]string{kind, caller, callee}, "|")
		if override := stateOverrides[key]; override != "" {
			state = override
		}
		origin := "source_declared"
		if state == "resolved_declared" {
			origin = "customer_topology"
		}
		confidence := relationshipConfidence(state)
		evidenceRefs := []string{"execution_relationship:" + strings.TrimSpace(item.Value)}
		if len(parts) > 4 && strings.TrimSpace(parts[4]) != "" {
			evidenceRefs = append(evidenceRefs, strings.TrimSpace(parts[4]))
		}
		relationships = append(relationships, model.ExecutionRelationship{
			RelationshipID:    relationshipID(kind, caller, callee, state),
			Kind:              kind,
			Caller:            caller,
			Callee:            callee,
			Origin:            origin,
			ResolutionState:   state,
			Confidence:        confidence,
			EvidenceRefs:      evidenceRefs,
			TruncationReasons: append([]string(nil), truncation[key]...),
		})
	}
	for _, receipt := range receipts {
		key := strings.Join([]string{receipt.kind, receipt.caller, receipt.callee}, "|")
		if relationshipSliceContains(relationships, key, receipt.state) {
			continue
		}
		relationships = append(relationships, model.ExecutionRelationship{
			RelationshipID:    relationshipID(receipt.kind, receipt.caller, receipt.callee, receipt.state),
			Kind:              receipt.kind,
			Caller:            receipt.caller,
			Callee:            receipt.callee,
			Origin:            "resolver_receipt",
			ResolutionState:   receipt.state,
			Confidence:        relationshipConfidence(receipt.state),
			EvidenceRefs:      []string{receipt.ref},
			TruncationReasons: append([]string(nil), receipt.reasons...),
		})
	}
	return model.NormalizeExecutionRelationships(relationships)
}

func relationshipSliceContains(items []model.ExecutionRelationship, key, state string) bool {
	for _, item := range items {
		if strings.Join([]string{item.Kind, item.Caller, item.Callee}, "|") == key && item.ResolutionState == state {
			return true
		}
	}
	return false
}

func relationshipID(kind, caller, callee, state string) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{strings.TrimSpace(kind), strings.TrimSpace(caller), strings.TrimSpace(callee), strings.TrimSpace(state)}, "\x00")))
	return "xrel-" + hex.EncodeToString(digest[:8])
}

func relationshipConfidence(state string) string {
	switch strings.TrimSpace(state) {
	case "resolved_local":
		return "high"
	case "resolved_declared":
		return "medium"
	default:
		return "low"
	}
}

func isTruncationResolutionState(state string) bool {
	switch strings.TrimSpace(state) {
	case "cycle_blocked", "depth_limited", "fanout_limited":
		return true
	default:
		return false
	}
}

func cloneExecutionRelationships(in []model.ExecutionRelationship) []model.ExecutionRelationship {
	out := model.NormalizeExecutionRelationships(in)
	for index := range out {
		out[index].EvidenceRefs = append([]string(nil), out[index].EvidenceRefs...)
		out[index].TruncationReasons = append([]string(nil), out[index].TruncationReasons...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RelationshipID < out[j].RelationshipID })
	return out
}
