package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

type enterpriseContextProjection struct {
	RuntimeContextEvidenceState string
	RuntimeProvider             string
	RuntimeHost                 string
	RuntimeKind                 string
	ModelProvider               string
	ModelVersion                string
	ExecutionEnvironment        string
	StateRetentionEvidenceState string
	StateRetentionStatus        string
	RetainedStateTypes          []string
	StateLocationRefs           []string
	StateDigestRefs             []string
}

func decorateActionPathsForEnterpriseContext(paths []risk.ActionPath, sessions *ingest.SessionSummary, packets *ingest.EvidencePacketSummary) []risk.ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]risk.ActionPath(nil), paths...)
	byPath := enterpriseContextByPath(sessions, packets)
	for i := range out {
		projected, ok := byPath[strings.TrimSpace(out[i].PathID)]
		if !ok {
			continue
		}
		out[i].RuntimeContextEvidenceState = strings.TrimSpace(projected.RuntimeContextEvidenceState)
		out[i].RuntimeProvider = strings.TrimSpace(projected.RuntimeProvider)
		out[i].RuntimeHost = strings.TrimSpace(projected.RuntimeHost)
		out[i].RuntimeKind = strings.TrimSpace(projected.RuntimeKind)
		out[i].ModelProvider = strings.TrimSpace(projected.ModelProvider)
		out[i].ModelVersion = strings.TrimSpace(projected.ModelVersion)
		out[i].ExecutionEnvironment = strings.TrimSpace(projected.ExecutionEnvironment)
		out[i].StateRetentionEvidenceState = strings.TrimSpace(projected.StateRetentionEvidenceState)
		out[i].StateRetentionStatus = strings.TrimSpace(projected.StateRetentionStatus)
		out[i].RetainedStateTypes = uniqueSortedStrings(append([]string(nil), projected.RetainedStateTypes...))
		out[i].StateLocationRefs = uniqueSortedStrings(append([]string(nil), projected.StateLocationRefs...))
		out[i].StateDigestRefs = uniqueSortedStrings(append([]string(nil), projected.StateDigestRefs...))
	}
	return risk.ProjectActionPaths(out)
}

func enterpriseContextByPath(sessions *ingest.SessionSummary, packets *ingest.EvidencePacketSummary) map[string]enterpriseContextProjection {
	out := map[string]enterpriseContextProjection{}
	if sessions != nil {
		for _, item := range sessions.Correlations {
			pathID := strings.TrimSpace(item.PathID)
			if pathID == "" {
				continue
			}
			out[pathID] = mergeEnterpriseContextProjection(out[pathID], enterpriseContextProjection{
				RuntimeProvider:      strings.TrimSpace(item.RuntimeProvider),
				RuntimeHost:          strings.TrimSpace(item.RuntimeHost),
				RuntimeKind:          strings.TrimSpace(item.RuntimeKind),
				ModelProvider:        strings.TrimSpace(item.ModelProvider),
				ModelVersion:         strings.TrimSpace(item.ModelVersion),
				ExecutionEnvironment: strings.TrimSpace(item.ExecutionEnvironment),
				StateRetentionStatus: strings.TrimSpace(item.StateRetentionStatus),
				RetainedStateTypes:   append([]string(nil), item.RetainedStateTypes...),
				StateLocationRefs:    append([]string(nil), item.StateLocationRefs...),
				StateDigestRefs:      append([]string(nil), item.StateDigestRefs...),
			})
		}
	}
	if packets != nil {
		for _, item := range packets.Correlations {
			pathID := strings.TrimSpace(item.PathID)
			if pathID == "" {
				continue
			}
			out[pathID] = mergeEnterpriseContextProjection(out[pathID], enterpriseContextProjection{
				RuntimeProvider:      strings.TrimSpace(item.RuntimeProvider),
				RuntimeHost:          strings.TrimSpace(item.RuntimeHost),
				RuntimeKind:          strings.TrimSpace(item.RuntimeKind),
				ModelProvider:        strings.TrimSpace(item.ModelProvider),
				ModelVersion:         strings.TrimSpace(item.ModelVersion),
				ExecutionEnvironment: strings.TrimSpace(item.ExecutionEnvironment),
				StateRetentionStatus: strings.TrimSpace(item.StateRetentionStatus),
				RetainedStateTypes:   append([]string(nil), item.RetainedStateTypes...),
				StateLocationRefs:    append([]string(nil), item.StateLocationRefs...),
				StateDigestRefs:      append([]string(nil), item.StateDigestRefs...),
			})
		}
	}
	for key, item := range out {
		item.RuntimeContextEvidenceState = runtimeContextState(item)
		item.StateRetentionEvidenceState = retentionContextState(item)
		out[key] = item
	}
	return out
}

func mergeEnterpriseContextProjection(current, incoming enterpriseContextProjection) enterpriseContextProjection {
	merged := current
	merged.RuntimeProvider, merged.RuntimeContextEvidenceState = mergeEnterpriseScalar(current.RuntimeProvider, current.RuntimeContextEvidenceState, incoming.RuntimeProvider)
	merged.RuntimeHost, merged.RuntimeContextEvidenceState = mergeEnterpriseScalar(current.RuntimeHost, merged.RuntimeContextEvidenceState, incoming.RuntimeHost)
	merged.RuntimeKind, merged.RuntimeContextEvidenceState = mergeEnterpriseScalar(current.RuntimeKind, merged.RuntimeContextEvidenceState, incoming.RuntimeKind)
	merged.ModelProvider, merged.RuntimeContextEvidenceState = mergeEnterpriseScalar(current.ModelProvider, merged.RuntimeContextEvidenceState, incoming.ModelProvider)
	merged.ModelVersion, merged.RuntimeContextEvidenceState = mergeEnterpriseScalar(current.ModelVersion, merged.RuntimeContextEvidenceState, incoming.ModelVersion)
	merged.ExecutionEnvironment, merged.RuntimeContextEvidenceState = mergeEnterpriseScalar(current.ExecutionEnvironment, merged.RuntimeContextEvidenceState, incoming.ExecutionEnvironment)
	merged.StateRetentionStatus, merged.StateRetentionEvidenceState = mergeEnterpriseScalar(current.StateRetentionStatus, current.StateRetentionEvidenceState, incoming.StateRetentionStatus)
	merged.RetainedStateTypes = uniqueSortedStrings(append(append([]string(nil), current.RetainedStateTypes...), incoming.RetainedStateTypes...))
	merged.StateLocationRefs = uniqueSortedStrings(append(append([]string(nil), current.StateLocationRefs...), incoming.StateLocationRefs...))
	merged.StateDigestRefs = uniqueSortedStrings(append(append([]string(nil), current.StateDigestRefs...), incoming.StateDigestRefs...))
	return merged
}

func mergeEnterpriseScalar(current, state, incoming string) (string, string) {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	state = strings.TrimSpace(state)
	switch {
	case state == risk.EvidenceStateContradictory:
		return "", risk.EvidenceStateContradictory
	case incoming == "":
		return current, state
	case current == "":
		return incoming, firstNonEmptyValue(state, risk.EvidenceStateVerified)
	case current == incoming:
		return current, firstNonEmptyValue(state, risk.EvidenceStateVerified)
	default:
		return "", risk.EvidenceStateContradictory
	}
}

func runtimeContextState(in enterpriseContextProjection) string {
	if strings.TrimSpace(in.RuntimeContextEvidenceState) == risk.EvidenceStateContradictory {
		return risk.EvidenceStateContradictory
	}
	for _, value := range []string{
		in.RuntimeProvider,
		in.RuntimeHost,
		in.RuntimeKind,
		in.ModelProvider,
		in.ModelVersion,
		in.ExecutionEnvironment,
	} {
		if strings.TrimSpace(value) != "" {
			return risk.EvidenceStateVerified
		}
	}
	return risk.EvidenceStateUnknown
}

func retentionContextState(in enterpriseContextProjection) string {
	if strings.TrimSpace(in.StateRetentionEvidenceState) == risk.EvidenceStateContradictory {
		return risk.EvidenceStateContradictory
	}
	status := strings.TrimSpace(in.StateRetentionStatus)
	if len(in.RetainedStateTypes) > 0 || len(in.StateLocationRefs) > 0 || len(in.StateDigestRefs) > 0 {
		return risk.EvidenceStateVerified
	}
	switch status {
	case "", "unknown":
		return risk.EvidenceStateUnknown
	}
	if status != "" {
		return risk.EvidenceStateVerified
	}
	return risk.EvidenceStateUnknown
}
