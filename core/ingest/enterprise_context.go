package ingest

import (
	"fmt"
	"strings"
)

const (
	StateRetentionUnknown            = "unknown"
	StateRetentionEphemeral          = "ephemeral"
	StateRetentionRetained           = "retained"
	StateRetentionRetainedWithExpiry = "retained_with_expiry"
	StateRetentionOperatorManaged    = "operator_managed"
)

func normalizeRuntimeContextValue(value string) string {
	return strings.TrimSpace(value)
}

func normalizeStateRetentionStatus(value string) string {
	switch strings.TrimSpace(value) {
	case StateRetentionUnknown,
		StateRetentionEphemeral,
		StateRetentionRetained,
		StateRetentionRetainedWithExpiry,
		StateRetentionOperatorManaged:
		return strings.TrimSpace(value)
	default:
		return ""
	}
}

func normalizeRetainedStateTypes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		switch strings.TrimSpace(value) {
		case "prompt_digest",
			"response_digest",
			"tool_result_digest",
			"log_digest",
			"checkpoint_digest",
			"memory_digest",
			"sandbox_manifest":
			normalized = append(normalized, strings.TrimSpace(value))
		}
	}
	return mergeStrings(normalized...)
}

func normalizeStateLocationRefs(values []string) []string {
	return mergeStrings(values...)
}

func normalizeStateDigestRefs(values []string) []string {
	return mergeStrings(values...)
}

func validateEnterpriseContext(recordLabel string, retentionStatus string, retainedStateTypes []string, stateLocationRefs []string, stateDigestRefs []string) error {
	if strings.TrimSpace(retentionStatus) == "" && len(retainedStateTypes) == 0 && len(stateLocationRefs) == 0 && len(stateDigestRefs) == 0 {
		return nil
	}
	if strings.TrimSpace(retentionStatus) == "" {
		retentionStatus = StateRetentionUnknown
	}
	for _, value := range retainedStateTypes {
		if !isAllowedRetainedStateType(value) {
			return fmt.Errorf("%s contains unsupported retained_state_type %q", recordLabel, strings.TrimSpace(value))
		}
	}
	for _, value := range stateLocationRefs {
		if looksSecretLike(value) || looksRawStateContent(value) {
			return fmt.Errorf("%s contains raw retained state reference content", recordLabel)
		}
	}
	for _, value := range stateDigestRefs {
		if !looksDigestRef(value) {
			return fmt.Errorf("%s contains invalid state digest ref %q", recordLabel, strings.TrimSpace(value))
		}
	}
	return nil
}

func isAllowedRetainedStateType(value string) bool {
	switch strings.TrimSpace(value) {
	case "prompt_digest",
		"response_digest",
		"tool_result_digest",
		"log_digest",
		"checkpoint_digest",
		"memory_digest",
		"sandbox_manifest":
		return true
	default:
		return false
	}
}

func looksDigestRef(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	return strings.HasPrefix(trimmed, "sha256:") || strings.HasPrefix(trimmed, "sha512:")
}

func looksRawStateContent(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(trimmed, "\n") {
		return true
	}
	for _, needle := range []string{
		"prompt contents",
		"response contents",
		"tool result",
		"memory contents",
		"checkpoint contents",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
