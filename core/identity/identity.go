package identity

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	StateDiscovered  = "discovered"
	StateUnderReview = "under_review"
	StateApproved    = "approved"
	StateActive      = "active"
	StateDeprecated  = "deprecated"
	StateRevoked     = "revoked"
)

var validStates = map[string]struct{}{
	StateDiscovered:  {},
	StateUnderReview: {},
	StateApproved:    {},
	StateActive:      {},
	StateDeprecated:  {},
	StateRevoked:     {},
}

// ToolID deterministically derives a canonical tool identity component.
func ToolID(toolType, location string) string {
	key := strings.ToLower(strings.TrimSpace(toolType)) + "::" + strings.ToLower(strings.TrimSpace(location))
	digest := sha1.Sum([]byte(key))
	return fmt.Sprintf("%s-%s", sanitize(strings.TrimSpace(toolType)), hex.EncodeToString(digest[:])[:10])
}

// AgentID deterministically derives the canonical agent identifier.
func AgentID(toolID, org string) string {
	trimmedTool := strings.TrimSpace(toolID)
	trimmedOrg := strings.TrimSpace(org)
	if trimmedOrg == "" {
		trimmedOrg = "local"
	}
	return fmt.Sprintf("wrkr:%s:%s", trimmedTool, trimmedOrg)
}

func IsValidState(state string) bool {
	_, ok := validStates[strings.TrimSpace(state)]
	return ok
}

func sanitize(in string) string {
	trimmed := strings.ToLower(strings.TrimSpace(in))
	if trimmed == "" {
		return "tool"
	}
	builder := strings.Builder{}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	out := strings.Trim(builder.String(), "-")
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	if out == "" {
		return "tool"
	}
	return out
}
