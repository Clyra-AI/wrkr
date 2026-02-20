package supplychain

import "strings"

// MCPInput carries deterministic offline trust signals.
type MCPInput struct {
	Transport      string
	Pinned         bool
	HasLockfile    bool
	CredentialRefs int
}

// ScoreMCP computes a deterministic 0-10 trust score from offline signals.
func ScoreMCP(in MCPInput) float64 {
	score := 10.0
	if !in.Pinned {
		score -= 5
	}
	if !in.HasLockfile {
		score -= 2
	}
	switch strings.ToLower(strings.TrimSpace(in.Transport)) {
	case "http", "https", "sse", "streamable_http":
		score -= 2
	}
	if in.CredentialRefs > 0 {
		score -= 1
	}
	if score < 0 {
		return 0
	}
	return score
}

func SeverityFromTrust(score float64) string {
	switch {
	case score <= 2:
		return "critical"
	case score <= 4:
		return "high"
	case score <= 6:
		return "medium"
	default:
		return "low"
	}
}
