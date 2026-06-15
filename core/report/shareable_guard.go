package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/state"
)

type shareableSafetyError struct {
	label    string
	category string
}

func (e *shareableSafetyError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("shareable output failed residual redaction validation for %s token in %s", e.category, e.label)
}

func IsShareableSafetyError(err error) bool {
	var target *shareableSafetyError
	return errors.As(err, &target)
}

type shareableSensitiveToken struct {
	Category string
	Value    string
}

func ApplyShareableResidualRedaction(snapshot state.Snapshot, summary Summary) (Summary, error) {
	profile, ok := ParseShareProfile(summary.ShareProfile)
	if !ok || !shareProfileRequiresRedaction(profile) {
		return summary, nil
	}
	tokens, err := collectShareableSensitiveTokens(snapshot)
	if err != nil {
		return Summary{}, err
	}
	if len(tokens) == 0 {
		return summary, nil
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return Summary{}, fmt.Errorf("marshal shareable summary for residual redaction: %w", err)
	}
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Summary{}, fmt.Errorf("unmarshal shareable summary for residual redaction: %w", err)
	}
	raw = applyShareableTokenRedaction(raw, tokens)
	redactedPayload, err := json.Marshal(raw)
	if err != nil {
		return Summary{}, fmt.Errorf("marshal shareable summary after residual redaction: %w", err)
	}
	var out Summary
	if err := json.Unmarshal(redactedPayload, &out); err != nil {
		return Summary{}, fmt.Errorf("unmarshal shareable summary after residual redaction: %w", err)
	}
	return out, nil
}

func ValidateShareableArtifacts(snapshot state.Snapshot, summary Summary, markdown string, includeEvidenceBundle bool) error {
	profile, ok := ParseShareProfile(summary.ShareProfile)
	if !ok || !shareProfileRequiresRedaction(profile) {
		return nil
	}
	tokens, err := collectShareableSensitiveTokens(snapshot)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return nil
	}
	outputs := []struct {
		label   string
		content string
	}{
		{
			label:   "report summary json",
			content: mustMarshalArtifactJSON(summary),
		},
	}
	if strings.TrimSpace(markdown) != "" {
		outputs = append(outputs, struct {
			label   string
			content string
		}{
			label:   "report markdown",
			content: markdown,
		})
	}
	if includeEvidenceBundle {
		outputs = append(outputs, struct {
			label   string
			content string
		}{
			label:   "evidence bundle json",
			content: mustMarshalArtifactJSON(BuildEvidenceBundle(summary)),
		})
	}
	for _, output := range outputs {
		if violation, ok := findResidualSensitiveToken(output.content, tokens); ok {
			return &shareableSafetyError{label: output.label, category: violation.Category}
		}
	}
	return nil
}

func mustMarshalArtifactJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(payload)
}

func collectShareableSensitiveTokens(snapshot state.Snapshot) ([]shareableSensitiveToken, error) {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot for shareable validation: %w", err)
	}
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot for shareable validation: %w", err)
	}
	deduped := map[string]shareableSensitiveToken{}
	walkShareableSensitiveTokens(raw, nil, deduped)
	out := make([]shareableSensitiveToken, 0, len(deduped))
	for _, token := range deduped {
		out = append(out, token)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category == out[j].Category {
			return out[i].Value < out[j].Value
		}
		return out[i].Category < out[j].Category
	})
	return out, nil
}

func walkShareableSensitiveTokens(value any, path []string, deduped map[string]shareableSensitiveToken) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			walkShareableSensitiveTokens(nested, append(path, key), deduped)
		}
	case []any:
		for _, nested := range typed {
			walkShareableSensitiveTokens(nested, path, deduped)
		}
	case string:
		category, ok := classifyShareableSensitiveToken(path, typed)
		if !ok {
			return
		}
		token := shareableSensitiveToken{
			Category: category,
			Value:    strings.TrimSpace(typed),
		}
		deduped[token.Category+"\x00"+token.Value] = token
	}
}

func classifyShareableSensitiveToken(path []string, value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) < 4 || looksLikeShareableRedactionValue(trimmed) {
		return "", false
	}
	key := ""
	if len(path) > 0 {
		key = strings.ToLower(path[len(path)-1])
	}
	switch {
	case looksLikeFilesystemPath(trimmed):
		return "filesystem", true
	case looksLikeReviewURL(trimmed):
		return "review_url", true
	case keyContainsAny(key, "owner", "issuer", "reviewer", "author"):
		if keyContainsAny(key, "status", "state", "source", "reason") {
			return "", false
		}
		if looksLikeOwnerValue(trimmed) {
			return "owner", true
		}
		return "", false
	case keyContainsAny(key, "repo", "organization", "org"):
		if looksLikeRepoValue(trimmed) {
			return "repo", true
		}
		return "", false
	case keyContainsAny(key, "subject"):
		return "credential_subject", true
	case keyContainsAny(key, "provider", "model", "host"):
		if strings.Contains(trimmed, "://") || strings.Contains(trimmed, ".") || strings.Contains(trimmed, "/") {
			return "provider", true
		}
		return "", false
	case keyContainsAny(key, "path", "location", "source"):
		if strings.Contains(trimmed, "/") || strings.Contains(trimmed, "\\") || strings.Contains(trimmed, ".") {
			return "path", true
		}
	case strings.HasPrefix(trimmed, "@"):
		return "owner", true
	case strings.Contains(trimmed, "-bot"):
		return "owner", true
	}
	return "", false
}

func looksLikeShareableRedactionValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{
		"owner-",
		"repo-",
		"org-",
		"loc-",
		"path-",
		"fs-",
		"provider-",
		"credential-",
		"finding-",
		"attack-",
		"evidence-",
		"binding-",
		"packet-",
		"proof-",
		"digest-",
	} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

func looksLikeReviewURL(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	return strings.Contains(trimmed, "/pull/") || strings.Contains(trimmed, "/pulls/") || strings.Contains(trimmed, "/merge_requests/")
}

func looksLikeOwnerValue(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	switch trimmed {
	case "", "unknown", "inferred", "declared", "verified", "none", "unset", "n/a":
		return false
	}
	return strings.HasPrefix(trimmed, "@") || strings.Contains(trimmed, "/") || strings.Contains(trimmed, "-bot")
}

func looksLikeRepoValue(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	switch trimmed {
	case "", "repo", "org", "organization", "multi", "path", "public-surface", "local":
		return false
	}
	return strings.Contains(trimmed, "/") ||
		strings.Contains(trimmed, "-") ||
		strings.Contains(trimmed, "_") ||
		strings.ContainsAny(trimmed, "0123456789")
}

func keyContainsAny(key string, parts ...string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	for _, part := range parts {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func findResidualSensitiveToken(content string, tokens []shareableSensitiveToken) (shareableSensitiveToken, bool) {
	for _, token := range tokens {
		if token.Value == "" {
			continue
		}
		if strings.Contains(content, token.Value) {
			return token, true
		}
	}
	return shareableSensitiveToken{}, false
}

func applyShareableTokenRedaction(value any, tokens []shareableSensitiveToken) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[key] = applyShareableTokenRedaction(nested, tokens)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, nested := range typed {
			out = append(out, applyShareableTokenRedaction(nested, tokens))
		}
		return out
	case string:
		return redactShareableTokenString(typed, tokens)
	default:
		return value
	}
}

func redactShareableTokenString(value string, tokens []shareableSensitiveToken) string {
	out := value
	ordered := append([]shareableSensitiveToken(nil), tokens...)
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].Value) == len(ordered[j].Value) {
			if ordered[i].Category == ordered[j].Category {
				return ordered[i].Value < ordered[j].Value
			}
			return ordered[i].Category < ordered[j].Category
		}
		return len(ordered[i].Value) > len(ordered[j].Value)
	})
	for _, token := range ordered {
		if token.Value == "" {
			continue
		}
		out = strings.ReplaceAll(out, token.Value, shareableTokenReplacement(token))
	}
	return out
}

func shareableTokenReplacement(token shareableSensitiveToken) string {
	switch token.Category {
	case "owner":
		return redactValue("owner", token.Value, 8)
	case "repo":
		return redactValue("repo", token.Value, 6)
	case "credential_subject":
		return redactValue("credential", token.Value, 8)
	case "filesystem":
		return redactValue("fs", token.Value, 8)
	case "path":
		return redactValue("loc", token.Value, 8)
	default:
		return redactValue("provider", token.Value, 8)
	}
}
