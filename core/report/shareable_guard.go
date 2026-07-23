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

type shareableRedactionEntry struct {
	Token       shareableSensitiveToken
	Replacement string
}

type shareableRedactionPlan struct {
	Entries []shareableRedactionEntry
	Tokens  []shareableSensitiveToken
}

func ApplyShareableResidualRedaction(snapshot state.Snapshot, summary Summary) (Summary, error) {
	profile, ok := ParseShareProfile(summary.ShareProfile)
	if !ok || !shareProfileRequiresRedaction(profile) {
		return summary, nil
	}
	plan, err := buildShareableRedactionPlan(snapshot)
	if err != nil {
		return Summary{}, err
	}
	if len(plan.Entries) == 0 {
		return summary, nil
	}
	replacer := newShareableTokenReplacer(plan.Entries)
	var sourceHighlights []WorkflowHighlight
	if summary.WorkflowHighlights != nil && len(summary.WorkflowHighlights.sourceHighlights) > 0 {
		sourceHighlights = append([]WorkflowHighlight(nil), summary.WorkflowHighlights.sourceHighlights...)
	}
	var focusSourceItems []AgentActionBOMItem
	if summary.AgentActionBOM != nil && len(summary.AgentActionBOM.focusSourceItems) > 0 {
		focusSourceItems = append([]AgentActionBOMItem(nil), summary.AgentActionBOM.focusSourceItems...)
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return Summary{}, fmt.Errorf("marshal shareable summary for residual redaction: %w", err)
	}
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Summary{}, fmt.Errorf("unmarshal shareable summary for residual redaction: %w", err)
	}
	raw = applyShareableTokenRedaction(raw, replacer)
	redactedPayload, err := json.Marshal(raw)
	if err != nil {
		return Summary{}, fmt.Errorf("marshal shareable summary after residual redaction: %w", err)
	}
	var out Summary
	if err := json.Unmarshal(redactedPayload, &out); err != nil {
		return Summary{}, fmt.Errorf("unmarshal shareable summary after residual redaction: %w", err)
	}
	if len(sourceHighlights) > 0 && out.WorkflowHighlights != nil {
		redacted, err := applyShareableResidualRedactionValue("workflow highlight source", sourceHighlights, replacer)
		if err != nil {
			return Summary{}, err
		}
		out.WorkflowHighlights.sourceHighlights = redacted
	}
	if len(focusSourceItems) > 0 && out.AgentActionBOM != nil {
		redacted, err := applyShareableResidualRedactionValue("agent action bom source items", focusSourceItems, replacer)
		if err != nil {
			return Summary{}, err
		}
		out.AgentActionBOM.focusSourceItems = redacted
	}
	return out, nil
}

func applyShareableResidualRedactionValue[T any](label string, value T, replacer *strings.Replacer) (T, error) {
	var zero T
	payload, err := json.Marshal(value)
	if err != nil {
		return zero, fmt.Errorf("marshal %s for residual redaction: %w", label, err)
	}
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return zero, fmt.Errorf("unmarshal %s for residual redaction: %w", label, err)
	}
	raw = applyShareableTokenRedaction(raw, replacer)
	redactedPayload, err := json.Marshal(raw)
	if err != nil {
		return zero, fmt.Errorf("marshal %s after residual redaction: %w", label, err)
	}
	var out T
	if err := json.Unmarshal(redactedPayload, &out); err != nil {
		return zero, fmt.Errorf("unmarshal %s after residual redaction: %w", label, err)
	}
	return out, nil
}

func ValidateShareableArtifacts(snapshot state.Snapshot, summary Summary, markdown string, includeEvidenceBundle bool) error {
	profile, ok := ParseShareProfile(summary.ShareProfile)
	if !ok || !shareProfileRequiresRedaction(profile) {
		return nil
	}
	plan, err := buildShareableRedactionPlan(snapshot)
	if err != nil {
		return err
	}
	if len(plan.Tokens) == 0 {
		return nil
	}
	replacer := newShareableTokenReplacer(plan.Entries)
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
		var violation shareableSensitiveToken
		var found bool
		if strings.HasSuffix(output.label, "json") {
			violation, found = findResidualSensitiveJSONValue(output.content, plan.Tokens, replacer)
		} else {
			violation, found = findResidualSensitiveToken(output.content, plan.Tokens, replacer)
		}
		if found {
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

func buildShareableRedactionPlan(snapshot state.Snapshot) (shareableRedactionPlan, error) {
	tokens, err := collectShareableSensitiveTokens(snapshot)
	if err != nil {
		return shareableRedactionPlan{}, err
	}
	entries := make([]shareableRedactionEntry, 0, len(tokens))
	for _, token := range tokens {
		if strings.TrimSpace(token.Value) == "" {
			continue
		}
		entries = append(entries, shareableRedactionEntry{
			Token:       token,
			Replacement: shareableTokenReplacement(token),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].Token.Value) == len(entries[j].Token.Value) {
			if entries[i].Token.Category == entries[j].Token.Category {
				return entries[i].Token.Value < entries[j].Token.Value
			}
			return entries[i].Token.Category < entries[j].Token.Category
		}
		return len(entries[i].Token.Value) > len(entries[j].Token.Value)
	})
	return shareableRedactionPlan{
		Entries: entries,
		Tokens:  tokens,
	}, nil
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
		if isGenericCredentialSubject(trimmed) {
			return "", false
		}
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

func isGenericCredentialSubject(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "path", "artifact-path", "artifact_path", "cache-dependency-path", "cache_dependency_path", "pattern", "persist-credentials", "persist_credentials", "restore-keys", "restore_keys", "source", "source_code", "plain_source_code", "unknown", "unset", "none", "n/a":
		return true
	default:
		return false
	}
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
	if isDigitsOnly(trimmed) {
		return false
	}
	return strings.Contains(trimmed, "/") ||
		strings.Contains(trimmed, "-") ||
		strings.Contains(trimmed, "_") ||
		strings.ContainsAny(trimmed, "0123456789")
}

func isDigitsOnly(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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

func findResidualSensitiveToken(content string, tokens []shareableSensitiveToken, replacer *strings.Replacer) (shareableSensitiveToken, bool) {
	if replacer == nil || replacer.Replace(content) == content {
		return shareableSensitiveToken{}, false
	}
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

func findResidualSensitiveJSONValue(content string, tokens []shareableSensitiveToken, replacer *strings.Replacer) (shareableSensitiveToken, bool) {
	var raw any
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return findResidualSensitiveToken(content, tokens, replacer)
	}
	return findResidualSensitiveValue(raw, tokens, replacer)
}

func findResidualSensitiveValue(value any, tokens []shareableSensitiveToken, replacer *strings.Replacer) (shareableSensitiveToken, bool) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if token, ok := findResidualSensitiveValue(typed[key], tokens, replacer); ok {
				return token, true
			}
		}
	case []any:
		for _, nested := range typed {
			if token, ok := findResidualSensitiveValue(nested, tokens, replacer); ok {
				return token, true
			}
		}
	case string:
		return findResidualSensitiveToken(typed, tokens, replacer)
	}
	return shareableSensitiveToken{}, false
}

func newShareableTokenReplacer(entries []shareableRedactionEntry) *strings.Replacer {
	pairs := make([]string, 0, len(entries)*2)
	for _, entry := range entries {
		if entry.Token.Value == "" {
			continue
		}
		pairs = append(pairs, entry.Token.Value, entry.Replacement)
	}
	return strings.NewReplacer(pairs...)
}

func applyShareableTokenRedaction(value any, replacer *strings.Replacer) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, nested := range typed {
			out[key] = applyShareableTokenRedaction(nested, replacer)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, nested := range typed {
			out = append(out, applyShareableTokenRedaction(nested, replacer))
		}
		return out
	case string:
		return replacer.Replace(typed)
	default:
		return value
	}
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
