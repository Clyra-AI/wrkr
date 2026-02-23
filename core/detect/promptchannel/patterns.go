package promptchannel

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type signal struct {
	FindingType    string
	ReasonCode     string
	PatternFamily  string
	Confidence     string
	Severity       string
	LocationClass  string
	Snippets       []string
	Remediation    string
	RuleDescriptor string
}

var overrideMatchers = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bignore\s+(the\s+)?(previous|prior|system|policy|safety)\s+instructions?\b`),
	regexp.MustCompile(`(?i)\bdisregard\s+(the\s+)?(previous|system|policy)\s+instructions?\b`),
	regexp.MustCompile(`(?i)\boverride\s+(the\s+)?(system|policy|safety|guardrail)\b`),
	regexp.MustCompile(`(?i)\bdo\s+not\s+follow\s+(the\s+)?(system|policy|safety|previous)\s+instructions?\b`),
}

func hiddenTextSnippets(raw string) []string {
	runes := []rune(raw)
	out := make([]string, 0)
	for i, r := range runes {
		if !isHiddenRune(r) {
			continue
		}
		start := i - 12
		if start < 0 {
			start = 0
		}
		end := i + 13
		if end > len(runes) {
			end = len(runes)
		}
		snippet := strings.TrimSpace(string(runes[start:end]))
		if snippet == "" {
			continue
		}
		out = append(out, snippet)
	}
	return normalizeSnippets(out)
}

func overrideSnippets(segments []string) []string {
	out := make([]string, 0)
	for _, segment := range segments {
		trimmed := strings.TrimSpace(segment)
		if trimmed == "" {
			continue
		}
		for _, matcher := range overrideMatchers {
			if matcher.MatchString(trimmed) {
				out = append(out, excerpt(trimmed, 140))
				break
			}
		}
	}
	return normalizeSnippets(out)
}

func untrustedInjectionSnippets(segments []string) []string {
	out := make([]string, 0)
	for _, segment := range segments {
		normalized := strings.ToLower(strings.TrimSpace(segment))
		if normalized == "" {
			continue
		}
		if !hasAny(normalized, []string{"system prompt", "system_prompt", "assistant_prompt", "instruction prompt", "prompt_template"}) {
			continue
		}
		if !hasAny(normalized, []string{"user_input", "user input", "issue.body", "pull_request.body", "comment", "external", "untrusted", "stdin", "markdown"}) {
			continue
		}
		if !hasAny(normalized, []string{"append", "concat", "merge", "template", "format", "{{", "${", ">>", "join", "cat "}) {
			continue
		}
		out = append(out, excerpt(segment, 160))
	}
	return normalizeSnippets(out)
}

func isPromptSurface(rel string) bool {
	normalized := strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel)))
	if normalized == "" {
		return false
	}
	base := filepath.Base(normalized)

	switch base {
	case "agents.md", "agents.override.md", "claude.md", ".cursorrules", "jenkinsfile", "skill.md":
		return true
	}
	if strings.HasPrefix(normalized, ".github/workflows/") {
		return true
	}
	if strings.Contains(normalized, "/skills/") && strings.HasSuffix(base, ".md") {
		return true
	}
	if strings.HasPrefix(normalized, ".agents/") || strings.HasPrefix(normalized, ".claude/") || strings.HasPrefix(normalized, ".cursor/") || strings.HasPrefix(normalized, ".codex/") {
		return hasTextLikeExtension(normalized)
	}
	if strings.Contains(normalized, "prompt") || strings.Contains(normalized, "instruction") {
		return hasTextLikeExtension(normalized)
	}
	return false
}

func classifyLocation(rel string) string {
	normalized := strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel)))
	base := filepath.Base(normalized)
	switch {
	case strings.HasPrefix(normalized, ".github/workflows/") || base == "jenkinsfile":
		return "workflow"
	case strings.Contains(normalized, "/skills/") || base == "skill.md":
		return "skill"
	case base == "agents.md" || base == "agents.override.md" || base == "claude.md":
		return "instruction_doc"
	case strings.HasSuffix(normalized, ".json") || strings.HasSuffix(normalized, ".yaml") || strings.HasSuffix(normalized, ".yml") || strings.HasSuffix(normalized, ".toml"):
		return "config"
	case strings.HasSuffix(normalized, ".sh"):
		return "script"
	default:
		return "text"
	}
}

func hasTextLikeExtension(rel string) bool {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh", ".py", ".js", ".ts":
		return true
	default:
		return false
	}
}

func isHiddenRune(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x202A, 0x202B, 0x202D, 0x202E, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069:
		return true
	default:
		return false
	}
}

func hasAny(value string, tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func excerpt(value string, limit int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if limit <= 0 {
		return trimmed
	}
	if utf8.RuneCountInString(trimmed) <= limit {
		return trimmed
	}
	runes := []rune(trimmed)
	return strings.TrimSpace(string(runes[:limit]))
}

func normalizeSnippets(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
