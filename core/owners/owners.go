package owners

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type rule struct {
	pattern string
	owner   string
}

// ResolveOwner derives ownership from CODEOWNERS with deterministic fallback.
func ResolveOwner(root, repo, org, location string) string {
	rules := loadCodeowners(root)
	normalized := normalizePath(location)
	owner := ""
	for _, item := range rules {
		if matchPattern(item.pattern, normalized) {
			owner = item.owner
		}
	}
	if owner != "" {
		return owner
	}
	return fallbackOwner(repo, org)
}

func loadCodeowners(root string) []rule {
	paths := []string{"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}
	for _, rel := range paths {
		path := filepath.Join(root, filepath.FromSlash(rel))
		payload, err := os.ReadFile(path) // #nosec G304 -- path is derived from known CODEOWNERS locations under the selected local root.
		if err != nil {
			continue
		}
		rules := parseRules(string(payload))
		if len(rules) > 0 {
			return rules
		}
	}
	return nil
}

func parseRules(content string) []rule {
	scanner := bufio.NewScanner(strings.NewReader(content))
	out := make([]rule, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		out = append(out, rule{pattern: normalizePath(parts[0]), owner: strings.TrimSpace(parts[1])})
	}
	return out
}

func matchPattern(pattern, path string) bool {
	pattern = strings.TrimPrefix(pattern, "/")
	path = strings.TrimPrefix(path, "/")
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "/"))
	}
	if strings.Contains(pattern, "*") {
		ok, err := filepath.Match(pattern, path)
		if err == nil && ok {
			return true
		}
	}
	if pattern == path {
		return true
	}
	return strings.HasSuffix(path, pattern)
}

func fallbackOwner(repo, org string) string {
	trimmedRepo := strings.TrimSpace(repo)
	team := "owners"
	if trimmedRepo != "" {
		if idx := strings.LastIndex(trimmedRepo, "/"); idx >= 0 && idx < len(trimmedRepo)-1 {
			trimmedRepo = trimmedRepo[idx+1:]
		}
		if token := strings.Split(strings.ReplaceAll(trimmedRepo, "_", "-"), "-")[0]; strings.TrimSpace(token) != "" {
			team = strings.ToLower(token)
		}
	}
	if strings.TrimSpace(org) == "" {
		return "@local/" + team
	}
	return "@" + strings.ToLower(strings.TrimSpace(org)) + "/" + team
}

func normalizePath(in string) string {
	return filepath.ToSlash(strings.TrimSpace(in))
}
