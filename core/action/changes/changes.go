package changes

import (
	"path/filepath"
	"sort"
	"strings"
)

var aiPrefixes = []string{
	".claude/",
	".cursor/",
	".codex/",
	".agents/skills/",
	".github/copilot-",
	".github/workflows/",
	"workflows/",
	"agent-plans/",
}

var aiExact = map[string]struct{}{
	"AGENTS.md":          {},
	"AGENTS.override.md": {},
	"CLAUDE.md":          {},
	".mcp.json":          {},
	".vscode/mcp.json":   {},
	".cursor/mcp.json":   {},
	"wrkr-policy.yaml":   {},
	"gait.yaml":          {},
	"Jenkinsfile":        {},
}

func HasRelevantChanges(paths []string) bool {
	return len(RelevantPaths(paths)) > 0
}

func RelevantPaths(paths []string) []string {
	out := make([]string, 0)
	for _, path := range paths {
		normalized := filepath.ToSlash(strings.TrimSpace(path))
		if normalized == "" {
			continue
		}
		if _, ok := aiExact[normalized]; ok {
			out = append(out, normalized)
			continue
		}
		for _, prefix := range aiPrefixes {
			if strings.HasPrefix(normalized, prefix) {
				out = append(out, normalized)
				break
			}
		}
	}
	out = uniqueSorted(out)
	return out
}

func uniqueSorted(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		set[item] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
