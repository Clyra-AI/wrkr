package detect

import (
	"path/filepath"
	"strings"
)

func IsGeneratedPath(rel string) bool {
	normalized := normalizePathFilterPath(rel)
	if normalized == "" || normalized == "." {
		return false
	}
	if strings.HasSuffix(normalized, ".min.js") {
		return true
	}
	parts := strings.Split(normalized, "/")
	for idx, part := range parts {
		switch part {
		case "node_modules", "dist", "build", "vendor", ".venv", "generated", "generated-sdks", "generated-sdk", ".pnpm", ".pnpm-store", ".docusaurus", ".next", ".nuxt":
			return true
		case "target":
			return true
		case ".yarn":
			if idx+1 < len(parts) {
				switch parts[idx+1] {
				case "sdks", "cache", "__virtual__", "unplugged":
					return true
				}
			}
		case ".vitepress":
			if idx+1 < len(parts) {
				switch parts[idx+1] {
				case "cache", "dist":
					return true
				}
			}
		case ".cache":
			if idx > 0 && (parts[idx-1] == ".vitepress" || parts[idx-1] == "docs" || parts[idx-1] == "docs-site") {
				return true
			}
		}
		if strings.Contains(part, "generated-sdk") || strings.Contains(part, "generated_client") {
			return true
		}
	}
	return false
}

func IsWebMCPRouteFile(rel string) bool {
	normalized := normalizePathFilterPath(rel)
	switch normalized {
	case ".well-known/webmcp", ".well-known/webmcp.json", ".well-known/webmcp.yaml", ".well-known/webmcp.yml":
		return true
	}
	return strings.HasSuffix(normalized, "/.well-known/webmcp") ||
		strings.HasSuffix(normalized, "/.well-known/webmcp.json") ||
		strings.HasSuffix(normalized, "/.well-known/webmcp.yaml") ||
		strings.HasSuffix(normalized, "/.well-known/webmcp.yml")
}

func IsHighSignalWebMCPPath(rel string) bool {
	normalized := normalizePathFilterPath(rel)
	if normalized == "" {
		return false
	}
	if IsWebMCPRouteFile(normalized) {
		return true
	}
	if hasPathFilterSegment(normalized, ".well-known", "webmcp", "routes", "route", "router", "api", "server", "handler", "gateway", "ui") {
		return true
	}
	return baseNameContainsPathFilterToken(normalized, "webmcp", "mcp", "register", "route", "router", "server", "gateway", "api", "handler")
}

func IsHighSignalAgentFrameworkSourcePath(rel string) bool {
	normalized := normalizePathFilterPath(rel)
	if normalized == "" {
		return false
	}
	if strings.HasPrefix(normalized, ".wrkr/agents/") {
		return true
	}
	if hasPathFilterSegment(normalized, "agent", "agents", "crew", "crews", "assistant", "assistants", "orchestrator", "orchestrators", "bot", "bots", "handoff", "handoffs") {
		return true
	}
	return baseNameContainsPathFilterToken(normalized, "agent", "crew", "assistant", "orchestrator", "handoff", "mcp")
}

func IsHighSignalMCPCandidateSourcePath(rel string) bool {
	normalized := normalizePathFilterPath(rel)
	if normalized == "" {
		return false
	}
	if strings.HasPrefix(normalized, ".well-known/") {
		return true
	}
	if hasPathFilterSegment(normalized, ".well-known", "mcp", "server", "servers", "gateway", "gateways", "agent", "agents", "tools", "tool", "scripts", "script", "routes", "route", "router", "api") {
		return true
	}
	return baseNameContainsPathFilterToken(normalized, "mcp", "server", "client", "gateway", "agent", "tool", "router", "route", "register")
}

func normalizePathFilterPath(rel string) string {
	return strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel)))
}

func hasPathFilterSegment(rel string, want ...string) bool {
	if rel == "" {
		return false
	}
	segments := strings.Split(rel, "/")
	for _, segment := range segments {
		for _, candidate := range want {
			if segment == candidate {
				return true
			}
		}
	}
	return false
}

func baseNameContainsPathFilterToken(rel string, tokens ...string) bool {
	if rel == "" {
		return false
	}
	base := strings.TrimSuffix(filepath.Base(rel), filepath.Ext(rel))
	for _, token := range tokens {
		if strings.Contains(base, token) {
			return true
		}
	}
	return false
}
