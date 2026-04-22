package detect

import (
	"path/filepath"
	"strings"
)

func IsGeneratedPath(rel string) bool {
	normalized := strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel)))
	if normalized == "" || normalized == "." {
		return false
	}
	if strings.HasSuffix(normalized, ".min.js") {
		return true
	}
	parts := strings.Split(normalized, "/")
	for idx, part := range parts {
		switch part {
		case "node_modules", "dist", "build", "vendor", ".venv", "generated", "generated-sdks", "generated-sdk":
			return true
		case "target":
			return true
		case ".yarn":
			if idx+1 < len(parts) && parts[idx+1] == "sdks" {
				return true
			}
		}
		if strings.Contains(part, "generated-sdk") || strings.Contains(part, "generated_client") {
			return true
		}
	}
	return false
}
