package detect

import (
	"fmt"
	"os"
	"strings"
)

// ValidateScopeRoot ensures detector scope roots are valid directories.
func ValidateScopeRoot(root string) error {
	clean := strings.TrimSpace(root)
	if clean == "" {
		return fmt.Errorf("scope root is required")
	}
	info, err := os.Stat(clean)
	if err != nil {
		return fmt.Errorf("stat scope root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("scope root is not a directory: %s", clean)
	}
	return nil
}
