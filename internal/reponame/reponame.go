package reponame

import (
	"fmt"
	"strings"
)

// NormalizeRepo validates and canonicalizes an owner/repo identifier.
func NormalizeRepo(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	parts := strings.Split(trimmed, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("repo must be owner/repo, got %q", value)
	}
	owner, err := normalizeSegment(parts[0], "repo owner")
	if err != nil {
		return "", err
	}
	repo, err := normalizeSegment(parts[1], "repo name")
	if err != nil {
		return "", err
	}
	return owner + "/" + repo, nil
}

// ValidateRepo reports whether value is a path-safe owner/repo identifier.
func ValidateRepo(value string) error {
	_, err := NormalizeRepo(value)
	return err
}

// NormalizeOrg validates and canonicalizes an organization identifier.
func NormalizeOrg(value string) (string, error) {
	return normalizeSegment(value, "org")
}

// ValidateOrg reports whether value is a path-safe organization identifier.
func ValidateOrg(value string) error {
	_, err := NormalizeOrg(value)
	return err
}

func normalizeSegment(value string, label string) (string, error) {
	trimmed := strings.TrimSpace(value)
	switch trimmed {
	case "":
		return "", fmt.Errorf("%s is required", label)
	case ".", "..":
		return "", fmt.Errorf("%s must not be %q", label, trimmed)
	}
	if strings.Contains(trimmed, "/") || strings.Contains(trimmed, "\\") {
		return "", fmt.Errorf("%s must not contain path separators: %q", label, value)
	}
	return trimmed, nil
}
