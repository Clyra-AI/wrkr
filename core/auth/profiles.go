package auth

import (
	"errors"
	"strings"
)

var ErrFixProfileRequired = errors.New("fix profile token is required for write operations")

// ResolveFixToken resolves a write-capable token and fails closed when only scan credentials exist.
func ResolveFixToken(scanToken, fixToken, overrideToken string) (string, error) {
	if token := strings.TrimSpace(overrideToken); token != "" {
		return token, nil
	}
	if token := strings.TrimSpace(fixToken); token != "" {
		return token, nil
	}
	if strings.TrimSpace(scanToken) != "" {
		return "", ErrFixProfileRequired
	}
	return "", ErrFixProfileRequired
}
