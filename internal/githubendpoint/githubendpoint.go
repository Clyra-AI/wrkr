// Package githubendpoint validates token-bearing GitHub API endpoints.
package githubendpoint

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var ErrUnsafeEndpoint = errors.New("unsafe GitHub API endpoint")

type Options struct {
	// AllowInsecureLoopback permits HTTP only for localhost test/development servers.
	AllowInsecureLoopback bool
}

func Parse(raw string, options Options) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: parse URL: %v", ErrUnsafeEndpoint, err)
	}
	if endpoint.Scheme == "" || endpoint.Host == "" || endpoint.Hostname() == "" {
		return nil, fmt.Errorf("%w: URL must include scheme and host", ErrUnsafeEndpoint)
	}
	if endpoint.User != nil {
		return nil, fmt.Errorf("%w: userinfo is not allowed", ErrUnsafeEndpoint)
	}
	if endpoint.Fragment != "" {
		return nil, fmt.Errorf("%w: fragments are not allowed", ErrUnsafeEndpoint)
	}
	if endpoint.RawQuery != "" {
		return nil, fmt.Errorf("%w: query parameters are not allowed", ErrUnsafeEndpoint)
	}
	switch strings.ToLower(endpoint.Scheme) {
	case "https":
		return endpoint, nil
	case "http":
		if options.AllowInsecureLoopback && isLoopback(endpoint.Hostname()) {
			return endpoint, nil
		}
		return nil, fmt.Errorf("%w: HTTPS is required", ErrUnsafeEndpoint)
	default:
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrUnsafeEndpoint, endpoint.Scheme)
	}
}

func RedirectPolicy(base *url.URL) func(*http.Request, []*http.Request) error {
	return func(next *http.Request, _ []*http.Request) error {
		if next == nil || next.URL == nil {
			return fmt.Errorf("%w: invalid redirect target", ErrUnsafeEndpoint)
		}
		if next.URL.Scheme != "https" || next.URL.User != nil || next.URL.Fragment != "" || next.URL.Hostname() == "" {
			return fmt.Errorf("%w: redirect must remain HTTPS without userinfo or fragments", ErrUnsafeEndpoint)
		}
		if !sameOrigin(base, next.URL) {
			return fmt.Errorf("%w: redirect must remain on the configured GitHub API origin", ErrUnsafeEndpoint)
		}
		return nil
	}
}

func isLoopback(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}
