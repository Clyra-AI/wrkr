package githubendpoint

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseRequiresSafeHTTPSBaseURL(t *testing.T) {
	t.Parallel()

	endpoint, err := Parse("https://github.example/api/v3", Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := endpoint.String(), "https://github.example/api/v3"; got != want {
		t.Fatalf("endpoint = %q, want %q", got, want)
	}

	for _, raw := range []string{
		"http://github.example",
		"https://token@github.example",
		"https://github.example#fragment",
		"https://github.example?token=leak",
		"github.example",
	} {
		if _, err := Parse(raw, Options{}); !errors.Is(err, ErrUnsafeEndpoint) {
			t.Fatalf("Parse(%q) error = %v, want unsafe endpoint", raw, err)
		}
	}
}

func TestArchiveRedirectPolicyAllowsOnlyTokenlessGitHubCodeload(t *testing.T) {
	t.Parallel()
	base, err := Parse("https://api.github.com", Options{})
	if err != nil {
		t.Fatal(err)
	}
	policy := ArchiveRedirectPolicy(base)
	req := httptest.NewRequest(http.MethodGet, "https://codeload.github.com/acme/repo/legacy.tar.gz/main", nil)
	req.Header.Set("Authorization", "Bearer secret")
	if err := policy(req, nil); err != nil {
		t.Fatalf("expected GitHub codeload redirect to be accepted: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Fatalf("archive redirect retained authorization header: %q", got)
	}
	bad := httptest.NewRequest(http.MethodGet, "https://download.example/archive.tgz", nil)
	if err := policy(bad, nil); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("expected untrusted archive redirect rejection, got %v", err)
	}
}

func TestParseAllowsExplicitLoopbackHTTPOnly(t *testing.T) {
	t.Parallel()
	if _, err := Parse("http://127.0.0.1:8080", Options{AllowInsecureLoopback: true}); err != nil {
		t.Fatalf("Parse(loopback) error = %v", err)
	}
	if _, err := Parse("http://github.example", Options{AllowInsecureLoopback: true}); !errors.Is(err, ErrUnsafeEndpoint) {
		t.Fatalf("Parse(external HTTP) error = %v, want unsafe endpoint", err)
	}
}

func TestRedirectPolicyRejectsCrossOriginAndDowngrade(t *testing.T) {
	t.Parallel()
	base, err := Parse("https://github.example/api/v3", Options{})
	if err != nil {
		t.Fatal(err)
	}
	policy := RedirectPolicy(base)
	for _, raw := range []string{"https://other.example/api/v3", "http://github.example/api/v3"} {
		req := httptest.NewRequest("GET", raw, nil)
		if err := policy(req, nil); !errors.Is(err, ErrUnsafeEndpoint) {
			t.Fatalf("policy(%q) error = %v, want unsafe endpoint", raw, err)
		}
	}
}
