package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/source"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Connector acquires GitHub repos/org lists with deterministic request semantics.
type Connector struct {
	BaseURL    string
	Token      string
	HTTPClient HTTPClient
	MaxRetries int
	Backoff    time.Duration
}

func NewConnector(baseURL, token string, client HTTPClient) *Connector {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Connector{
		BaseURL:    strings.TrimRight(baseURL, "/"),
		Token:      token,
		HTTPClient: client,
		MaxRetries: 2,
		Backoff:    25 * time.Millisecond,
	}
}

func (c *Connector) AcquireRepo(ctx context.Context, repo string) (source.RepoManifest, error) {
	if err := validateRepo(repo); err != nil {
		return source.RepoManifest{}, err
	}
	if c.BaseURL == "" {
		return source.RepoManifest{Repo: repo, Location: repo, Source: "github_repo"}, nil
	}

	endpoint := c.BaseURL + "/repos/" + repo
	respBody, err := c.doGETWithRetry(ctx, endpoint)
	if err != nil {
		return source.RepoManifest{}, err
	}

	var payload struct {
		FullName string `json:"full_name"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return source.RepoManifest{}, fmt.Errorf("parse repo response: %w", err)
	}
	if payload.FullName == "" {
		payload.FullName = repo
	}
	return source.RepoManifest{Repo: payload.FullName, Location: payload.FullName, Source: "github_repo"}, nil
}

func (c *Connector) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	org = strings.TrimSpace(org)
	if org == "" {
		return nil, errors.New("org is required")
	}
	if c.BaseURL == "" {
		return []string{org + "/default"}, nil
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	u.Path = path.Join(u.Path, "orgs", org, "repos")
	q := u.Query()
	q.Set("per_page", "100")
	u.RawQuery = q.Encode()

	respBody, err := c.doGETWithRetry(ctx, u.String())
	if err != nil {
		return nil, err
	}

	var payload []struct {
		FullName string `json:"full_name"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("parse org repos response: %w", err)
	}

	repos := make([]string, 0, len(payload))
	for _, item := range payload {
		repo := strings.TrimSpace(item.FullName)
		if repo == "" {
			if item.Name == "" {
				continue
			}
			repo = org + "/" + item.Name
		}
		repos = append(repos, repo)
	}
	if len(repos) == 0 {
		repos = append(repos, org+"/default")
	}
	return repos, nil
}

func (c *Connector) doGETWithRetry(ctx context.Context, endpoint string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read response body: %w", readErr)
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return body, nil
			}
			if !isRetryable(resp.StatusCode) {
				return nil, fmt.Errorf("github API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			lastErr = fmt.Errorf("github API transient status %d", resp.StatusCode)
		}

		if attempt == c.MaxRetries {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.Backoff * time.Duration(attempt+1)):
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, lastErr
}

func isRetryable(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func validateRepo(repo string) error {
	repo = strings.TrimSpace(repo)
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("repo must be owner/repo, got %q", repo)
	}
	return nil
}
