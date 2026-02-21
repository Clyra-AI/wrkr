package pr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

const (
	defaultGitHubAPI = "https://api.github.com"
	maxAttempts      = 3
)

type GitHubClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewGitHubClient(baseURL, token string, client *http.Client) *GitHubClient {
	trimmedBase := strings.TrimSpace(baseURL)
	if trimmedBase == "" {
		trimmedBase = defaultGitHubAPI
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &GitHubClient{
		baseURL: strings.TrimRight(trimmedBase, "/"),
		token:   strings.TrimSpace(token),
		http:    client,
	}
}

func (c *GitHubClient) ListOpenByHead(ctx context.Context, owner, repo, headBranch, baseBranch string) ([]PullRequest, error) {
	endpoint, err := c.repoURL(owner, repo, "pulls")
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("state", "open")
	query.Set("head", owner+":"+headBranch)
	query.Set("base", baseBranch)
	endpoint.RawQuery = query.Encode()

	var raw []githubPR
	if err := c.doJSON(ctx, http.MethodGet, endpoint.String(), nil, &raw); err != nil {
		return nil, err
	}
	out := make([]PullRequest, 0, len(raw))
	for _, item := range raw {
		out = append(out, item.toPullRequest())
	}
	return out, nil
}

func (c *GitHubClient) Create(ctx context.Context, owner, repo string, req CreateRequest) (PullRequest, error) {
	endpoint, err := c.repoURL(owner, repo, "pulls")
	if err != nil {
		return PullRequest{}, err
	}
	payload := map[string]any{
		"title": req.Title,
		"head":  req.Head,
		"base":  req.Base,
		"body":  req.Body,
	}
	var raw githubPR
	if err := c.doJSON(ctx, http.MethodPost, endpoint.String(), payload, &raw); err != nil {
		return PullRequest{}, err
	}
	return raw.toPullRequest(), nil
}

func (c *GitHubClient) Update(ctx context.Context, owner, repo string, number int, req UpdateRequest) (PullRequest, error) {
	endpoint, err := c.repoURL(owner, repo, "pulls", strconv.Itoa(number))
	if err != nil {
		return PullRequest{}, err
	}
	payload := map[string]any{"title": req.Title, "body": req.Body}
	var raw githubPR
	if err := c.doJSON(ctx, http.MethodPatch, endpoint.String(), payload, &raw); err != nil {
		return PullRequest{}, err
	}
	return raw.toPullRequest(), nil
}

func (c *GitHubClient) doJSON(ctx context.Context, method, endpoint string, payload any, out any) error {
	var bodyBytes []byte
	var err error
	if payload != nil {
		bodyBytes, err = json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal github payload: %w", err)
		}
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var body io.Reader
		if len(bodyBytes) > 0 {
			body = bytes.NewReader(bodyBytes)
		}

		req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
		if err != nil {
			return fmt.Errorf("build github request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.http.Do(req)
		if err != nil {
			if attempt < maxAttempts {
				continue
			}
			return fmt.Errorf("github request failed: %w", err)
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read github response: %w", readErr)
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(respBody) > 0 {
				if err := json.Unmarshal(respBody, out); err != nil {
					return fmt.Errorf("decode github response: %w", err)
				}
			}
			return nil
		}

		if shouldRetry(resp.StatusCode) && attempt < maxAttempts {
			continue
		}
		return fmt.Errorf("github api %s %s failed: status=%d body=%s", method, endpoint, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return fmt.Errorf("github request attempts exceeded")
}

func shouldRetry(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func (c *GitHubClient) repoURL(owner, repo string, parts ...string) (*url.URL, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("parse github base url: %w", err)
	}
	base.Path = path.Join(base.Path, "/repos", owner, repo)
	for _, item := range parts {
		base.Path = path.Join(base.Path, item)
	}
	return base, nil
}

type githubPR struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Title   string `json:"title"`
	Body    string `json:"body"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (p githubPR) toPullRequest() PullRequest {
	return PullRequest{
		Number: p.Number,
		URL:    p.HTMLURL,
		Title:  p.Title,
		Body:   p.Body,
		Head:   p.Head.Ref,
		Base:   p.Base.Ref,
	}
}
