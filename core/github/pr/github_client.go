package pr

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type httpStatusError struct {
	method string
	url    string
	status int
	body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("github api %s %s failed: status=%d body=%s", e.method, e.url, e.status, strings.TrimSpace(e.body))
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

func (c *GitHubClient) EnsureHeadRef(ctx context.Context, owner, repo, headBranch, baseBranch string) error {
	if strings.TrimSpace(headBranch) == "" || strings.TrimSpace(baseBranch) == "" {
		return fmt.Errorf("head/base branches are required")
	}
	if _, err := c.refSHA(ctx, owner, repo, headBranch); err == nil {
		return nil
	} else {
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || statusErr.status != http.StatusNotFound {
			return err
		}
	}

	baseSHA, err := c.refSHA(ctx, owner, repo, baseBranch)
	if err != nil {
		return fmt.Errorf("resolve base branch %q: %w", baseBranch, err)
	}

	endpoint, err := c.repoURL(owner, repo, "git", "refs")
	if err != nil {
		return err
	}
	payload := map[string]any{
		"ref": "refs/heads/" + strings.TrimSpace(headBranch),
		"sha": baseSHA,
	}
	if err := c.doJSON(ctx, http.MethodPost, endpoint.String(), payload, nil); err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.status == http.StatusUnprocessableEntity {
			// Branch may have been created by a concurrent run between existence check and create.
			return nil
		}
		return err
	}
	return nil
}

func (c *GitHubClient) EnsureFileContent(ctx context.Context, owner, repo, branch, filePath, commitMessage string, content []byte) (bool, error) {
	trimmedPath := strings.TrimSpace(filePath)
	trimmedBranch := strings.TrimSpace(branch)
	trimmedMessage := strings.TrimSpace(commitMessage)
	if trimmedPath == "" {
		return false, fmt.Errorf("file path is required")
	}
	if trimmedBranch == "" {
		return false, fmt.Errorf("branch is required")
	}
	if trimmedMessage == "" {
		return false, fmt.Errorf("commit message is required")
	}

	endpoint, err := c.repoURL(owner, repo, "contents", trimmedPath)
	if err != nil {
		return false, err
	}
	query := endpoint.Query()
	query.Set("ref", trimmedBranch)
	endpoint.RawQuery = query.Encode()

	existingSHA := ""
	existingContent, err := c.readFileContent(ctx, endpoint.String())
	if err == nil {
		existingSHA = existingContent.SHA
		decoded, decodeErr := decodeGitHubFileContent(existingContent.Content, existingContent.Encoding)
		if decodeErr != nil {
			return false, decodeErr
		}
		if bytes.Equal(decoded, content) {
			return false, nil
		}
	} else {
		var statusErr *httpStatusError
		if !errors.As(err, &statusErr) || statusErr.status != http.StatusNotFound {
			return false, err
		}
	}

	payload := map[string]any{
		"message": trimmedMessage,
		"content": base64.StdEncoding.EncodeToString(content),
		"branch":  trimmedBranch,
	}
	if strings.TrimSpace(existingSHA) != "" {
		payload["sha"] = existingSHA
	}

	if err := c.doJSON(ctx, http.MethodPut, endpoint.String(), payload, nil); err != nil {
		var statusErr *httpStatusError
		if errors.As(err, &statusErr) && statusErr.status == http.StatusUnprocessableEntity {
			lower := strings.ToLower(statusErr.body)
			if strings.Contains(lower, "same") || strings.Contains(lower, "no changes") {
				return false, nil
			}
		}
		return false, err
	}
	return true, nil
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

type githubFileContent struct {
	SHA      string `json:"sha"`
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func (c *GitHubClient) readFileContent(ctx context.Context, endpoint string) (githubFileContent, error) {
	var payload githubFileContent
	if err := c.doJSON(ctx, http.MethodGet, endpoint, nil, &payload); err != nil {
		return githubFileContent{}, err
	}
	return payload, nil
}

func decodeGitHubFileContent(content, encoding string) ([]byte, error) {
	if strings.TrimSpace(content) == "" {
		return []byte{}, nil
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "base64":
		clean := strings.ReplaceAll(strings.TrimSpace(content), "\n", "")
		decoded, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, fmt.Errorf("decode github file content: %w", err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported github file encoding %q", encoding)
	}
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

		resp, err := c.http.Do(req) // #nosec G704 -- request targets GitHub API endpoint assembled from validated base URL and fixed path segments.
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
		return &httpStatusError{
			method: method,
			url:    endpoint,
			status: resp.StatusCode,
			body:   string(respBody),
		}
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
	segments := []string{"repos", owner, repo}
	segments = append(segments, parts...)
	base.Path = joinURLPath(base.Path, segments...)
	return base, nil
}

func joinURLPath(basePath string, segments ...string) string {
	items := make([]string, 0, len(segments)+2)
	if trimmed := strings.Trim(basePath, "/"); trimmed != "" {
		items = append(items, strings.Split(trimmed, "/")...)
	}
	for _, segment := range segments {
		trimmed := strings.Trim(segment, "/")
		if trimmed == "" {
			continue
		}
		items = append(items, strings.Split(trimmed, "/")...)
	}
	if len(items) == 0 {
		return "/"
	}
	return "/" + path.Join(items...)
}

func (c *GitHubClient) refSHA(ctx context.Context, owner, repo, branch string) (string, error) {
	endpoint, err := c.repoURL(owner, repo, "git", "ref", "heads", branch)
	if err != nil {
		return "", err
	}
	var payload struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := c.doJSON(ctx, http.MethodGet, endpoint.String(), nil, &payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.Object.SHA) == "" {
		return "", fmt.Errorf("git ref for branch %q did not include object sha", branch)
	}
	return strings.TrimSpace(payload.Object.SHA), nil
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
