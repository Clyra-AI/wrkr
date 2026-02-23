package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
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
		return source.RepoManifest{}, errors.New("github api base url is required for repository acquisition")
	}

	meta, err := c.repoMetadata(ctx, repo)
	if err != nil {
		return source.RepoManifest{}, err
	}
	fullName := strings.TrimSpace(meta.FullName)
	if fullName == "" {
		fullName = strings.TrimSpace(repo)
	}
	return source.RepoManifest{Repo: fullName, Location: fullName, Source: "github_repo"}, nil
}

func (c *Connector) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	org = strings.TrimSpace(org)
	if org == "" {
		return nil, errors.New("org is required")
	}
	if c.BaseURL == "" {
		return nil, errors.New("github api base url is required for organization acquisition")
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	u.Path = path.Join(u.Path, "orgs", org, "repos")
	repos := make([]string, 0, 128)
	seen := map[string]struct{}{}
	for page := 1; ; page++ {
		pageURL := *u
		q := pageURL.Query()
		q.Set("per_page", "100")
		q.Set("page", fmt.Sprintf("%d", page))
		pageURL.RawQuery = q.Encode()

		respBody, err := c.doGETWithRetry(ctx, pageURL.String())
		if err != nil {
			return nil, fmt.Errorf("list org repos page %d: %w", page, err)
		}

		var payload []struct {
			FullName string `json:"full_name"`
			Name     string `json:"name"`
		}
		if err := json.Unmarshal(respBody, &payload); err != nil {
			return nil, fmt.Errorf("parse org repos response page %d: %w", page, err)
		}
		if len(payload) == 0 {
			break
		}

		for _, item := range payload {
			repo := strings.TrimSpace(item.FullName)
			if repo == "" {
				if strings.TrimSpace(item.Name) == "" {
					continue
				}
				repo = org + "/" + item.Name
			}
			if _, ok := seen[repo]; ok {
				continue
			}
			seen[repo] = struct{}{}
			repos = append(repos, repo)
		}

		if len(payload) < 100 {
			break
		}
	}
	sort.Strings(repos)
	return repos, nil
}

// MaterializeRepo fetches repository file contents through the GitHub API and writes
// them into a deterministic local workspace under materializedRoot.
func (c *Connector) MaterializeRepo(ctx context.Context, repo string, materializedRoot string) (source.RepoManifest, error) {
	if err := validateRepo(repo); err != nil {
		return source.RepoManifest{}, err
	}
	if c.BaseURL == "" {
		return source.RepoManifest{}, errors.New("github api base url is required for repository materialization")
	}

	meta, err := c.repoMetadata(ctx, repo)
	if err != nil {
		return source.RepoManifest{}, err
	}
	fullName := strings.TrimSpace(meta.FullName)
	if fullName == "" {
		fullName = strings.TrimSpace(repo)
	}
	defaultBranch := strings.TrimSpace(meta.DefaultBranch)
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	parts := strings.SplitN(fullName, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return source.RepoManifest{}, fmt.Errorf("materialize repo: invalid full_name %q", fullName)
	}

	repoRoot := filepath.Join(materializedRoot, parts[0], parts[1])
	if err := os.RemoveAll(repoRoot); err != nil {
		return source.RepoManifest{}, fmt.Errorf("clean materialized repo root: %w", err)
	}
	if err := os.MkdirAll(repoRoot, 0o755); err != nil {
		return source.RepoManifest{}, fmt.Errorf("create materialized repo root: %w", err)
	}

	tree, err := c.repoTree(ctx, fullName, defaultBranch)
	if err != nil {
		return source.RepoManifest{}, err
	}
	sort.Slice(tree, func(i, j int) bool { return tree[i].Path < tree[j].Path })

	for _, item := range tree {
		if item.Type != "blob" || strings.TrimSpace(item.Path) == "" {
			continue
		}
		blob, blobErr := c.repoBlob(ctx, fullName, item.SHA)
		if blobErr != nil {
			return source.RepoManifest{}, blobErr
		}
		decoded, decodeErr := decodeBlob(blob.Content, blob.Encoding)
		if decodeErr != nil {
			return source.RepoManifest{}, fmt.Errorf("decode blob %s: %w", item.SHA, decodeErr)
		}
		dest, pathErr := safeJoin(repoRoot, item.Path)
		if pathErr != nil {
			return source.RepoManifest{}, pathErr
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return source.RepoManifest{}, fmt.Errorf("create materialized parent: %w", err)
		}
		if err := os.WriteFile(dest, decoded, 0o644); err != nil {
			return source.RepoManifest{}, fmt.Errorf("write materialized file %s: %w", item.Path, err)
		}
	}

	return source.RepoManifest{
		Repo:     fullName,
		Location: filepath.ToSlash(repoRoot),
		Source:   "github_repo_materialized",
	}, nil
}

type repoMeta struct {
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
}

func (c *Connector) repoMetadata(ctx context.Context, repo string) (repoMeta, error) {
	endpoint := c.BaseURL + "/repos/" + repo
	respBody, err := c.doGETWithRetry(ctx, endpoint)
	if err != nil {
		return repoMeta{}, err
	}

	var payload repoMeta
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return repoMeta{}, fmt.Errorf("parse repo response: %w", err)
	}
	return payload, nil
}

type treeItem struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
}

func (c *Connector) repoTree(ctx context.Context, repo, ref string) ([]treeItem, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	u.Path = path.Join(u.Path, "repos", repo, "git", "trees", ref)
	q := u.Query()
	q.Set("recursive", "1")
	u.RawQuery = q.Encode()

	respBody, reqErr := c.doGETWithRetry(ctx, u.String())
	if reqErr != nil {
		return nil, fmt.Errorf("load repo tree for %s@%s: %w", repo, ref, reqErr)
	}

	var payload struct {
		Tree []treeItem `json:"tree"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("parse repo tree response: %w", err)
	}
	return payload.Tree, nil
}

func (c *Connector) repoBlob(ctx context.Context, repo, sha string) (struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}, error) {
	endpoint := c.BaseURL + "/repos/" + repo + "/git/blobs/" + sha
	respBody, err := c.doGETWithRetry(ctx, endpoint)
	if err != nil {
		return struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}{}, fmt.Errorf("load repo blob %s for %s: %w", sha, repo, err)
	}
	var payload struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return payload, fmt.Errorf("parse repo blob response: %w", err)
	}
	return payload, nil
}

func decodeBlob(content, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "utf-8":
		return []byte(content), nil
	case "base64":
		cleaned := strings.ReplaceAll(content, "\n", "")
		return base64.StdEncoding.DecodeString(cleaned)
	default:
		return nil, fmt.Errorf("unsupported blob encoding %q", encoding)
	}
}

func safeJoin(root, rel string) (string, error) {
	cleanRoot := filepath.Clean(root)
	cleanRel := filepath.Clean(filepath.FromSlash(rel))
	if cleanRel == "." || cleanRel == string(os.PathSeparator) {
		return "", fmt.Errorf("invalid relative path %q", rel)
	}
	target := filepath.Join(cleanRoot, cleanRel)
	if target != cleanRoot && !strings.HasPrefix(target, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("refusing to materialize path outside root: %s", rel)
	}
	return target, nil
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
