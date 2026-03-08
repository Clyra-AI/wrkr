package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/internal/reponame"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// Connector acquires GitHub repos/org lists with deterministic request semantics.
type Connector struct {
	BaseURL          string
	Token            string
	HTTPClient       HTTPClient
	MaxRetries       int
	Backoff          time.Duration
	MaxBackoff       time.Duration
	FailureThreshold int
	Cooldown         time.Duration

	mu                  sync.Mutex
	consecutiveFailures int
	cooldownUntil       time.Time
	nowFn               func() time.Time
	sleepFn             func(context.Context, time.Duration) error
}

func NewConnector(baseURL, token string, client HTTPClient) *Connector {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Connector{
		BaseURL:          strings.TrimRight(baseURL, "/"),
		Token:            token,
		HTTPClient:       client,
		MaxRetries:       2,
		Backoff:          25 * time.Millisecond,
		MaxBackoff:       2 * time.Second,
		FailureThreshold: 3,
		Cooldown:         10 * time.Second,
		nowFn:            time.Now,
		sleepFn:          sleepWithContext,
	}
}

// DegradedError indicates connector circuit-breaker degradation.
type DegradedError struct {
	CooldownUntil time.Time
	Cause         string
}

func (e *DegradedError) Error() string {
	cause := strings.TrimSpace(e.Cause)
	if cause == "" {
		cause = "upstream transient failures exceeded threshold"
	}
	if e.CooldownUntil.IsZero() {
		return "connector degraded: " + cause
	}
	return fmt.Sprintf("connector degraded until %s: %s", e.CooldownUntil.UTC().Format(time.RFC3339), cause)
}

// IsDegradedError reports whether err represents connector degradation.
func IsDegradedError(err error) bool {
	var degraded *DegradedError
	return errors.As(err, &degraded)
}

func (c *Connector) AcquireRepo(ctx context.Context, repo string) (source.RepoManifest, error) {
	repo, err := normalizeRepo(repo)
	if err != nil {
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
		fullName = repo
	}
	fullName, err = normalizeRepo(fullName)
	if err != nil {
		return source.RepoManifest{}, fmt.Errorf("acquire repo metadata: %w", err)
	}
	return source.RepoManifest{Repo: fullName, Location: fullName, Source: "github_repo"}, nil
}

func (c *Connector) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	normalizedOrg, err := reponame.NormalizeOrg(org)
	if err != nil {
		return nil, err
	}
	if c.BaseURL == "" {
		return nil, errors.New("github api base url is required for organization acquisition")
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base url: %w", err)
	}
	u.Path = path.Join(u.Path, "orgs", normalizedOrg, "repos")
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
				repo = normalizedOrg + "/" + item.Name
			}
			repo, err = normalizeRepo(repo)
			if err != nil {
				return nil, fmt.Errorf("list org repos page %d: %w", page, err)
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
	repo, err := normalizeRepo(repo)
	if err != nil {
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
		fullName = repo
	}
	fullName, err = normalizeRepo(fullName)
	if err != nil {
		return source.RepoManifest{}, fmt.Errorf("materialize repo metadata: %w", err)
	}
	defaultBranch := strings.TrimSpace(meta.DefaultBranch)
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	repoRoot, err := safeJoin(materializedRoot, fullName)
	if err != nil {
		return source.RepoManifest{}, fmt.Errorf("materialize repo root: %w", err)
	}
	if err := os.RemoveAll(repoRoot); err != nil {
		return source.RepoManifest{}, fmt.Errorf("clean materialized repo root: %w", err)
	}
	if err := os.MkdirAll(repoRoot, 0o750); err != nil {
		return source.RepoManifest{}, fmt.Errorf("create materialized repo root: %w", err)
	}

	tree, err := c.repoTree(ctx, fullName, defaultBranch)
	if err != nil {
		return source.RepoManifest{}, err
	}
	sort.Slice(tree, func(i, j int) bool { return tree[i].Path < tree[j].Path })

	for _, item := range tree {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return source.RepoManifest{}, ctxErr
		}
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
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return source.RepoManifest{}, fmt.Errorf("create materialized parent: %w", err)
		}
		if err := os.WriteFile(dest, decoded, 0o600); err != nil {
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
		Tree      []treeItem `json:"tree"`
		Truncated bool       `json:"truncated"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, fmt.Errorf("parse repo tree response: %w", err)
	}
	if payload.Truncated {
		return nil, fmt.Errorf("repo tree for %s@%s is truncated; repository is too large for single recursive tree request", repo, ref)
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
	if degradeErr := c.checkDegraded(); degradeErr != nil {
		return nil, degradeErr
	}

	var lastErr error
	for attempt := 0; attempt <= c.MaxRetries; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		if c.Token != "" {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := c.HTTPClient.Do(req)
		retryDelay := c.jitteredBackoff(attempt)
		if err != nil {
			lastErr = fmt.Errorf("request failed: %w", err)
		} else {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read response body: %w", readErr)
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				c.recordSuccess()
				return body, nil
			}
			if !isRetryable(resp.StatusCode) {
				c.resetFailureStreak()
				return nil, fmt.Errorf("github API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			}
			retryDelay = c.retryDelayForResponse(resp, attempt)
			lastErr = fmt.Errorf("github API transient status %d", resp.StatusCode)
		}

		if attempt == c.MaxRetries {
			break
		}
		if sleepErr := c.sleep(ctx, retryDelay); sleepErr != nil {
			return nil, sleepErr
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	return nil, c.recordFailure(lastErr)
}

func (c *Connector) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

func (c *Connector) sleep(ctx context.Context, duration time.Duration) error {
	if c.sleepFn != nil {
		return c.sleepFn(ctx, duration)
	}
	return sleepWithContext(ctx, duration)
}

func (c *Connector) jitteredBackoff(attempt int) time.Duration {
	backoff := c.Backoff
	if backoff <= 0 {
		backoff = 25 * time.Millisecond
	}
	maxBackoff := c.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 2 * time.Second
	}

	shift := attempt
	if shift > 8 {
		shift = 8
	}
	base := float64(backoff) * math.Pow(2, float64(shift))
	delay := time.Duration(base)
	if delay > maxBackoff {
		delay = maxBackoff
	}

	// Deterministic bounded jitter in [-20%, +20%].
	jitterPct := (attempt*37)%41 - 20
	jitter := delay * time.Duration(jitterPct) / 100
	delay += jitter

	minDelay := backoff / 2
	if minDelay <= 0 {
		minDelay = time.Millisecond
	}
	if delay < minDelay {
		delay = minDelay
	}
	if delay > maxBackoff {
		delay = maxBackoff
	}
	return delay
}

func (c *Connector) retryDelayForResponse(resp *http.Response, attempt int) time.Duration {
	if resp == nil {
		return c.jitteredBackoff(attempt)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		return c.jitteredBackoff(attempt)
	}

	now := c.now()
	if wait, ok := parseRetryAfter(resp.Header.Get("Retry-After"), now); ok {
		return wait
	}
	if wait, ok := parseRateLimitReset(resp.Header.Get("X-RateLimit-Reset"), now); ok {
		return wait
	}
	return c.jitteredBackoff(attempt)
}

func parseRetryAfter(raw string, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	wait := when.Sub(now)
	if wait < 0 {
		return 0, false
	}
	return wait, true
}

func parseRateLimitReset(raw string, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, false
	}
	epoch, err := strconv.ParseInt(value, 10, 64)
	if err != nil || epoch <= 0 {
		return 0, false
	}
	wait := time.Unix(epoch, 0).Sub(now)
	if wait < 0 {
		return 0, false
	}
	return wait, true
}

func (c *Connector) checkDegraded() error {
	threshold := c.FailureThreshold
	cooldown := c.Cooldown
	if threshold <= 0 || cooldown <= 0 {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cooldownUntil.IsZero() {
		return nil
	}
	now := c.now()
	if now.Before(c.cooldownUntil) {
		return &DegradedError{
			CooldownUntil: c.cooldownUntil,
			Cause:         "cooldown active after repeated upstream failures",
		}
	}
	c.cooldownUntil = time.Time{}
	c.consecutiveFailures = 0
	return nil
}

func (c *Connector) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFailures = 0
	c.cooldownUntil = time.Time{}
}

func (c *Connector) resetFailureStreak() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFailures = 0
}

func (c *Connector) recordFailure(lastErr error) error {
	if lastErr == nil {
		return errors.New("request failed")
	}
	if errors.Is(lastErr, context.Canceled) || errors.Is(lastErr, context.DeadlineExceeded) {
		return lastErr
	}

	threshold := c.FailureThreshold
	cooldown := c.Cooldown
	if threshold <= 0 || cooldown <= 0 {
		return lastErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.consecutiveFailures++
	if c.consecutiveFailures < threshold {
		return lastErr
	}

	c.cooldownUntil = c.now().Add(cooldown)
	c.consecutiveFailures = 0
	return &DegradedError{
		CooldownUntil: c.cooldownUntil,
		Cause:         lastErr.Error(),
	}
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func isRetryable(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

func validateRepo(repo string) error {
	return reponame.ValidateRepo(repo)
}

func normalizeRepo(repo string) (string, error) {
	return reponame.NormalizeRepo(repo)
}
