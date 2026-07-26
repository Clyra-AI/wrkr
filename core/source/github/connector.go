package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"github.com/Clyra-AI/wrkr/internal/githubendpoint"
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
	// AllowSourceMaterialization permits broad source-code extension fetching for
	// explicit deep/debug scans. Default hosted scans keep this false.
	AllowSourceMaterialization bool
	endpointOptions            githubendpoint.Options

	mu                  sync.Mutex
	consecutiveFailures int
	cooldownUntil       time.Time
	nowFn               func() time.Time
	sleepFn             func(context.Context, time.Duration) error
	onRetry             func(RetryEvent)
	onCooldown          func(CooldownEvent)
	cooldownErr         error
	requestStats        source.AcquisitionTelemetry
}

// ConnectorOptions controls explicit development-only connector behavior.
type ConnectorOptions struct {
	AllowInsecureLoopback bool
}

type RetryEvent struct {
	Attempt    int
	StatusCode int
	Delay      time.Duration
}

type CooldownEvent struct {
	Delay time.Duration
	Until time.Time
}

func NewConnector(baseURL, token string, client HTTPClient) *Connector {
	return NewConnectorWithOptions(baseURL, token, client, ConnectorOptions{})
}

// NewConnectorWithOptions permits loopback HTTP only when explicitly requested
// for local development or tests. Production callers must use NewConnector.
func NewConnectorWithOptions(baseURL, token string, client HTTPClient, options ConnectorOptions) *Connector {
	endpointOptions := githubendpoint.Options{AllowInsecureLoopback: options.AllowInsecureLoopback}
	if configured, ok := client.(*http.Client); ok {
		client = newSafeHTTPClient(baseURL, endpointOptions, configured)
	} else if client == nil {
		client = newSafeHTTPClient(baseURL, endpointOptions, nil)
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
		endpointOptions:  endpointOptions,
		nowFn:            time.Now,
		sleepFn:          sleepWithContext,
	}
}

func newSafeHTTPClient(baseURL string, options githubendpoint.Options, source *http.Client) *http.Client {
	client := http.Client{Timeout: 10 * time.Second}
	if source != nil {
		client = *source
	}
	if endpoint, err := githubendpoint.Parse(baseURL, options); err == nil {
		client.CheckRedirect = githubendpoint.RedirectPolicy(endpoint)
	}
	return &client
}

func (c *Connector) validateEndpoint() error {
	if c == nil {
		return errors.New("github connector is required")
	}
	_, err := githubendpoint.Parse(c.BaseURL, c.endpointOptions)
	return err
}

func (c *Connector) SetRetryHandler(fn func(RetryEvent)) {
	if c == nil {
		return
	}
	c.onRetry = fn
}

func (c *Connector) SetCooldownHandler(fn func(CooldownEvent)) {
	if c == nil {
		return
	}
	c.onCooldown = fn
}

func (c *Connector) SetAllowSourceMaterialization(allow bool) {
	if c == nil {
		return
	}
	c.AllowSourceMaterialization = allow
}

func (c *Connector) AcquisitionTelemetry() source.AcquisitionTelemetry {
	if c == nil {
		return source.AcquisitionTelemetry{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.requestStats
	out.Warnings = append([]string(nil), c.requestStats.Warnings...)
	if c.AllowSourceMaterialization {
		out.Mode = "archive"
	} else {
		out.Mode = "sparse_api"
	}
	return out
}

func (c *Connector) EnsureRequestBudget(repoCount int) error {
	if c == nil || repoCount <= 0 {
		return nil
	}
	perRepo := 50
	if c.AllowSourceMaterialization {
		perRepo = 2
	}
	estimate := repoCount*perRepo + 25
	c.mu.Lock()
	c.requestStats.EstimatedRequests = estimate
	remaining := c.requestStats.RateLimitRemaining
	limit := c.requestStats.RateLimitLimit
	if limit > 0 && remaining < estimate {
		c.requestStats.Warnings = append(c.requestStats.Warnings, fmt.Sprintf("estimated GitHub requests %d exceed remaining budget %d", estimate, remaining))
	}
	c.mu.Unlock()
	if limit > 0 && remaining < estimate {
		return fmt.Errorf("github request budget is insufficient before materialization: estimated=%d remaining=%d; wait for reset, scan pre-cloned repositories with --path, or reduce the org scope", estimate, remaining)
	}
	return nil
}

// DegradedError indicates connector circuit-breaker degradation.
type DegradedError struct {
	CooldownUntil time.Time
	Cause         string
	Err           error
}

func (e *DegradedError) Error() string {
	cause := strings.TrimSpace(e.Cause)
	if cause == "" && e.Err != nil {
		cause = strings.TrimSpace(e.Err.Error())
	}
	if cause == "" {
		cause = "upstream transient failures exceeded threshold"
	}
	if e.CooldownUntil.IsZero() {
		return "connector degraded: " + cause
	}
	return fmt.Sprintf("connector degraded until %s: %s", e.CooldownUntil.UTC().Format(time.RFC3339), cause)
}

func (e *DegradedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// IsDegradedError reports whether err represents connector degradation.
func IsDegradedError(err error) bool {
	var degraded *DegradedError
	return errors.As(err, &degraded)
}

type RateLimitedError struct {
	StatusCode int
	Attempts   int
	Evidence   string
	Message    string
}

func (e *RateLimitedError) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("github API rate limit exhausted after %d attempt(s)", e.Attempts)}
	if e.StatusCode != 0 {
		parts = append(parts, fmt.Sprintf("status=%d", e.StatusCode))
	}
	if evidence := strings.TrimSpace(e.Evidence); evidence != "" {
		parts = append(parts, "evidence="+evidence)
	}
	if message := strings.TrimSpace(e.Message); message != "" {
		parts = append(parts, "upstream_message="+message)
	}
	return strings.Join(parts, "; ")
}

// IsRateLimitedError reports whether err represents exhausted hosted throttling.
func IsRateLimitedError(err error) bool {
	var target *RateLimitedError
	return errors.As(err, &target)
}

func (c *Connector) AcquireRepo(ctx context.Context, repo string) (source.RepoManifest, error) {
	repo, err := normalizeRepo(repo)
	if err != nil {
		return source.RepoManifest{}, err
	}
	if c.BaseURL == "" {
		return source.RepoManifest{}, errors.New("github api base url is required for repository acquisition")
	}
	if err := c.validateEndpoint(); err != nil {
		return source.RepoManifest{}, err
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
	return source.RepoManifest{
		Repo:              fullName,
		Location:          fullName,
		Source:            "github_repo",
		OwnershipMetadata: repoOwnershipMetadata(meta),
	}, nil
}

func (c *Connector) ListOrgRepos(ctx context.Context, org string) ([]string, error) {
	normalizedOrg, err := reponame.NormalizeOrg(org)
	if err != nil {
		return nil, err
	}
	if c.BaseURL == "" {
		return nil, errors.New("github api base url is required for organization acquisition")
	}
	if err := c.validateEndpoint(); err != nil {
		return nil, err
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
	if err := c.validateEndpoint(); err != nil {
		return source.RepoManifest{}, err
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

	if c.AllowSourceMaterialization {
		emptyRepo, archiveErr := c.materializeRepoArchive(ctx, fullName, defaultBranch, repoRoot, meta.Size != nil && *meta.Size == 0)
		if archiveErr != nil {
			return source.RepoManifest{}, archiveErr
		}
		contentStatus := source.RepoContentStatusAvailable
		if emptyRepo {
			contentStatus = source.RepoContentStatusEmpty
		}
		return source.RepoManifest{
			Repo:              fullName,
			Location:          "github://" + fullName,
			ScanRoot:          filepath.ToSlash(repoRoot),
			Source:            "github_repo_archive",
			ContentStatus:     contentStatus,
			OwnershipMetadata: repoOwnershipMetadata(meta),
		}, nil
	}

	tree, emptyRepo, err := c.repoTree(ctx, fullName, defaultBranch)
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
		dest, pathErr := safeJoin(repoRoot, item.Path)
		if pathErr != nil {
			return source.RepoManifest{}, pathErr
		}
		if !shouldMaterializeBlobWithSource(item.Path, c.AllowSourceMaterialization) {
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
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return source.RepoManifest{}, fmt.Errorf("create materialized parent: %w", err)
		}
		if err := os.WriteFile(dest, decoded, 0o600); err != nil {
			return source.RepoManifest{}, fmt.Errorf("write materialized file %s: %w", item.Path, err)
		}
	}

	contentStatus := source.RepoContentStatusAvailable
	if emptyRepo {
		contentStatus = source.RepoContentStatusEmpty
	}
	return source.RepoManifest{
		Repo:              fullName,
		Location:          "github://" + fullName,
		ScanRoot:          filepath.ToSlash(repoRoot),
		Source:            "github_repo_materialized",
		ContentStatus:     contentStatus,
		OwnershipMetadata: repoOwnershipMetadata(meta),
	}, nil
}

type repoMeta struct {
	FullName      string   `json:"full_name"`
	DefaultBranch string   `json:"default_branch"`
	Size          *int     `json:"size"`
	Topics        []string `json:"topics"`
	Teams         []string `json:"teams"`
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

func (c *Connector) repoTree(ctx context.Context, repo, ref string) ([]treeItem, bool, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, false, fmt.Errorf("invalid base url: %w", err)
	}
	u.Path = path.Join(u.Path, "repos", repo, "git", "trees", ref)
	q := u.Query()
	q.Set("recursive", "1")
	u.RawQuery = q.Encode()

	respBody, reqErr := c.doGETWithRetry(ctx, u.String())
	if reqErr != nil {
		if isEmptyRepositoryTreeError(reqErr) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("load repo tree for %s@%s: %w", repo, ref, reqErr)
	}

	var payload struct {
		Tree      []treeItem `json:"tree"`
		Truncated bool       `json:"truncated"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return nil, false, fmt.Errorf("parse repo tree response: %w", err)
	}
	if payload.Truncated {
		return nil, false, fmt.Errorf("repo tree for %s@%s is truncated; repository is too large for single recursive tree request", repo, ref)
	}
	return payload.Tree, len(payload.Tree) == 0, nil
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

const (
	maxArchiveResponseBytes = 100 << 20
	maxArchiveFileBytes     = 10 << 20
	maxArchiveExtractBytes  = 250 << 20
	maxArchiveExpandedBytes = 2 << 30
	maxArchiveFiles         = 50000
	archiveRequestTimeout   = 5 * time.Minute
)

func (c *Connector) materializeRepoArchive(ctx context.Context, repo, ref, repoRoot string, knownEmpty bool) (bool, error) {
	endpoint := c.BaseURL + "/repos/" + repo + "/tarball/" + url.PathEscape(ref)
	body, err := c.doGETWithRetryClient(ctx, endpoint, maxArchiveResponseBytes, c.archiveHTTPClient())
	if err != nil {
		if isEmptyRepositoryTreeError(err) || (knownEmpty && isMissingRepositoryArchiveError(err)) {
			return true, nil
		}
		return false, fmt.Errorf("load repository archive for %s@%s: %w", repo, ref, err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("open repository archive for %s: %w", repo, err)
	}
	defer func() { _ = gz.Close() }()
	rootFS, err := os.OpenRoot(repoRoot)
	if err != nil {
		return false, fmt.Errorf("open materialized repo root: %w", err)
	}
	defer func() { _ = rootFS.Close() }()

	reader := tar.NewReader(gz)
	expandedBytes := int64(0)
	materializedBytes := int64(0)
	archiveEntries := 0
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return false, fmt.Errorf("read repository archive for %s: %w", repo, nextErr)
		}
		archiveEntries++
		if archiveEntries > maxArchiveFiles {
			return false, fmt.Errorf("repository archive for %s exceeds %d entries", repo, maxArchiveFiles)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if header.Size < 0 {
			return false, fmt.Errorf("repository archive for %s contains an invalid negative-size entry", repo)
		}
		rel, relErr := archiveRelativePath(header.Name)
		if relErr != nil {
			return false, fmt.Errorf("repository archive for %s: %w", repo, relErr)
		}
		localRel := filepath.FromSlash(rel)
		if !filepath.IsLocal(localRel) {
			return false, fmt.Errorf("repository archive for %s contains a non-local entry %q", repo, header.Name)
		}
		materialize := shouldMaterializeBlobWithSource(rel, true)
		expandedBytes, materializedBytes, err = addArchiveEntryBytes(expandedBytes, materializedBytes, header.Size, materialize)
		if err != nil {
			return false, fmt.Errorf("repository archive for %s: %w", repo, err)
		}
		if !materialize {
			continue
		}
		if header.Size > maxArchiveFileBytes {
			return false, fmt.Errorf("repository archive file %s exceeds the %d-byte limit", rel, maxArchiveFileBytes)
		}
		if err := rootFS.MkdirAll(filepath.Dir(localRel), 0o750); err != nil {
			return false, fmt.Errorf("create materialized parent: %w", err)
		}
		file, openErr := rootFS.OpenFile(localRel, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if openErr != nil {
			return false, fmt.Errorf("create materialized file %s: %w", rel, openErr)
		}
		_, copyErr := io.CopyN(file, reader, header.Size)
		closeErr := file.Close()
		if copyErr != nil {
			return false, fmt.Errorf("write materialized file %s: %w", rel, copyErr)
		}
		if closeErr != nil {
			return false, fmt.Errorf("close materialized file %s: %w", rel, closeErr)
		}
	}
	return archiveEntries == 0, nil
}

func addArchiveEntryBytes(expanded, materialized, entryBytes int64, materialize bool) (int64, int64, error) {
	if entryBytes > maxArchiveExpandedBytes-expanded {
		return expanded, materialized, fmt.Errorf("exceeds the %d-byte expanded archive limit", maxArchiveExpandedBytes)
	}
	expanded += entryBytes
	if !materialize {
		return expanded, materialized, nil
	}
	if entryBytes > maxArchiveExtractBytes-materialized {
		return expanded, materialized, fmt.Errorf("exceeds the %d-byte materialized file limit", maxArchiveExtractBytes)
	}
	return expanded, materialized + entryBytes, nil
}

func archiveRelativePath(name string) (string, error) {
	raw := strings.ReplaceAll(strings.TrimSpace(name), "\\", "/")
	if raw == "" || strings.HasPrefix(raw, "/") || strings.ContainsRune(raw, '\x00') {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	for _, part := range strings.Split(raw, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("unsafe archive entry %q", name)
		}
	}
	normalized := path.Clean(raw)
	if normalized == "." || normalized == ".." || strings.HasPrefix(normalized, "../") {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	parts := strings.Split(normalized, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid archive entry %q", name)
	}
	rel := strings.Join(parts[1:], "/")
	if rel == "" || strings.HasPrefix(rel, "/") || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("unsafe archive entry %q", name)
	}
	return rel, nil
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

func cloneSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func repoOwnershipMetadata(meta repoMeta) *source.RepoOwnershipMetadata {
	topics := cloneSortedStrings(meta.Topics)
	teams := cloneSortedStrings(meta.Teams)
	if len(topics) == 0 && len(teams) == 0 {
		return nil
	}
	return &source.RepoOwnershipMetadata{Topics: topics, Teams: teams}
}

func shouldMaterializeBlobWithSource(rel string, allowSourceMaterialization bool) bool {
	normalized := strings.Trim(strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel))), "/")
	if normalized == "" {
		return false
	}
	if hasBlockedMaterializedTraversal(normalized) {
		return false
	}

	base := path.Base(normalized)
	if isSparseDetectorCandidate(normalized, base) {
		return true
	}
	if shouldSkipMaterializedTraversal(normalized) {
		return false
	}

	switch base {
	case "agents.md", "agents.override.md", "claude.md", ".cursorrules", ".mcp.json", "mcp.json", "managed-mcp.json",
		"codeowners",
		"jenkinsfile", "go.mod", "go.sum", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
		"pyproject.toml", "poetry.lock", "uv.lock", "cargo.toml", "gemfile", "pom.xml",
		"build.gradle", "build.gradle.kts", "composer.json", "dockerfile", "gait.yaml",
		"owners.yaml", "owners.yml", "wrkr-owners.yaml", "wrkr-owners.yml",
		"service-catalog.yaml", "service-catalog.yml", "catalog-info.yaml", "catalog-info.yml":
		return true
	}
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return true
	}
	if strings.HasPrefix(base, "readme") {
		return true
	}
	if strings.HasPrefix(base, "docker-compose") || strings.HasPrefix(base, "compose.") {
		return true
	}
	if !allowSourceMaterialization || !isSparseSourceExtension(path.Ext(normalized)) {
		return false
	}
	return true
}

func isSparseDetectorCandidate(normalized, base string) bool {
	if isSparseMCPGatewayCandidate(normalized) {
		return true
	}
	if isSparseCompiledActionPath(normalized) {
		return true
	}
	if isSparseEnvCandidate(normalized) {
		return true
	}
	if isSparsePromptSurface(normalized) {
		return true
	}
	if isSparseWellKnownPath(normalized) {
		return true
	}
	if isSparseAgentCardPath(base) {
		return true
	}

	for _, prefix := range []string{
		".claude/",
		".cursor/",
		".codex/",
		".agents/",
		".github/workflows/",
		".gait/",
		".wrkr/agents/",
	} {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	if normalized == ".wrkr/detectors/extensions.json" {
		return true
	}
	if normalized == ".wrkr/owners.json" || normalized == ".wrkr/service-catalog.json" {
		return true
	}
	if strings.HasPrefix(normalized, ".vscode/") && strings.Contains(base, "mcp") {
		return true
	}
	if strings.HasPrefix(normalized, ".github/") {
		ext := path.Ext(normalized)
		if ext == ".json" || ext == ".yaml" || ext == ".yml" || strings.Contains(base, "copilot") {
			return true
		}
	}
	return false
}

func isSparseCompiledActionPath(rel string) bool {
	return strings.HasPrefix(rel, "workflows/") ||
		strings.HasPrefix(rel, "agent-plans/") ||
		strings.HasSuffix(rel, ".agent-script.json") ||
		strings.HasSuffix(rel, ".ptc.json")
}

func isSparseEnvCandidate(rel string) bool {
	return rel == ".env" || strings.HasPrefix(rel, ".env.")
}

func isSparsePromptSurface(rel string) bool {
	base := path.Base(rel)
	switch base {
	case "agents.md", "agents.override.md", "claude.md", ".cursorrules", "jenkinsfile", "skill.md":
		return true
	}
	if strings.HasPrefix(rel, ".github/workflows/") {
		return true
	}
	if strings.Contains(rel, "/skills/") && strings.HasSuffix(base, ".md") {
		return true
	}
	if strings.HasPrefix(rel, ".agents/") ||
		strings.HasPrefix(rel, ".claude/") ||
		strings.HasPrefix(rel, ".cursor/") ||
		strings.HasPrefix(rel, ".codex/") {
		return hasSparseTextLikeExtension(rel)
	}
	if strings.Contains(rel, "prompt") || strings.Contains(rel, "instruction") {
		return hasSparseTextLikeExtension(rel)
	}
	return false
}

func isSparseWellKnownPath(rel string) bool {
	return strings.HasPrefix(rel, ".well-known/") || strings.Contains(rel, "/.well-known/")
}

func isSparseAgentCardPath(base string) bool {
	return base == "agent.json" || base == "agent-card.json"
}

func hasSparseTextLikeExtension(rel string) bool {
	switch path.Ext(rel) {
	case ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh", ".py", ".js", ".ts":
		return true
	default:
		return false
	}
}

func isSparseMCPGatewayCandidate(rel string) bool {
	ext := path.Ext(rel)
	if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".toml" {
		return false
	}
	base := path.Base(rel)
	switch {
	case strings.Contains(base, "mcp-gateway"), strings.Contains(base, "mcpgateway"), strings.Contains(base, "mintmcp"):
		return true
	case strings.HasPrefix(base, "docker-compose"):
		return true
	case strings.Contains(base, "kong") && strings.Contains(rel, "mcp"):
		return true
	case strings.Contains(base, "docker") && strings.Contains(rel, "mcp"):
		return true
	default:
		return false
	}
}

func hasBlockedMaterializedTraversal(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		switch part {
		case "", ".", "..", ".git", "node_modules", "vendor", ".venv", "venv":
			return true
		}
	}
	return false
}

func shouldSkipMaterializedTraversal(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		switch part {
		case "dist", "build", "target", ".next", "coverage":
			return true
		}
	}
	return false
}

func isSparseSourceExtension(ext string) bool {
	switch strings.ToLower(strings.TrimSpace(ext)) {
	case ".go", ".html", ".htm", ".java", ".js", ".jsx", ".kt", ".mjs", ".cjs", ".mts", ".cts", ".php", ".py", ".rb", ".rs", ".ts", ".tsx":
		return true
	default:
		return false
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
	return c.doGETWithRetryLimit(ctx, endpoint, 0)
}

func (c *Connector) doGETWithRetryLimit(ctx context.Context, endpoint string, maxBytes int64) ([]byte, error) {
	return c.doGETWithRetryClient(ctx, endpoint, maxBytes, c.HTTPClient)
}

func (c *Connector) doGETWithRetryClient(ctx context.Context, endpoint string, maxBytes int64, client HTTPClient) ([]byte, error) {
	if degradeErr := c.checkDegraded(); degradeErr != nil {
		c.emitCooldown(0, degradeErr)
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

		resp, err := client.Do(req)
		retryDelay := c.jitteredBackoff(attempt)
		statusCode := 0
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				lastErr = fmt.Errorf("request timed out before the scan deadline: %v", err)
			} else {
				lastErr = fmt.Errorf("request failed: %w", err)
			}
		} else {
			c.recordResponseHeaders(resp.Header)
			reader := io.Reader(resp.Body)
			if maxBytes > 0 {
				reader = io.LimitReader(resp.Body, maxBytes+1)
			}
			body, readErr := io.ReadAll(reader)
			_ = resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("read response body: %w", readErr)
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if maxBytes > 0 && int64(len(body)) > maxBytes {
					return nil, fmt.Errorf("github response exceeds the %d-byte limit", maxBytes)
				}
				c.recordSuccess()
				return body, nil
			}
			classification := classifyResponse(resp, body)
			if !classification.Retryable {
				c.resetFailureStreak()
				return nil, formatStatusError(resp.StatusCode, classification.Message)
			}
			statusCode = resp.StatusCode
			retryDelay = c.retryDelayForResponse(resp, classification.RateLimited, attempt)
			if classification.RateLimited {
				lastErr = &RateLimitedError{
					StatusCode: resp.StatusCode,
					Attempts:   attempt + 1,
					Evidence:   classification.Evidence,
					Message:    classification.Message,
				}
			} else {
				lastErr = fmt.Errorf("github API transient status %d", resp.StatusCode)
			}
		}

		if attempt == c.MaxRetries {
			break
		}
		c.emitRetry(attempt+1, retryDelay, statusCode)
		if sleepErr := c.sleep(ctx, retryDelay); sleepErr != nil {
			return nil, sleepErr
		}
	}
	if lastErr == nil {
		lastErr = errors.New("request failed")
	}
	recordedErr := c.recordFailure(lastErr)
	c.emitCooldown(0, recordedErr)
	return nil, recordedErr
}

func (c *Connector) archiveHTTPClient() HTTPClient {
	configured, ok := c.HTTPClient.(*http.Client)
	if !ok {
		return c.HTTPClient
	}
	base, err := githubendpoint.Parse(c.BaseURL, c.endpointOptions)
	if err != nil {
		return c.HTTPClient
	}
	clone := *configured
	clone.Timeout = archiveRequestTimeout
	clone.CheckRedirect = githubendpoint.ArchiveRedirectPolicy(base)
	return &clone
}

func (c *Connector) recordResponseHeaders(header http.Header) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requestStats.Requests++
	if value, err := strconv.Atoi(strings.TrimSpace(header.Get("X-RateLimit-Limit"))); err == nil && value > 0 {
		c.requestStats.RateLimitLimit = value
	}
	if value, err := strconv.Atoi(strings.TrimSpace(header.Get("X-RateLimit-Remaining"))); err == nil && value >= 0 {
		c.requestStats.RateLimitRemaining = value
	}
	if raw := strings.TrimSpace(header.Get("X-RateLimit-Reset")); raw != "" {
		if epoch, err := strconv.ParseInt(raw, 10, 64); err == nil && epoch > 0 {
			c.requestStats.RateLimitReset = time.Unix(epoch, 0).UTC().Format(time.RFC3339)
		}
	}
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

func (c *Connector) retryDelayForResponse(resp *http.Response, rateLimited bool, attempt int) time.Duration {
	if resp == nil {
		return c.jitteredBackoff(attempt)
	}
	if !rateLimited {
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
			Err:           c.cooldownErr,
		}
	}
	c.cooldownUntil = time.Time{}
	c.consecutiveFailures = 0
	c.cooldownErr = nil
	return nil
}

func (c *Connector) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFailures = 0
	c.cooldownUntil = time.Time{}
	c.cooldownErr = nil
}

func (c *Connector) resetFailureStreak() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.consecutiveFailures = 0
	c.cooldownErr = nil
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
	c.cooldownErr = lastErr
	return &DegradedError{
		CooldownUntil: c.cooldownUntil,
		Cause:         lastErr.Error(),
		Err:           lastErr,
	}
}

func (c *Connector) emitRetry(attempt int, delay time.Duration, statusCode int) {
	if c == nil || c.onRetry == nil {
		return
	}
	c.onRetry(RetryEvent{
		Attempt:    attempt,
		StatusCode: statusCode,
		Delay:      delay,
	})
}

func (c *Connector) emitCooldown(delay time.Duration, err error) {
	if c == nil || c.onCooldown == nil {
		return
	}
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		return
	}
	wait := delay
	if wait <= 0 && !degraded.CooldownUntil.IsZero() {
		wait = time.Until(degraded.CooldownUntil)
		if wait < 0 {
			wait = 0
		}
	}
	c.onCooldown(CooldownEvent{
		Delay: wait,
		Until: degraded.CooldownUntil,
	})
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

type responseClassification struct {
	Retryable   bool
	RateLimited bool
	Evidence    string
	Message     string
}

func classifyResponse(resp *http.Response, body []byte) responseClassification {
	message := extractAPIMessage(body)
	if resp == nil {
		return responseClassification{Message: message}
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return responseClassification{
			Retryable:   true,
			RateLimited: true,
			Evidence:    summarizeRateLimitEvidence(resp, body),
			Message:     message,
		}
	case resp.StatusCode >= 500:
		return responseClassification{
			Retryable: true,
			Message:   message,
		}
	case resp.StatusCode == http.StatusForbidden:
		evidence := summarizeRateLimitEvidence(resp, body)
		if evidence == "" {
			return responseClassification{Message: message}
		}
		return responseClassification{
			Retryable:   true,
			RateLimited: true,
			Evidence:    evidence,
			Message:     message,
		}
	default:
		return responseClassification{Message: message}
	}
}

func summarizeRateLimitEvidence(resp *http.Response, body []byte) string {
	if resp == nil {
		return ""
	}

	evidence := make([]string, 0, 4)
	if strings.TrimSpace(resp.Header.Get("Retry-After")) != "" {
		evidence = append(evidence, "retry_after_header")
	}
	if strings.TrimSpace(resp.Header.Get("X-RateLimit-Reset")) != "" {
		evidence = append(evidence, "x_ratelimit_reset_header")
	}
	if strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining")) == "0" {
		evidence = append(evidence, "x_ratelimit_remaining=0")
	}
	if phrase := matchedRateLimitPhrase(body); phrase != "" {
		evidence = append(evidence, "body="+phrase)
	}
	return strings.Join(evidence, ",")
}

func matchedRateLimitPhrase(body []byte) string {
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	for _, phrase := range []string{
		"secondary rate limit",
		"rate limit exceeded",
		"rate limited",
		"rate limit",
	} {
		if strings.Contains(lower, phrase) {
			return phrase
		}
	}
	return ""
}

func extractAPIMessage(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}

	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && strings.TrimSpace(payload.Message) != "" {
		return sanitizeErrorMessage(payload.Message)
	}
	return sanitizeErrorMessage(trimmed)
}

func sanitizeErrorMessage(raw string) string {
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return ""
	}
	message := strings.Join(parts, " ")
	if len(message) > 240 {
		return message[:240] + "..."
	}
	return message
}

type statusError struct {
	StatusCode int
	Message    string
}

func (e *statusError) Error() string {
	if e == nil {
		return ""
	}
	if strings.TrimSpace(e.Message) == "" {
		return fmt.Sprintf("github API status %d", e.StatusCode)
	}
	return fmt.Sprintf("github API status %d: %s", e.StatusCode, e.Message)
}

func formatStatusError(statusCode int, message string) error {
	return &statusError{StatusCode: statusCode, Message: strings.TrimSpace(message)}
}

func isEmptyRepositoryTreeError(err error) bool {
	var statusErr *statusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusConflict {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(statusErr.Message))
	return strings.Contains(message, "repository is empty") || strings.Contains(message, "git repository is empty")
}

func isMissingRepositoryArchiveError(err error) bool {
	var statusErr *statusError
	return errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusNotFound
}

func normalizeRepo(repo string) (string, error) {
	return reponame.NormalizeRepo(repo)
}
