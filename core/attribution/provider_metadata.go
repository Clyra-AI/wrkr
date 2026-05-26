package attribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	SourceGitHubEvent = "github_event_payload"
	SourceGitLabEvent = "gitlab_merge_request_event"
	SourceSidecar     = "source_metadata"
)

type Context struct {
	RepoRoot        string
	Candidates      []Candidate
	ControlMetadata map[string]ControlMetadata
}

type Candidate struct {
	Source       string
	PRNumber     int
	CommitSHA    string
	Author       string
	Timestamp    string
	ProviderURL  string
	ChangedFiles []string
}

type sourceMetadataPayload struct {
	Source       string   `json:"source"`
	Provider     string   `json:"provider"`
	PRNumber     int      `json:"pr_number"`
	CommitSHA    string   `json:"commit_sha"`
	Author       string   `json:"author"`
	Timestamp    string   `json:"timestamp"`
	ProviderURL  string   `json:"provider_url"`
	ChangedFiles []string `json:"changed_files"`
	Files        []string `json:"files"`
}

func LoadContext(repoRoot string) Context {
	return LoadContextAt(repoRoot, time.Time{})
}

func LoadContextAt(repoRoot string, generatedAt time.Time) Context {
	repoRoot = strings.TrimSpace(repoRoot)
	return Context{
		RepoRoot:        repoRoot,
		Candidates:      loadCandidates(repoRoot),
		ControlMetadata: loadControlMetadataAt(repoRoot, generatedAt),
	}
}

func Resolve(ctx Context, relPath string, lineRange *model.LocationRange) *Result {
	if result := fromCandidates(ctx.Candidates, relPath, lineRange); result != nil {
		return result
	}
	return Local(ctx.RepoRoot, relPath, lineRange)
}

func loadCandidates(repoRoot string) []Candidate {
	if strings.TrimSpace(repoRoot) == "" {
		return nil
	}
	loaders := []func(string) *Candidate{
		loadSidecarMetadata,
		loadGitHubEventMetadata,
		loadGitLabEventMetadata,
	}
	out := make([]Candidate, 0, len(loaders))
	for _, loader := range loaders {
		if candidate := loader(repoRoot); candidate != nil {
			out = append(out, *candidate)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if candidatePriority(out[i]) != candidatePriority(out[j]) {
			return candidatePriority(out[i]) < candidatePriority(out[j])
		}
		if out[i].Timestamp != out[j].Timestamp {
			return out[i].Timestamp > out[j].Timestamp
		}
		if out[i].PRNumber != out[j].PRNumber {
			return out[i].PRNumber > out[j].PRNumber
		}
		return out[i].Source < out[j].Source
	})
	return out
}

func fromCandidates(candidates []Candidate, relPath string, lineRange *model.LocationRange) *Result {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if relPath == "" {
		return nil
	}
	for _, candidate := range candidates {
		if result := resultForCandidate(candidate, relPath, lineRange); result != nil {
			return result
		}
	}
	for _, candidate := range candidates {
		if len(candidate.ChangedFiles) == 0 {
			return resultForCandidate(candidate, relPath, lineRange)
		}
	}
	return nil
}

func resultForCandidate(candidate Candidate, relPath string, lineRange *model.LocationRange) *Result {
	if relPath == "" {
		return nil
	}
	changedFile := relPath
	if len(candidate.ChangedFiles) > 0 {
		matched := false
		for _, file := range candidate.ChangedFiles {
			if filepath.ToSlash(strings.TrimSpace(file)) == relPath {
				matched = true
				changedFile = filepath.ToSlash(strings.TrimSpace(file))
				break
			}
		}
		if !matched {
			return nil
		}
	}
	return &Result{
		Source:      strings.TrimSpace(candidate.Source),
		Confidence:  ConfidenceHigh,
		PRNumber:    candidate.PRNumber,
		CommitSHA:   strings.TrimSpace(candidate.CommitSHA),
		Author:      strings.TrimSpace(candidate.Author),
		Timestamp:   normalizeMetadataTimestamp(candidate.Timestamp),
		ChangedFile: changedFile,
		LineRange:   normalizeLineRange(lineRange),
		ProviderURL: strings.TrimSpace(candidate.ProviderURL),
	}
}

func loadSidecarMetadata(repoRoot string) *Candidate {
	payload, err := os.ReadFile(filepath.Join(repoRoot, ".wrkr", "provenance", "source-metadata.json")) // #nosec G304 -- deterministic local provenance sidecar under the scanned repo root.
	if err != nil {
		return nil
	}
	var decoded sourceMetadataPayload
	if json.Unmarshal(payload, &decoded) != nil {
		return nil
	}
	files := decoded.ChangedFiles
	if len(files) == 0 {
		files = decoded.Files
	}
	source := strings.TrimSpace(decoded.Source)
	if source == "" {
		source = SourceSidecar
	}
	return &Candidate{
		Source:       source,
		PRNumber:     decoded.PRNumber,
		CommitSHA:    strings.TrimSpace(decoded.CommitSHA),
		Author:       strings.TrimSpace(decoded.Author),
		Timestamp:    strings.TrimSpace(decoded.Timestamp),
		ProviderURL:  strings.TrimSpace(decoded.ProviderURL),
		ChangedFiles: normalizeChangedFiles(files),
	}
}

func loadGitHubEventMetadata(repoRoot string) *Candidate {
	payload, err := os.ReadFile(filepath.Join(repoRoot, ".wrkr", "provenance", "github-event.json")) // #nosec G304 -- deterministic local GitHub event payload under the scanned repo root.
	if err != nil {
		return nil
	}
	var decoded struct {
		PullRequest struct {
			Number    int    `json:"number"`
			HTMLURL   string `json:"html_url"`
			UpdatedAt string `json:"updated_at"`
			User      struct {
				Login string `json:"login"`
			} `json:"user"`
			Head struct {
				SHA string `json:"sha"`
			} `json:"head"`
		} `json:"pull_request"`
		Commits []struct {
			Added    []string `json:"added"`
			Modified []string `json:"modified"`
			Removed  []string `json:"removed"`
		} `json:"commits"`
	}
	if json.Unmarshal(payload, &decoded) != nil {
		return nil
	}
	changedFiles := []string{}
	for _, commit := range decoded.Commits {
		changedFiles = append(changedFiles, commit.Added...)
		changedFiles = append(changedFiles, commit.Modified...)
		changedFiles = append(changedFiles, commit.Removed...)
	}
	return &Candidate{
		Source:       SourceGitHubEvent,
		PRNumber:     decoded.PullRequest.Number,
		CommitSHA:    strings.TrimSpace(decoded.PullRequest.Head.SHA),
		Author:       strings.TrimSpace(decoded.PullRequest.User.Login),
		Timestamp:    strings.TrimSpace(decoded.PullRequest.UpdatedAt),
		ProviderURL:  strings.TrimSpace(decoded.PullRequest.HTMLURL),
		ChangedFiles: normalizeChangedFiles(changedFiles),
	}
}

func loadGitLabEventMetadata(repoRoot string) *Candidate {
	payload, err := os.ReadFile(filepath.Join(repoRoot, ".wrkr", "provenance", "gitlab-event.json")) // #nosec G304 -- deterministic local GitLab event payload under the scanned repo root.
	if err != nil {
		return nil
	}
	var decoded struct {
		User struct {
			Name     string `json:"name"`
			Username string `json:"username"`
		} `json:"user"`
		ObjectAttributes struct {
			IID        int    `json:"iid"`
			URL        string `json:"url"`
			UpdatedAt  string `json:"updated_at"`
			LastCommit struct {
				ID string `json:"id"`
			} `json:"last_commit"`
		} `json:"object_attributes"`
		Commits []struct {
			Added    []string `json:"added"`
			Modified []string `json:"modified"`
			Removed  []string `json:"removed"`
		} `json:"commits"`
		Changes struct {
			ModifiedPaths []string `json:"modified_paths"`
		} `json:"changes"`
	}
	if json.Unmarshal(payload, &decoded) != nil {
		return nil
	}
	changedFiles := append([]string(nil), decoded.Changes.ModifiedPaths...)
	for _, commit := range decoded.Commits {
		changedFiles = append(changedFiles, commit.Added...)
		changedFiles = append(changedFiles, commit.Modified...)
		changedFiles = append(changedFiles, commit.Removed...)
	}
	author := strings.TrimSpace(decoded.User.Username)
	if author == "" {
		author = strings.TrimSpace(decoded.User.Name)
	}
	return &Candidate{
		Source:       SourceGitLabEvent,
		PRNumber:     decoded.ObjectAttributes.IID,
		CommitSHA:    strings.TrimSpace(decoded.ObjectAttributes.LastCommit.ID),
		Author:       author,
		Timestamp:    strings.TrimSpace(decoded.ObjectAttributes.UpdatedAt),
		ProviderURL:  strings.TrimSpace(decoded.ObjectAttributes.URL),
		ChangedFiles: normalizeChangedFiles(changedFiles),
	}
}

func normalizeChangedFiles(files []string) []string {
	if len(files) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(files))
	for _, file := range files {
		normalized := filepath.ToSlash(strings.TrimSpace(file))
		if normalized == "" {
			continue
		}
		if _, ok := set[normalized]; ok {
			continue
		}
		set[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func candidatePriority(candidate Candidate) int {
	switch strings.TrimSpace(candidate.Source) {
	case SourceSidecar:
		return 0
	case SourceGitHubEvent:
		return 1
	case SourceGitLabEvent:
		return 2
	default:
		return 3
	}
}

func normalizeMetadataTimestamp(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC().Format(time.RFC3339)
	}
	return value
}
