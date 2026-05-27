package attribution

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	SourceProviderProvenance = "provider_pr_mr_provenance"
	SourceGitHubEvent        = "github_event_payload"
	SourceGitLabEvent        = "gitlab_merge_request_event"
	SourceSidecar            = "source_metadata"
)

type Context struct {
	RepoRoot        string
	Candidates      []Candidate
	ControlMetadata map[string]ControlMetadata
}

type Candidate struct {
	Source       string
	Provider     string
	Reference    string
	PRNumber     int
	CommitSHA    string
	Author       string
	Timestamp    string
	ProviderURL  string
	ChangedFiles []string
	Provenance   *Provenance
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
	loaders := []func(string) []Candidate{
		loadProviderProvenanceCandidates,
		loadSidecarMetadataCandidates,
		loadGitHubEventMetadataCandidates,
		loadGitLabEventMetadataCandidates,
	}
	out := make([]Candidate, 0, len(loaders))
	for _, loader := range loaders {
		out = append(out, loader(repoRoot)...)
	}
	normalized := make([]Candidate, 0, len(out))
	for _, candidate := range out {
		candidate.Source = strings.TrimSpace(candidate.Source)
		candidate.Provider = strings.TrimSpace(candidate.Provider)
		candidate.Reference = strings.TrimSpace(candidate.Reference)
		candidate.CommitSHA = strings.TrimSpace(candidate.CommitSHA)
		candidate.Author = strings.TrimSpace(candidate.Author)
		candidate.Timestamp = strings.TrimSpace(candidate.Timestamp)
		candidate.ProviderURL = strings.TrimSpace(candidate.ProviderURL)
		candidate.ChangedFiles = normalizeChangedFiles(candidate.ChangedFiles)
		candidate.Provenance = NormalizeProvenance(candidate.Provenance)
		if candidate.Provenance != nil {
			if candidate.Provider == "" {
				candidate.Provider = strings.TrimSpace(candidate.Provenance.Provider)
			}
			if candidate.Reference == "" {
				candidate.Reference = strings.TrimSpace(candidate.Provenance.Reference)
			}
			if candidate.ProviderURL == "" {
				candidate.ProviderURL = strings.TrimSpace(candidate.Provenance.ProviderURL)
			}
			if len(candidate.ChangedFiles) == 0 {
				candidate.ChangedFiles = append([]string(nil), candidate.Provenance.ChangedFiles...)
			}
		}
		normalized = append(normalized, candidate)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if candidatePriority(normalized[i]) != candidatePriority(normalized[j]) {
			return candidatePriority(normalized[i]) < candidatePriority(normalized[j])
		}
		if normalized[i].Timestamp != normalized[j].Timestamp {
			return normalized[i].Timestamp > normalized[j].Timestamp
		}
		if normalized[i].PRNumber != normalized[j].PRNumber {
			return normalized[i].PRNumber > normalized[j].PRNumber
		}
		return normalized[i].Source < normalized[j].Source
	})
	return normalized
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
		Provider:    strings.TrimSpace(candidate.Provider),
		Reference:   strings.TrimSpace(candidate.Reference),
		PRNumber:    candidate.PRNumber,
		CommitSHA:   strings.TrimSpace(candidate.CommitSHA),
		Author:      strings.TrimSpace(candidate.Author),
		Timestamp:   normalizeMetadataTimestamp(candidate.Timestamp),
		ChangedFile: changedFile,
		LineRange:   normalizeLineRange(lineRange),
		ProviderURL: strings.TrimSpace(candidate.ProviderURL),
		Provenance:  CloneProvenance(candidate.Provenance),
	}
}

func loadSidecarMetadataCandidates(repoRoot string) []Candidate {
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
	return []Candidate{{
		Source:       source,
		Provider:     strings.TrimSpace(decoded.Provider),
		Reference:    defaultReferenceForKind("pull_request", decoded.PRNumber),
		PRNumber:     decoded.PRNumber,
		CommitSHA:    strings.TrimSpace(decoded.CommitSHA),
		Author:       strings.TrimSpace(decoded.Author),
		Timestamp:    strings.TrimSpace(decoded.Timestamp),
		ProviderURL:  strings.TrimSpace(decoded.ProviderURL),
		ChangedFiles: normalizeChangedFiles(files),
		Provenance: NormalizeProvenance(&Provenance{
			Provider:     strings.TrimSpace(decoded.Provider),
			Kind:         "pull_request",
			Reference:    defaultReferenceForKind("pull_request", decoded.PRNumber),
			Number:       decoded.PRNumber,
			ProviderURL:  strings.TrimSpace(decoded.ProviderURL),
			HeadSHA:      strings.TrimSpace(decoded.CommitSHA),
			Author:       strings.TrimSpace(decoded.Author),
			UpdatedAt:    strings.TrimSpace(decoded.Timestamp),
			ChangedFiles: normalizeChangedFiles(files),
			MissingEvidence: []string{
				"reviewers_missing",
				"approvals_missing",
				"checks_missing",
				"deployments_missing",
				"branch_protection_missing",
				"environment_gates_missing",
			},
		}),
	}}
}

func loadGitHubEventMetadataCandidates(repoRoot string) []Candidate {
	payload, err := os.ReadFile(filepath.Join(repoRoot, ".wrkr", "provenance", "github-event.json")) // #nosec G304 -- deterministic local GitHub event payload under the scanned repo root.
	if err != nil {
		return nil
	}
	var decoded struct {
		PullRequest struct {
			Number    int    `json:"number"`
			Title     string `json:"title"`
			HTMLURL   string `json:"html_url"`
			UpdatedAt string `json:"updated_at"`
			User      struct {
				Login string `json:"login"`
			} `json:"user"`
			Head struct {
				SHA string `json:"sha"`
				Ref string `json:"ref"`
			} `json:"head"`
			Base struct {
				Ref string `json:"ref"`
			} `json:"base"`
			MergedBy struct {
				Login string `json:"login"`
			} `json:"merged_by"`
			MergeCommitSHA string `json:"merge_commit_sha"`
			Merged         bool   `json:"merged"`
		} `json:"pull_request"`
		Commits []struct {
			Added    []string `json:"added"`
			Modified []string `json:"modified"`
			Removed  []string `json:"removed"`
		} `json:"commits"`
		Reviews           []provenanceActorPayload            `json:"reviews"`
		Approvals         []provenanceActorPayload            `json:"approvals"`
		CheckRuns         []provenanceCheckPayload            `json:"check_runs"`
		Deployments       []provenanceDeploymentPayload       `json:"deployments"`
		BranchProtections []provenanceBranchProtectionPayload `json:"branch_protections"`
		EnvironmentGates  []provenanceEnvironmentGatePayload  `json:"environment_gates"`
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
	kind := "pull_request"
	return []Candidate{{
		Source:       SourceGitHubEvent,
		Provider:     "github",
		Reference:    defaultReferenceForKind(kind, decoded.PullRequest.Number),
		PRNumber:     decoded.PullRequest.Number,
		CommitSHA:    strings.TrimSpace(decoded.PullRequest.Head.SHA),
		Author:       strings.TrimSpace(decoded.PullRequest.User.Login),
		Timestamp:    strings.TrimSpace(decoded.PullRequest.UpdatedAt),
		ProviderURL:  strings.TrimSpace(decoded.PullRequest.HTMLURL),
		ChangedFiles: normalizeChangedFiles(changedFiles),
		Provenance: NormalizeProvenance(&Provenance{
			Provider:          "github",
			Kind:              kind,
			Reference:         defaultReferenceForKind(kind, decoded.PullRequest.Number),
			Number:            decoded.PullRequest.Number,
			Title:             strings.TrimSpace(decoded.PullRequest.Title),
			ProviderURL:       strings.TrimSpace(decoded.PullRequest.HTMLURL),
			HeadSHA:           strings.TrimSpace(decoded.PullRequest.Head.SHA),
			MergeCommitSHA:    strings.TrimSpace(decoded.PullRequest.MergeCommitSHA),
			Author:            strings.TrimSpace(decoded.PullRequest.User.Login),
			UpdatedAt:         strings.TrimSpace(decoded.PullRequest.UpdatedAt),
			BaseBranch:        strings.TrimSpace(decoded.PullRequest.Base.Ref),
			HeadBranch:        strings.TrimSpace(decoded.PullRequest.Head.Ref),
			MergedBy:          strings.TrimSpace(decoded.PullRequest.MergedBy.Login),
			MergeState:        githubMergeState(decoded.PullRequest.Merged),
			ChangedFiles:      normalizeChangedFiles(changedFiles),
			Reviewers:         normalizeProvenanceActors(decoded.Reviews),
			Approvals:         normalizeProvenanceActors(decoded.Approvals),
			Checks:            normalizeProvenanceChecks(decoded.CheckRuns),
			Deployments:       normalizeProvenanceDeployments(decoded.Deployments),
			BranchProtections: normalizeProvenanceBranchProtections(decoded.BranchProtections),
			EnvironmentGates:  normalizeProvenanceEnvironmentGates(decoded.EnvironmentGates),
		}),
	}}
}

func loadGitLabEventMetadataCandidates(repoRoot string) []Candidate {
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
			IID            int    `json:"iid"`
			Title          string `json:"title"`
			URL            string `json:"url"`
			UpdatedAt      string `json:"updated_at"`
			SourceBranch   string `json:"source_branch"`
			TargetBranch   string `json:"target_branch"`
			MergeCommitSHA string `json:"merge_commit_sha"`
			MergeStatus    string `json:"merge_status"`
			LastCommit     struct {
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
		Reviewers         []provenanceActorPayload            `json:"reviewers"`
		Approvals         []provenanceActorPayload            `json:"approvals"`
		Pipelines         []provenanceCheckPayload            `json:"pipelines"`
		Deployments       []provenanceDeploymentPayload       `json:"deployments"`
		BranchProtections []provenanceBranchProtectionPayload `json:"branch_protections"`
		EnvironmentGates  []provenanceEnvironmentGatePayload  `json:"environment_gates"`
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
	kind := "merge_request"
	return []Candidate{{
		Source:       SourceGitLabEvent,
		Provider:     "gitlab",
		Reference:    defaultReferenceForKind(kind, decoded.ObjectAttributes.IID),
		PRNumber:     decoded.ObjectAttributes.IID,
		CommitSHA:    strings.TrimSpace(decoded.ObjectAttributes.LastCommit.ID),
		Author:       author,
		Timestamp:    strings.TrimSpace(decoded.ObjectAttributes.UpdatedAt),
		ProviderURL:  strings.TrimSpace(decoded.ObjectAttributes.URL),
		ChangedFiles: normalizeChangedFiles(changedFiles),
		Provenance: NormalizeProvenance(&Provenance{
			Provider:          "gitlab",
			Kind:              kind,
			Reference:         defaultReferenceForKind(kind, decoded.ObjectAttributes.IID),
			Number:            decoded.ObjectAttributes.IID,
			Title:             strings.TrimSpace(decoded.ObjectAttributes.Title),
			ProviderURL:       strings.TrimSpace(decoded.ObjectAttributes.URL),
			HeadSHA:           strings.TrimSpace(decoded.ObjectAttributes.LastCommit.ID),
			MergeCommitSHA:    strings.TrimSpace(decoded.ObjectAttributes.MergeCommitSHA),
			Author:            author,
			UpdatedAt:         strings.TrimSpace(decoded.ObjectAttributes.UpdatedAt),
			BaseBranch:        strings.TrimSpace(decoded.ObjectAttributes.TargetBranch),
			HeadBranch:        strings.TrimSpace(decoded.ObjectAttributes.SourceBranch),
			MergeState:        strings.TrimSpace(decoded.ObjectAttributes.MergeStatus),
			ChangedFiles:      normalizeChangedFiles(changedFiles),
			Reviewers:         normalizeProvenanceActors(decoded.Reviewers),
			Approvals:         normalizeProvenanceActors(decoded.Approvals),
			Checks:            normalizeProvenanceChecks(decoded.Pipelines),
			Deployments:       normalizeProvenanceDeployments(decoded.Deployments),
			BranchProtections: normalizeProvenanceBranchProtections(decoded.BranchProtections),
			EnvironmentGates:  normalizeProvenanceEnvironmentGates(decoded.EnvironmentGates),
		}),
	}}
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
	case SourceProviderProvenance:
		return 0
	case SourceSidecar:
		return 1
	case SourceGitHubEvent:
		return 2
	case SourceGitLabEvent:
		return 3
	default:
		return 4
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

func defaultReferenceForKind(kind string, number int) string {
	switch strings.TrimSpace(kind) {
	case "merge_request":
		if number > 0 {
			return "mr/" + strings.TrimSpace(strconv.Itoa(number))
		}
	default:
		if number > 0 {
			return "pr/" + strings.TrimSpace(strconv.Itoa(number))
		}
	}
	return ""
}

func githubMergeState(merged bool) string {
	if merged {
		return "merged"
	}
	return "open"
}
