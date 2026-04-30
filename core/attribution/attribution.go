package attribution

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	SourceLocalGit = "local_git"
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

type Result struct {
	Source        string               `json:"source"`
	Confidence    string               `json:"confidence"`
	MissingReason string               `json:"missing_reason,omitempty"`
	PRNumber      int                  `json:"pr_number,omitempty"`
	CommitSHA     string               `json:"commit_sha,omitempty"`
	Author        string               `json:"author,omitempty"`
	Timestamp     string               `json:"timestamp,omitempty"`
	ChangedFile   string               `json:"changed_file,omitempty"`
	LineRange     *model.LocationRange `json:"line_range,omitempty"`
	ProviderURL   string               `json:"provider_url,omitempty"`
}

func Local(repoRoot, relPath string, lineRange *model.LocationRange) *Result {
	base := &Result{
		Source:      SourceLocalGit,
		Confidence:  ConfidenceLow,
		ChangedFile: filepath.ToSlash(strings.TrimSpace(relPath)),
		LineRange:   normalizeLineRange(lineRange),
	}
	repoRoot = strings.TrimSpace(repoRoot)
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if repoRoot == "" || relPath == "" {
		base.MissingReason = "location_unavailable"
		return base
	}
	if _, err := git(repoRoot, "rev-parse", "--show-toplevel"); err != nil {
		base.MissingReason = "git_metadata_unavailable"
		return base
	}

	if blame := blameRange(repoRoot, relPath, lineRange); blame != nil {
		return blame
	}
	if latest := latestCommit(repoRoot, relPath, lineRange); latest != nil {
		return latest
	}
	base.MissingReason = "history_unavailable"
	return base
}

func Merge(current, incoming *Result) *Result {
	switch {
	case current == nil:
		return clone(incoming)
	case incoming == nil:
		return clone(current)
	}
	if confidenceRank(strings.TrimSpace(incoming.Confidence)) > confidenceRank(strings.TrimSpace(current.Confidence)) {
		return clone(incoming)
	}
	if strings.TrimSpace(current.CommitSHA) == "" && strings.TrimSpace(incoming.CommitSHA) != "" {
		return clone(incoming)
	}
	return clone(current)
}

func blameRange(repoRoot, relPath string, lineRange *model.LocationRange) *Result {
	args := []string{"blame", "--porcelain"}
	if normalized := normalizeLineRange(lineRange); normalized != nil {
		args = append(args, "-L", fmt.Sprintf("%d,%d", normalized.StartLine, normalized.EndLine))
	}
	args = append(args, "--", relPath)
	out, err := git(repoRoot, args...)
	if err != nil {
		return nil
	}
	lines := strings.Split(out, "\n")
	if len(lines) == 0 {
		return nil
	}
	header := strings.Fields(strings.TrimSpace(lines[0]))
	if len(header) == 0 {
		return nil
	}
	commitSHA := strings.TrimSpace(header[0])
	if commitSHA == "" || commitSHA == strings.Repeat("0", len(commitSHA)) {
		return nil
	}
	result := &Result{
		Source:      SourceLocalGit,
		Confidence:  ConfidenceHigh,
		CommitSHA:   commitSHA,
		ChangedFile: relPath,
		LineRange:   normalizeLineRange(lineRange),
	}
	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "author "):
			result.Author = strings.TrimSpace(strings.TrimPrefix(trimmed, "author "))
		case strings.HasPrefix(trimmed, "author-time "):
			if parsed := parseUnixTimestamp(strings.TrimSpace(strings.TrimPrefix(trimmed, "author-time "))); parsed != "" {
				result.Timestamp = parsed
			}
		}
		if result.Author != "" && result.Timestamp != "" {
			break
		}
	}
	if result.Author == "" {
		return nil
	}
	return result
}

func latestCommit(repoRoot, relPath string, lineRange *model.LocationRange) *Result {
	out, err := git(repoRoot, "log", "-n", "1", "--format=%H%n%an%n%aI", "--", relPath)
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 3 {
		return nil
	}
	commitSHA := strings.TrimSpace(lines[0])
	author := strings.TrimSpace(lines[1])
	timestamp := strings.TrimSpace(lines[2])
	if commitSHA == "" || author == "" || timestamp == "" {
		return nil
	}
	return &Result{
		Source:        SourceLocalGit,
		Confidence:    ConfidenceLow,
		MissingReason: "line_range_unavailable",
		CommitSHA:     commitSHA,
		Author:        author,
		Timestamp:     timestamp,
		ChangedFile:   relPath,
		LineRange:     normalizeLineRange(lineRange),
	}
}

func git(repoRoot string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoRoot}, args...)...) // #nosec G204 -- deterministic local git metadata lookup.
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

func parseUnixTimestamp(raw string) string {
	seconds, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format(time.RFC3339)
}

func normalizeLineRange(in *model.LocationRange) *model.LocationRange {
	if in == nil {
		return nil
	}
	start := in.StartLine
	end := in.EndLine
	if start <= 0 && end <= 0 {
		return nil
	}
	if start <= 0 {
		start = end
	}
	if end <= 0 {
		end = start
	}
	if end < start {
		start, end = end, start
	}
	return &model.LocationRange{StartLine: start, EndLine: end}
}

func confidenceRank(value string) int {
	switch strings.TrimSpace(value) {
	case ConfidenceHigh:
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

func clone(in *Result) *Result {
	if in == nil {
		return nil
	}
	out := *in
	out.Source = strings.TrimSpace(out.Source)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.MissingReason = strings.TrimSpace(out.MissingReason)
	out.CommitSHA = strings.TrimSpace(out.CommitSHA)
	out.Author = strings.TrimSpace(out.Author)
	out.Timestamp = strings.TrimSpace(out.Timestamp)
	out.ChangedFile = filepath.ToSlash(strings.TrimSpace(out.ChangedFile))
	out.ProviderURL = strings.TrimSpace(out.ProviderURL)
	out.LineRange = normalizeLineRange(in.LineRange)
	return &out
}
