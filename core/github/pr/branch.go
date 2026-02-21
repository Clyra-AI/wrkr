package pr

import (
	"fmt"
	"regexp"
	"strings"
)

var nonSlug = regexp.MustCompile(`[^a-z0-9-]+`)

// BranchName returns a deterministic branch name for remediation runs.
func BranchName(botIdentity, repoName, scheduleKey, fingerprint string) string {
	bot := sanitizeSlug(botIdentity)
	if bot == "" {
		bot = "wrkr-bot"
	}
	repo := sanitizeSlug(repoName)
	if repo == "" {
		repo = "repo"
	}
	schedule := sanitizeSlug(scheduleKey)
	if schedule == "" {
		schedule = "adhoc"
	}
	fp := sanitizeSlug(fingerprint)
	if len(fp) > 12 {
		fp = fp[:12]
	}
	if fp == "" {
		fp = "nohash"
	}

	branch := fmt.Sprintf("%s/remediation/%s/%s/%s", bot, repo, schedule, fp)
	if len(branch) <= 120 {
		return branch
	}
	maxRepoLen := 120 - len(fmt.Sprintf("%s/remediation//%s/%s", bot, schedule, fp))
	if maxRepoLen < 4 {
		maxRepoLen = 4
	}
	if len(repo) > maxRepoLen {
		repo = repo[:maxRepoLen]
	}
	return fmt.Sprintf("%s/remediation/%s/%s/%s", bot, repo, schedule, fp)
}

func sanitizeSlug(in string) string {
	value := strings.ToLower(strings.TrimSpace(in))
	value = strings.ReplaceAll(value, "/", "-")
	value = nonSlug.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return ""
	}
	value = strings.ReplaceAll(value, "--", "-")
	value = strings.ReplaceAll(value, "--", "-")
	return value
}
