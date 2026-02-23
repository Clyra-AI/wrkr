package pr

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func UpsertIssueComment(ctx context.Context, api CommentAPI, in UpsertIssueCommentInput) (UpsertIssueCommentResult, error) {
	if strings.TrimSpace(in.Owner) == "" || strings.TrimSpace(in.Repo) == "" {
		return UpsertIssueCommentResult{}, fmt.Errorf("owner/repo are required")
	}
	if in.IssueNumber <= 0 {
		return UpsertIssueCommentResult{}, fmt.Errorf("issue number must be positive")
	}

	body := ensureFingerprintMarker(in.Body, in.Fingerprint)
	comments, err := api.ListIssueComments(ctx, in.Owner, in.Repo, in.IssueNumber)
	if err != nil {
		return UpsertIssueCommentResult{}, err
	}
	sort.Slice(comments, func(i, j int) bool { return comments[i].ID < comments[j].ID })

	for _, comment := range comments {
		if !hasFingerprint(comment.Body, in.Fingerprint) {
			continue
		}
		if strings.TrimSpace(comment.Body) == strings.TrimSpace(body) {
			return UpsertIssueCommentResult{Action: "noop", Comment: comment}, nil
		}
		updated, updateErr := api.UpdateIssueComment(ctx, in.Owner, in.Repo, comment.ID, body)
		if updateErr != nil {
			return UpsertIssueCommentResult{}, updateErr
		}
		return UpsertIssueCommentResult{Action: "updated", Comment: updated}, nil
	}

	created, createErr := api.CreateIssueComment(ctx, in.Owner, in.Repo, in.IssueNumber, body)
	if createErr != nil {
		return UpsertIssueCommentResult{}, createErr
	}
	return UpsertIssueCommentResult{Action: "created", Comment: created}, nil
}
