package pr

import (
	"context"
	"fmt"
	"testing"
)

func TestUpsertIssueCommentCreateThenNoop(t *testing.T) {
	t.Parallel()

	api := &fakeCommentAPI{}
	in := UpsertIssueCommentInput{
		Owner:       "acme",
		Repo:        "backend",
		IssueNumber: 12,
		Body:        "wrkr PR mode comment",
		Fingerprint: "wrkr-action-pr-mode-v1",
	}
	first, err := UpsertIssueComment(context.Background(), api, in)
	if err != nil {
		t.Fatalf("first upsert issue comment: %v", err)
	}
	if first.Action != "created" {
		t.Fatalf("expected created action, got %q", first.Action)
	}

	second, err := UpsertIssueComment(context.Background(), api, in)
	if err != nil {
		t.Fatalf("second upsert issue comment: %v", err)
	}
	if second.Action != "noop" {
		t.Fatalf("expected noop action, got %q", second.Action)
	}
	if api.createCalls != 1 {
		t.Fatalf("expected one create call, got %d", api.createCalls)
	}
}

func TestUpsertIssueCommentUpdatesWhenBodyChanges(t *testing.T) {
	t.Parallel()

	api := &fakeCommentAPI{}
	in := UpsertIssueCommentInput{
		Owner:       "acme",
		Repo:        "backend",
		IssueNumber: 12,
		Body:        "wrkr comment v1",
		Fingerprint: "wrkr-action-pr-mode-v1",
	}
	if _, err := UpsertIssueComment(context.Background(), api, in); err != nil {
		t.Fatalf("seed comment: %v", err)
	}

	in.Body = "wrkr comment v2"
	updated, err := UpsertIssueComment(context.Background(), api, in)
	if err != nil {
		t.Fatalf("update comment: %v", err)
	}
	if updated.Action != "updated" {
		t.Fatalf("expected updated action, got %q", updated.Action)
	}
	if api.updateCalls != 1 {
		t.Fatalf("expected one update call, got %d", api.updateCalls)
	}
}

type fakeCommentAPI struct {
	comments    []IssueComment
	createCalls int
	updateCalls int
}

func (f *fakeCommentAPI) ListIssueComments(_ context.Context, _ string, _ string, _ int) ([]IssueComment, error) {
	out := make([]IssueComment, len(f.comments))
	copy(out, f.comments)
	return out, nil
}

func (f *fakeCommentAPI) CreateIssueComment(_ context.Context, _ string, _ string, _ int, body string) (IssueComment, error) {
	f.createCalls++
	comment := IssueComment{ID: 100 + f.createCalls, Body: body}
	f.comments = append(f.comments, comment)
	return comment, nil
}

func (f *fakeCommentAPI) UpdateIssueComment(_ context.Context, _ string, _ string, commentID int, body string) (IssueComment, error) {
	f.updateCalls++
	for i := range f.comments {
		if f.comments[i].ID != commentID {
			continue
		}
		f.comments[i].Body = body
		return f.comments[i], nil
	}
	return IssueComment{}, fmt.Errorf("comment %d not found", commentID)
}
