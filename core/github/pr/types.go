package pr

import "context"

// PullRequest is a minimal deterministic PR contract used by wrkr fix automation.
type PullRequest struct {
	Number int    `json:"number"`
	URL    string `json:"url"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Head   string `json:"head"`
	Base   string `json:"base"`
}

type CreateRequest struct {
	Title string `json:"title"`
	Head  string `json:"head"`
	Base  string `json:"base"`
	Body  string `json:"body"`
}

type UpdateRequest struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// IssueComment is a minimal deterministic PR comment contract.
type IssueComment struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

// API abstracts GitHub PR APIs for deterministic tests and retry behavior.
type API interface {
	EnsureHeadRef(ctx context.Context, owner, repo, headBranch, baseBranch string) error
	EnsureFileContent(ctx context.Context, owner, repo, branch, filePath, commitMessage string, content []byte) (bool, error)
	ListOpenByHead(ctx context.Context, owner, repo, headBranch, baseBranch string) ([]PullRequest, error)
	Create(ctx context.Context, owner, repo string, req CreateRequest) (PullRequest, error)
	Update(ctx context.Context, owner, repo string, number int, req UpdateRequest) (PullRequest, error)
}

// CommentAPI abstracts issue comment APIs for deterministic PR comment upserts.
type CommentAPI interface {
	ListIssueComments(ctx context.Context, owner, repo string, issueNumber int) ([]IssueComment, error)
	CreateIssueComment(ctx context.Context, owner, repo string, issueNumber int, body string) (IssueComment, error)
	UpdateIssueComment(ctx context.Context, owner, repo string, commentID int, body string) (IssueComment, error)
}

type UpsertInput struct {
	Owner       string
	Repo        string
	HeadBranch  string
	BaseBranch  string
	Title       string
	Body        string
	Fingerprint string
}

type UpsertResult struct {
	Action      string      `json:"action"`
	PullRequest PullRequest `json:"pull_request"`
}

type UpsertIssueCommentInput struct {
	Owner       string
	Repo        string
	IssueNumber int
	Body        string
	Fingerprint string
}

type UpsertIssueCommentResult struct {
	Action  string       `json:"action"`
	Comment IssueComment `json:"comment"`
}
