package pr

import (
	"context"
	"fmt"
	"testing"
)

func TestBranchNameDeterministic(t *testing.T) {
	t.Parallel()

	got := BranchName("wrkr-bot", "acme/backend", "weekly", "abcdef1234567890")
	want := "wrkr-bot/remediation/acme-backend/weekly/abcdef123456"
	if got != want {
		t.Fatalf("unexpected branch\nwant=%q\ngot=%q", want, got)
	}
}

func TestUpsertCreateThenNoopIdempotent(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{}
	in := UpsertInput{
		Owner:       "acme",
		Repo:        "backend",
		HeadBranch:  "wrkr-bot/remediation/backend/weekly/abc",
		BaseBranch:  "main",
		Title:       "wrkr remediation",
		Body:        "summary",
		Fingerprint: "abc123",
	}

	first, err := Upsert(context.Background(), api, in)
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.Action != "created" {
		t.Fatalf("expected created action, got %q", first.Action)
	}

	second, err := Upsert(context.Background(), api, in)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if second.Action != "noop" {
		t.Fatalf("expected noop action on identical rerun, got %q", second.Action)
	}
	if api.createCalls != 1 {
		t.Fatalf("expected one create call, got %d", api.createCalls)
	}
	if api.ensureHeadCalls != 2 {
		t.Fatalf("expected ensure-head call per run, got %d", api.ensureHeadCalls)
	}
}

func TestUpsertUpdatesWhenFingerprintChanges(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{}
	in := UpsertInput{
		Owner:       "acme",
		Repo:        "backend",
		HeadBranch:  "wrkr-bot/remediation/backend/weekly/abc",
		BaseBranch:  "main",
		Title:       "wrkr remediation",
		Body:        "summary",
		Fingerprint: "abc123",
	}
	if _, err := Upsert(context.Background(), api, in); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}

	in.Fingerprint = "def456"
	in.Body = "summary updated"
	updated, err := Upsert(context.Background(), api, in)
	if err != nil {
		t.Fatalf("update upsert: %v", err)
	}
	if updated.Action != "updated" {
		t.Fatalf("expected updated action, got %q", updated.Action)
	}
	if api.updateCalls != 1 {
		t.Fatalf("expected one update call, got %d", api.updateCalls)
	}
}

func TestUpsertStopsWhenHeadRefEnsureFails(t *testing.T) {
	t.Parallel()

	api := &fakeAPI{ensureHeadErr: fmt.Errorf("head ref missing")}
	in := UpsertInput{
		Owner:       "acme",
		Repo:        "backend",
		HeadBranch:  "wrkr-bot/remediation/backend/weekly/abc",
		BaseBranch:  "main",
		Title:       "wrkr remediation",
		Body:        "summary",
		Fingerprint: "abc123",
	}

	_, err := Upsert(context.Background(), api, in)
	if err == nil {
		t.Fatal("expected ensure-head failure to stop upsert")
	}
	if api.createCalls != 0 {
		t.Fatalf("expected no create call on ensure-head failure, got %d", api.createCalls)
	}
}

type fakeAPI struct {
	prs             []PullRequest
	createCalls     int
	updateCalls     int
	ensureHeadCalls int
	ensureHeadErr   error
}

func (f *fakeAPI) EnsureHeadRef(_ context.Context, _ string, _ string, _ string, _ string) error {
	f.ensureHeadCalls++
	return f.ensureHeadErr
}

func (f *fakeAPI) EnsureFileContent(_ context.Context, _ string, _ string, _ string, _ string, _ string, _ []byte) (bool, error) {
	return false, nil
}

func (f *fakeAPI) ListOpenByHead(_ context.Context, _ string, _ string, headBranch, baseBranch string) ([]PullRequest, error) {
	out := make([]PullRequest, 0)
	for _, item := range f.prs {
		if item.Head == headBranch && item.Base == baseBranch {
			out = append(out, item)
		}
	}
	return out, nil
}

func (f *fakeAPI) Create(_ context.Context, _ string, _ string, req CreateRequest) (PullRequest, error) {
	f.createCalls++
	created := PullRequest{
		Number: 100 + f.createCalls,
		URL:    fmt.Sprintf("https://example.test/pr/%d", 100+f.createCalls),
		Title:  req.Title,
		Body:   req.Body,
		Head:   req.Head,
		Base:   req.Base,
	}
	f.prs = append(f.prs, created)
	return created, nil
}

func (f *fakeAPI) Update(_ context.Context, _ string, _ string, number int, req UpdateRequest) (PullRequest, error) {
	f.updateCalls++
	for i := range f.prs {
		if f.prs[i].Number != number {
			continue
		}
		f.prs[i].Title = req.Title
		f.prs[i].Body = req.Body
		return f.prs[i], nil
	}
	return PullRequest{}, fmt.Errorf("pr %d not found", number)
}
