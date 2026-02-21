package pr

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func Upsert(ctx context.Context, api API, in UpsertInput) (UpsertResult, error) {
	if strings.TrimSpace(in.Owner) == "" || strings.TrimSpace(in.Repo) == "" {
		return UpsertResult{}, fmt.Errorf("owner/repo are required")
	}
	if strings.TrimSpace(in.HeadBranch) == "" || strings.TrimSpace(in.BaseBranch) == "" {
		return UpsertResult{}, fmt.Errorf("head/base branches are required")
	}
	if strings.TrimSpace(in.Title) == "" {
		return UpsertResult{}, fmt.Errorf("title is required")
	}

	body := ensureFingerprintMarker(in.Body, in.Fingerprint)
	existing, err := api.ListOpenByHead(ctx, in.Owner, in.Repo, in.HeadBranch, in.BaseBranch)
	if err != nil {
		return UpsertResult{}, err
	}
	if len(existing) > 0 {
		sort.Slice(existing, func(i, j int) bool { return existing[i].Number < existing[j].Number })
		current := existing[0]
		if hasFingerprint(current.Body, in.Fingerprint) && strings.TrimSpace(current.Title) == strings.TrimSpace(in.Title) {
			return UpsertResult{Action: "noop", PullRequest: current}, nil
		}
		updated, err := api.Update(ctx, in.Owner, in.Repo, current.Number, UpdateRequest{Title: in.Title, Body: body})
		if err != nil {
			return UpsertResult{}, err
		}
		return UpsertResult{Action: "updated", PullRequest: updated}, nil
	}

	created, err := api.Create(ctx, in.Owner, in.Repo, CreateRequest{
		Title: in.Title,
		Head:  in.HeadBranch,
		Base:  in.BaseBranch,
		Body:  body,
	})
	if err != nil {
		return UpsertResult{}, err
	}
	return UpsertResult{Action: "created", PullRequest: created}, nil
}

func ensureFingerprintMarker(body, fingerprint string) string {
	trimmedFP := strings.TrimSpace(fingerprint)
	if trimmedFP == "" {
		return strings.TrimSpace(body)
	}
	marker := "<!-- wrkr-fingerprint:" + trimmedFP + " -->"
	trimmedBody := strings.TrimSpace(body)
	if strings.Contains(trimmedBody, marker) {
		return trimmedBody
	}
	if trimmedBody == "" {
		return marker
	}
	return trimmedBody + "\n\n" + marker
}

func hasFingerprint(body, fingerprint string) bool {
	trimmedFP := strings.TrimSpace(fingerprint)
	if trimmedFP == "" {
		return false
	}
	return strings.Contains(body, "<!-- wrkr-fingerprint:"+trimmedFP+" -->")
}
