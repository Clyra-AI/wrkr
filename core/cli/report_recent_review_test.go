package cli

import (
	"bytes"
	"testing"
)

func TestReportRecentReviewRejectsInvalidSelectors(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--json",
		"--recent-pr-review",
		"--review-ids", "bad/id",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}
