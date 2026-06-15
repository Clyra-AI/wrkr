package cli

import (
	"testing"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestClassifyScanReportArtifactErrorMapsShareableSafetyToUnsafeBlocked(t *testing.T) {
	t.Parallel()

	shareableErr := func() error {
		return reportcore.ValidateShareableArtifacts(
			state.Snapshot{
				Findings: []source.Finding{{
					Repo: "enterprise-001",
					Org:  "acme",
				}},
			},
			reportcore.Summary{
				ShareProfile: string(reportcore.ShareProfileCustomerRedacted),
				Sections: []reportcore.Section{{
					ID:    "headline",
					Facts: []string{"enterprise-001 still appears here"},
				}},
			},
			"",
			false,
		)
	}()
	if shareableErr == nil {
		t.Fatal("expected shareable safety error")
	}

	code, exitCode, handled := classifyScanReportArtifactError(shareableErr)
	if !handled {
		t.Fatalf("expected shareable safety error to be handled, got %v", shareableErr)
	}
	if code != "unsafe_operation_blocked" || exitCode != exitUnsafeBlocked {
		t.Fatalf("expected unsafe-operation mapping, got code=%q exit=%d", code, exitCode)
	}
}
