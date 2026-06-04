package proofcompat

import (
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
)

func TestEnsureWrkrRecordTypesAllowsWrkrSpecificProofRecords(t *testing.T) {
	t.Parallel()
	if err := EnsureWrkrRecordTypes(); err != nil {
		t.Fatalf("ensure wrkr record types: %v", err)
	}

	for _, test := range []struct {
		name       string
		recordType string
		event      map[string]any
	}{
		{
			name:       "lifecycle_transition",
			recordType: "lifecycle_transition",
			event: map[string]any{
				"event_type":     "lifecycle_transition",
				"previous_state": "discovered",
				"new_state":      "under_review",
				"trigger":        "state_changed",
				"diff":           map[string]any{},
			},
		},
		{
			name:       "evidence",
			recordType: "evidence",
			event: map[string]any{
				"event_type":   "evidence_attached",
				"evidence_url": "https://tickets.example/SEC-123",
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := proof.NewRecord(proof.RecordOpts{
				Timestamp:     time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
				Source:        "wrkr",
				SourceProduct: "wrkr",
				Type:          test.recordType,
				Event:         test.event,
			}); err != nil {
				t.Fatalf("build %s proof record: %v", test.recordType, err)
			}
		})
	}
}
