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
		{
			name:       "decision_trace",
			recordType: "decision_trace",
			event: map[string]any{
				"event_type": "decision_trace",
				"trace_id":   "dt-123",
				"path_id":    "apc-123",
				"actor": map[string]any{
					"agent_id":   "wrkr:codex:acme",
					"introduced": "pr/42",
				},
				"authority": map[string]any{
					"impact":            "release_or_deploy",
					"credential_reach":  "github_pat repository standing",
					"reachable_targets": []string{"prod-release"},
				},
				"context_used":  []string{"preset:release_automation"},
				"what_changed":  map[string]any{"artifact": ".agents/skills/release/SKILL.md"},
				"evidence_refs": []string{"proof_record:abc123"},
				"outcome": map[string]any{
					"recommended_control":        "approval_required",
					"delegation_readiness_state": "approval_required",
				},
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
