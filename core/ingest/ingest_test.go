package ingest

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestNormalizeRuntimeEvidenceBundle(t *testing.T) {
	t.Parallel()

	bundle, err := Normalize(Bundle{
		Records: []Record{{
			PathID:        "apc-123",
			Source:        "runtime_probe",
			ObservedAt:    time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			EvidenceClass: "policy_enforced",
		}},
	})
	if err != nil {
		t.Fatalf("normalize runtime evidence: %v", err)
	}
	if bundle.SchemaVersion != SchemaVersion {
		t.Fatalf("expected schema version %s, got %s", SchemaVersion, bundle.SchemaVersion)
	}
	if len(bundle.Records) != 1 || bundle.Records[0].RecordID == "" {
		t.Fatalf("expected normalized record id, got %+v", bundle.Records)
	}
}

func TestCorrelateMatchesByPathID(t *testing.T) {
	t.Parallel()

	summary := Correlate(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{PathID: "apc-123", AgentID: "wrkr:codex-aaaa:acme"}},
		},
	}, "runtime-evidence.json", Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Records: []Record{{
			PathID:        "apc-123",
			Source:        "runtime_probe",
			ObservedAt:    time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			EvidenceClass: "policy_enforced",
		}},
	})
	if summary.MatchedRecords != 1 || summary.UnmatchedRecords != 0 {
		t.Fatalf("expected matched runtime evidence summary, got %+v", summary)
	}
}
