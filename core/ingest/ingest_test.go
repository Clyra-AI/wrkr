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
	if bundle.Records[0].EvidenceClass != EvidenceClassPolicyDecision {
		t.Fatalf("expected normalized evidence class %q, got %+v", EvidenceClassPolicyDecision, bundle.Records[0])
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
			EvidenceClass: EvidenceClassPolicyDecision,
		}},
	})
	if summary.MatchedRecords != 1 || summary.UnmatchedRecords != 0 {
		t.Fatalf("expected matched runtime evidence summary, got %+v", summary)
	}
}

func TestCorrelateMatchesByAgentRepoWorkflowFallback(t *testing.T) {
	t.Parallel()

	summary := Correlate(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                   "apc-789",
				AgentID:                  "wrkr:codex-aaaa:acme",
				Repo:                     "acme/release",
				Location:                 ".github/workflows/release.yml",
				ToolType:                 "compiled_action",
				ActionClasses:            []string{"deploy"},
				MatchedProductionTargets: []string{"cluster/prod"},
			}},
		},
	}, "runtime-evidence.json", Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Records: []Record{{
			AgentID:       "wrkr:codex-aaaa:acme",
			Repo:          "acme/release",
			Location:      ".github/workflows/release.yml",
			Target:        "cluster/prod",
			ActionClasses: []string{"deploy"},
			Source:        "runtime_probe",
			ObservedAt:    time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
			EvidenceClass: EvidenceClassApproval,
		}},
	})
	if summary.MatchedRecords != 1 || len(summary.Correlations) != 1 {
		t.Fatalf("expected fallback match, got %+v", summary)
	}
	if summary.Correlations[0].PathID != "apc-789" || summary.Correlations[0].Status != CorrelationStatusMatched {
		t.Fatalf("expected correlation to resolve to apc-789, got %+v", summary.Correlations[0])
	}
}

func TestCorrelateHonorsExplicitUnmatchedStatusInSummary(t *testing.T) {
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
			EvidenceClass: EvidenceClassPolicyDecision,
			Status:        CorrelationStatusUnmatched,
		}},
	})
	if summary.MatchedRecords != 0 || summary.UnmatchedRecords != 1 {
		t.Fatalf("expected explicit unmatched status to drive summary counts, got %+v", summary)
	}
	if len(summary.Correlations) != 1 || summary.Correlations[0].Status != CorrelationStatusUnmatched {
		t.Fatalf("expected unmatched correlation to be preserved, got %+v", summary.Correlations)
	}
}

func TestCorrelatePreservesScopedContainmentEvidence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	bundle, err := Normalize(Bundle{
		GeneratedAt: now,
		Records: []Record{
			{
				PathID:                   "apc-contained",
				Source:                   "gait",
				ObservedAt:               now,
				EvidenceClass:            EvidenceClassContainmentReceipt,
				ContainmentStatus:        ContainmentStatusContained,
				ContainmentScopeRefs:     []string{"agent:parent", "agent:child"},
				AcknowledgedBoundaryRefs: []string{"github:token:revoked"},
			},
			{
				PathID:                 "apc-contained",
				Source:                 "gait",
				ObservedAt:             now,
				EvidenceClass:          EvidenceClassDescendantInvalidation,
				ContainmentScopeRefs:   []string{"agent:child"},
				UnresolvedBoundaryRefs: []string{"cloud:session:unknown"},
				ContainmentStatus:      ContainmentStatusUnresolved,
			},
		},
	})
	if err != nil {
		t.Fatalf("normalize containment evidence: %v", err)
	}
	summary := Correlate(state.Snapshot{RiskReport: &risk.Report{ActionPaths: []risk.ActionPath{{PathID: "apc-contained"}}}}, "runtime-evidence.json", bundle)
	if len(summary.Correlations) != 1 {
		t.Fatalf("expected one containment correlation, got %+v", summary.Correlations)
	}
	got := summary.Correlations[0]
	if got.ContainmentStatus != ContainmentStatusUnresolved {
		t.Fatalf("expected unresolved to dominate mixed containment evidence, got %+v", got)
	}
	if len(got.ContainmentScopeRefs) != 2 || len(got.AcknowledgedBoundaryRefs) != 1 || len(got.UnresolvedBoundaryRefs) != 1 {
		t.Fatalf("expected scoped containment refs to survive correlation, got %+v", got)
	}
}

func TestNormalizeRejectsUnknownContainmentStatus(t *testing.T) {
	t.Parallel()

	_, err := Normalize(Bundle{Records: []Record{{
		PathID:            "apc-contained",
		Source:            "gait",
		ObservedAt:        time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		EvidenceClass:     EvidenceClassStopRequest,
		ContainmentStatus: "complete_enough",
	}}})
	if err == nil {
		t.Fatal("expected unknown containment status to fail closed")
	}
}
