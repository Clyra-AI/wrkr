package scanquality

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestReconciliationLedgerAcceptsConsistentStages(t *testing.T) {
	report := Build(Input{
		SurfaceCoverage: []detect.SurfaceCoverage{{Surface: "ci_workflow:jenkins", Detector: "ciagent", Discovered: 3, Selected: 3, Attempted: 3, Parsed: 2, Partial: 1}},
		NormalizedFacts: 4, Bindings: 2, EffectiveAuthorities: 1, EligiblePaths: 2, ConfirmedPaths: 1, CandidatePaths: 1, DisplayedPaths: 2,
	})
	if report.ScanQualityVersion != "2" || report.ReconciliationLedger == nil || !report.ReconciliationLedger.Valid {
		t.Fatalf("expected valid scan-quality v2 ledger, got %+v", report)
	}
}

func TestReconciliationLedgerRejectsUnprojectedEligiblePaths(t *testing.T) {
	report := Build(Input{EligiblePaths: 2})
	if report.ReconciliationLedger == nil || report.ReconciliationLedger.Valid {
		t.Fatalf("expected unprojected paths to invalidate ledger, got %+v", report.ReconciliationLedger)
	}
	if len(report.ReconciliationLedger.Errors) != 1 || report.ReconciliationLedger.Errors[0] != "projected_paths_do_not_reconcile" {
		t.Fatalf("unexpected reconciliation errors: %v", report.ReconciliationLedger.Errors)
	}
}

func TestUpdateReportProjectionRecordsDisplayedAndSuppressedPaths(t *testing.T) {
	report := Build(Input{NormalizedFacts: 2, Bindings: 1, EligiblePaths: 3})
	UpdateReportProjection(&report, 2, 1)
	counts := map[string]int{}
	for _, stage := range report.ReconciliationLedger.Stages {
		counts[stage.StageID] = stage.Count
	}
	if counts["displayed_paths"] != 2 || counts["suppressed_paths"] != 1 || !report.ReconciliationLedger.Valid {
		t.Fatalf("unexpected report projection ledger: %+v", report.ReconciliationLedger)
	}
}

func TestReconciliationLedgerRejectsImpossibleTransitions(t *testing.T) {
	report := Build(Input{
		SurfaceCoverage:      []detect.SurfaceCoverage{{Surface: "openapi", Detector: "openapi", Discovered: 1, Selected: 2, Attempted: 3, Parsed: 4}},
		EffectiveAuthorities: 1, DisplayedPaths: 2, EligiblePaths: 1,
	})
	if report.ReconciliationLedger == nil || report.ReconciliationLedger.Valid || len(report.ReconciliationLedger.Errors) < 4 {
		t.Fatalf("expected fail-closed ledger errors, got %+v", report.ReconciliationLedger)
	}
}
