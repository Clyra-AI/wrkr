package compliance

import (
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/framework"
)

func TestEvaluateFrameworkCoverage(t *testing.T) {
	t.Parallel()
	frameworkDef := &proof.Framework{}
	frameworkDef.Framework.ID = "soc2"
	frameworkDef.Framework.Version = "2026"
	frameworkDef.Framework.Title = "SOC2"
	frameworkDef.Controls = []framework.Control{
		{
			ID:                  "cc6",
			Title:               "Logical Access",
			RequiredRecordTypes: []string{"approval", "permission_check"},
			RequiredFields:      []string{"record_id", "event"},
			MinimumFrequency:    "continuous",
		},
	}
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "approval")
	appendRecord(t, chain, "permission_check")

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate compliance: %v", err)
	}
	if result.Coverage != 100 {
		t.Fatalf("expected 100 coverage, got %.2f", result.Coverage)
	}
	if len(result.Gaps) != 0 {
		t.Fatalf("expected no gaps, got %v", result.Gaps)
	}
}

func TestEvaluateFrameworkGapWhenMissingRecordType(t *testing.T) {
	t.Parallel()
	frameworkDef := &proof.Framework{}
	frameworkDef.Framework.ID = "soc2"
	frameworkDef.Framework.Version = "2026"
	frameworkDef.Framework.Title = "SOC2"
	frameworkDef.Controls = []framework.Control{
		{
			ID:                  "cc7",
			Title:               "Operations",
			RequiredRecordTypes: []string{"incident"},
			RequiredFields:      []string{"record_id", "event"},
			MinimumFrequency:    "continuous",
		},
	}
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "approval")

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate compliance: %v", err)
	}
	if result.Coverage != 0 {
		t.Fatalf("expected 0 coverage, got %.2f", result.Coverage)
	}
	if len(result.Gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(result.Gaps))
	}
	if result.Gaps[0].MissingRecordTypes[0] != "incident" {
		t.Fatalf("expected missing incident record type, got %v", result.Gaps[0].MissingRecordTypes)
	}
}

func TestComplianceMapping_WRKRAControlsCovered(t *testing.T) {
	t.Parallel()

	frameworkIDs := []string{"eu-ai-act", "soc2", "pci-dss"}
	for _, frameworkID := range frameworkIDs {
		frameworkDef, err := proof.LoadFramework(frameworkID)
		if err != nil {
			t.Fatalf("load framework %s: %v", frameworkID, err)
		}
		chain := proof.NewChain("wrkr-proof")
		record, err := proof.NewRecord(proof.RecordOpts{
			Timestamp:     time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
			Source:        "wrkr",
			SourceProduct: "wrkr",
			Type:          "risk_assessment",
			Event: map[string]any{
				"assessment_type": "finding_risk",
				"finding": map[string]any{
					"rule_id": "WRKR-A010",
				},
			},
			Relationship: &proof.Relationship{
				PolicyRef: &proof.PolicyRef{
					PolicyID:       "wrkr-policy",
					MatchedRuleIDs: []string{"WRKR-A001", "WRKR-A010"},
				},
			},
			Controls: proof.Controls{PermissionsEnforced: true},
		})
		if err != nil {
			t.Fatalf("new record for %s: %v", frameworkID, err)
		}
		if err := proof.AppendToChain(chain, record); err != nil {
			t.Fatalf("append record for %s: %v", frameworkID, err)
		}

		result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
		if err != nil {
			t.Fatalf("evaluate framework %s: %v", frameworkID, err)
		}
		if result.Coverage == 0 {
			t.Fatalf("expected non-zero mapped coverage for %s, got %.2f", frameworkID, result.Coverage)
		}
		coveredByRules := false
		for _, control := range result.Controls {
			if len(control.MappedRuleIDs) > 0 {
				coveredByRules = true
				break
			}
		}
		if !coveredByRules {
			t.Fatalf("expected mapped WRKR-A rule coverage for %s, got %+v", frameworkID, result.Controls)
		}
	}
}

func appendRecord(t *testing.T, chain *proof.Chain, recordType string) {
	t.Helper()
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
		Source:        "wrkr",
		SourceProduct: "wrkr",
		Type:          recordType,
		Event:         map[string]any{"ok": true},
		Controls:      proof.Controls{PermissionsEnforced: true},
	})
	if err != nil {
		t.Fatalf("new record: %v", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		t.Fatalf("append record: %v", err)
	}
}
