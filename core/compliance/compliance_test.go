package compliance

import (
	"reflect"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/framework"
)

func TestFlattenPreservesLegacyControlRequirements(t *testing.T) {
	t.Parallel()

	legacy := framework.Control{
		ID:                  "legacy-control",
		Title:               "Legacy Control",
		RequiredRecordTypes: []string{"approval", "permission_check"},
		RequiredFields:      []string{"record_id", "event"},
		MinimumFrequency:    "continuous",
	}

	got := flatten([]framework.Control{legacy})
	if len(got) != 1 {
		t.Fatalf("expected one flattened control, got %d", len(got))
	}
	if !reflect.DeepEqual(got[0], legacy) {
		t.Fatalf("legacy control changed during flattening\nwant=%+v\ngot=%+v", legacy, got[0])
	}
}

func TestEvaluateEvidenceSetCoverageSelectsSatisfiedWrkrAlternativeDeterministically(t *testing.T) {
	t.Parallel()

	evidenceSets := []framework.EvidenceSet{
		{
			ID:                  "runtime-control",
			SourceProducts:      []string{"gait"},
			RequiredRecordTypes: []string{"permission_check", "policy_enforcement"},
			RequiredFields:      []string{"record_id", "source_product", "event"},
			MinimumFrequency:    "continuous",
		},
		{
			ID:                  "wrkr-discovery",
			SourceProducts:      []string{"wrkr"},
			RequiredRecordTypes: []string{"scan_finding"},
			RequiredFields:      []string{"record_id", "source_product", "event"},
			MinimumFrequency:    "continuous",
		},
	}
	evaluate := func(sets []framework.EvidenceSet) ControlCheck {
		frameworkDef := &proof.Framework{}
		frameworkDef.Framework.ID = "evidence-set-framework"
		frameworkDef.Framework.Version = "1"
		frameworkDef.Framework.Title = "Evidence Set Framework"
		frameworkDef.Controls = []framework.Control{{
			ID:           "evidence-set-control",
			Title:        "Evidence Set Control",
			EvidenceSets: sets,
		}}
		chain := proof.NewChain("wrkr-proof")
		appendRecord(t, chain, "scan_finding")
		result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
		if err != nil {
			t.Fatalf("evaluate evidence-set control: %v", err)
		}
		if len(result.Controls) != 1 {
			t.Fatalf("expected one control, got %d", len(result.Controls))
		}
		return result.Controls[0]
	}

	first := evaluate(evidenceSets)
	reversed := append([]framework.EvidenceSet(nil), evidenceSets...)
	reversed[0], reversed[1] = reversed[1], reversed[0]
	second := evaluate(reversed)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("evidence-set evaluation changed with input order\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.Status != "covered" {
		t.Fatalf("expected wrkr evidence path to be covered, got %+v", first)
	}
	wantTypes := []string{"scan_finding"}
	if !reflect.DeepEqual(first.RequiredRecordTypes, wantTypes) {
		t.Fatalf("required record types mismatch: want=%v got=%v", wantTypes, first.RequiredRecordTypes)
	}
	if len(first.MissingRecordTypes) != 0 {
		t.Fatalf("covered evidence path reported missing types: %+v", first)
	}
}

func TestEvaluateEvidenceSetCoverageRequiresEveryTypeInSelectedSet(t *testing.T) {
	t.Parallel()

	frameworkDef := &proof.Framework{}
	frameworkDef.Framework.ID = "combined-evidence-framework"
	frameworkDef.Framework.Version = "1"
	frameworkDef.Framework.Title = "Combined Evidence Framework"
	frameworkDef.Controls = []framework.Control{{
		ID:    "evidence-set-control",
		Title: "Evidence Set Control",
		EvidenceSets: []framework.EvidenceSet{{
			ID:                  "combined",
			SourceProducts:      []string{"wrkr", "gait"},
			RequiredRecordTypes: []string{"scan_finding", "permission_check"},
			RequiredFields:      []string{"record_id", "source_product", "event"},
			MinimumFrequency:    "continuous",
		}},
	}}
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding")

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate combined evidence set: %v", err)
	}
	if len(result.Controls) != 1 {
		t.Fatalf("expected one control, got %d", len(result.Controls))
	}
	check := result.Controls[0]
	if check.Status != "gap" {
		t.Fatalf("single record type must not cover a multi-type evidence set: %+v", check)
	}
	wantTypes := []string{"permission_check", "scan_finding"}
	if !reflect.DeepEqual(check.RequiredRecordTypes, wantTypes) {
		t.Fatalf("required record types mismatch: want=%v got=%v", wantTypes, check.RequiredRecordTypes)
	}
	wantMissing := []string{"permission_check"}
	if !reflect.DeepEqual(check.MissingRecordTypes, wantMissing) {
		t.Fatalf("missing record types mismatch: want=%v got=%v", wantMissing, check.MissingRecordTypes)
	}
}

func TestEvaluateEvidenceSetCoverageReportsMissingFields(t *testing.T) {
	t.Parallel()

	frameworkDef := &proof.Framework{}
	frameworkDef.Framework.ID = "field-scoped-framework"
	frameworkDef.Framework.Version = "1"
	frameworkDef.Framework.Title = "Field Scoped Framework"
	frameworkDef.Controls = []framework.Control{{
		ID:    "field-scoped-control",
		Title: "Field Scoped Control",
		EvidenceSets: []framework.EvidenceSet{{
			ID:                  "wrkr-discovery",
			SourceProducts:      []string{"wrkr"},
			RequiredRecordTypes: []string{"scan_finding"},
			RequiredFields:      []string{"record_id", "event.required_value"},
			MinimumFrequency:    "continuous",
		}},
	}}
	chain := proof.NewChain("wrkr-proof")
	appendRecord(t, chain, "scan_finding")

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate field-scoped evidence set: %v", err)
	}
	check := result.Controls[0]
	if check.Status != "gap" {
		t.Fatalf("missing required field must keep the evidence set uncovered: %+v", check)
	}
	if len(check.MissingRecordTypes) != 0 {
		t.Fatalf("present record type must not be reported missing when only a field is absent: %+v", check)
	}
	if !reflect.DeepEqual(check.MissingFields, []string{"event.required_value"}) {
		t.Fatalf("missing fields mismatch: %+v", check)
	}
}

func TestEvaluateEvidenceSetCoverageDoesNotProjectExternalOnlyAlternativeAsWrkrCoverage(t *testing.T) {
	t.Parallel()

	frameworkDef := &proof.Framework{}
	frameworkDef.Framework.ID = "source-scoped-framework"
	frameworkDef.Framework.Version = "1"
	frameworkDef.Framework.Title = "Source Scoped Framework"
	frameworkDef.Controls = []framework.Control{{
		ID:    "source-scoped-control",
		Title: "Source Scoped Control",
		EvidenceSets: []framework.EvidenceSet{
			{
				ID:                  "wrkr-discovery",
				SourceProducts:      []string{"wrkr"},
				RequiredRecordTypes: []string{"scan_finding"},
				RequiredFields:      []string{"record_id", "source_product", "event"},
				MinimumFrequency:    "continuous",
			},
			{
				ID:                  "runtime-control",
				SourceProducts:      []string{"gait"},
				RequiredRecordTypes: []string{"permission_check"},
				RequiredFields:      []string{"record_id", "source_product", "event"},
				MinimumFrequency:    "continuous",
			},
		},
	}}
	chain := proof.NewChain("wrkr-proof")
	appendRecordForProduct(t, chain, "gait", "permission_check")

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate source-scoped evidence sets: %v", err)
	}
	check := result.Controls[0]
	if check.Status != "gap" {
		t.Fatalf("external-only evidence path must not overclaim wrkr coverage: %+v", check)
	}
	if !reflect.DeepEqual(check.RequiredRecordTypes, []string{"scan_finding"}) ||
		!reflect.DeepEqual(check.MissingRecordTypes, []string{"scan_finding"}) {
		t.Fatalf("expected the wrkr evidence path to remain selected and incomplete: %+v", check)
	}
}

func TestEvaluateEvidenceSetCoverageRejectsAllExternalAlternatives(t *testing.T) {
	t.Parallel()

	frameworkDef := &proof.Framework{}
	frameworkDef.Framework.ID = "external-framework"
	frameworkDef.Framework.Version = "1"
	frameworkDef.Framework.Title = "External Framework"
	frameworkDef.Controls = []framework.Control{{
		ID:    "external-control",
		Title: "External Control",
		EvidenceSets: []framework.EvidenceSet{{
			ID:                  "runtime-control",
			SourceProducts:      []string{"gait"},
			RequiredRecordTypes: []string{"permission_check"},
			RequiredFields:      []string{"record_id", "source_product", "event"},
			MinimumFrequency:    "continuous",
		}},
	}}
	chain := proof.NewChain("wrkr-proof")
	appendRecordForProduct(t, chain, "gait", "permission_check")

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate external-only evidence set: %v", err)
	}
	check := result.Controls[0]
	if check.Status != "gap" || check.MatchedRecords != 0 {
		t.Fatalf("external-only evidence must not satisfy the wrkr projection: %+v", check)
	}
	if len(check.RequiredRecordTypes) != 0 || len(check.MissingRecordTypes) != 0 {
		t.Fatalf("external-only requirements must not be projected as wrkr requirements: %+v", check)
	}
}

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

	frameworkIDs := []string{"eu-ai-act", "soc2"}
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
		coveredByRules := false
		for _, control := range result.Controls {
			if len(control.MappedRuleIDs) > 0 {
				coveredByRules = true
				if control.Status == "covered" && (len(control.MissingRecordTypes) > 0 || len(control.MissingFields) > 0) {
					t.Fatalf("expected covered mapped control without missing evidence for %s, got %+v", frameworkID, control)
				}
			}
		}
		if !coveredByRules {
			t.Fatalf("expected mapped WRKR-A rule coverage for %s, got %+v", frameworkID, result.Controls)
		}
	}
}

func TestConfiguredControlRuleIDsUsesOnlyExplicitCompatibilityAliases(t *testing.T) {
	t.Parallel()

	if got := configuredControlRuleIDs("soc2", "cc6.1"); !reflect.DeepEqual(got, frameworkControlRuleMap["soc2"]["cc6"]) {
		t.Fatalf("expected explicit cc6.1 compatibility mapping, got %v", got)
	}
	if got := configuredControlRuleIDs("soc2", "cc6.3"); len(got) != 0 {
		t.Fatalf("cc6.3 must not inherit cc6 rules without an explicit equivalence, got %v", got)
	}
	if got := configuredControlRuleIDs("pci-dss", "req-6.5"); len(got) != 0 {
		t.Fatalf("unrelated PCI control must not inherit the legacy req-10 mapping, got %v", got)
	}
}

func TestComplianceMapping_DoesNotMaskMissingRecords(t *testing.T) {
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
				MatchedRuleIDs: []string{"WRKR-A010"},
			},
		},
		Controls: proof.Controls{PermissionsEnforced: true},
	})
	if err != nil {
		t.Fatalf("new record: %v", err)
	}
	if err := proof.AppendToChain(chain, record); err != nil {
		t.Fatalf("append record: %v", err)
	}

	result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
	if err != nil {
		t.Fatalf("evaluate compliance: %v", err)
	}
	if len(result.Gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(result.Gaps))
	}
	gap := result.Gaps[0]
	if gap.Status != "gap" {
		t.Fatalf("expected gap status, got %s", gap.Status)
	}
	if len(gap.MappedRuleIDs) == 0 {
		t.Fatalf("expected mapped rule IDs to be preserved, got %+v", gap)
	}
	if len(gap.MissingRecordTypes) != 1 || gap.MissingRecordTypes[0] != "incident" {
		t.Fatalf("expected missing incident record type, got %v", gap.MissingRecordTypes)
	}
}

func appendRecord(t *testing.T, chain *proof.Chain, recordType string) {
	t.Helper()
	appendRecordForProduct(t, chain, "wrkr", recordType)
}

func appendRecordForProduct(t *testing.T, chain *proof.Chain, sourceProduct, recordType string) {
	t.Helper()
	record, err := proof.NewRecord(proof.RecordOpts{
		Timestamp:     time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC),
		Source:        sourceProduct,
		SourceProduct: sourceProduct,
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
