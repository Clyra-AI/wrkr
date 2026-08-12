package model

import "testing"

func TestSortFindingsDeterministicOrdering(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{Severity: "low", FindingType: "z", ToolType: "tool-b", Location: "b", Org: "o"},
		{Severity: "critical", FindingType: "a", ToolType: "tool-a", Location: "a", Org: "o"},
		{Severity: "high", FindingType: "a", ToolType: "tool-a", Location: "a", Org: "o"},
	}
	SortFindings(findings)

	if findings[0].Severity != SeverityCritical {
		t.Fatalf("expected critical first, got %s", findings[0].Severity)
	}
	if findings[1].Severity != SeverityHigh {
		t.Fatalf("expected high second, got %s", findings[1].Severity)
	}
	if findings[2].Severity != SeverityLow {
		t.Fatalf("expected low third, got %s", findings[2].Severity)
	}
}

func TestNormalizeFindingDedupesPermissionsAndEvidence(t *testing.T) {
	t.Parallel()

	norm := NormalizeFinding(Finding{
		Severity:    "HIGH",
		Permissions: []string{"", " write", "read", "read"},
		Evidence: []Evidence{
			{Key: "b", Value: "2"},
			{Key: "a", Value: "1"},
			{Key: "", Value: ""},
		},
	})

	if norm.Severity != SeverityHigh {
		t.Fatalf("expected normalized severity high, got %s", norm.Severity)
	}
	if norm.DiscoveryMethod != DiscoveryMethodStatic {
		t.Fatalf("expected default discovery_method static, got %q", norm.DiscoveryMethod)
	}
	if len(norm.Permissions) != 2 || norm.Permissions[0] != "read" || norm.Permissions[1] != "write" {
		t.Fatalf("unexpected permissions: %#v", norm.Permissions)
	}
	if len(norm.Evidence) != 2 || norm.Evidence[0].Key != "a" || norm.Evidence[1].Key != "b" {
		t.Fatalf("unexpected evidence ordering: %#v", norm.Evidence)
	}
}

func TestNormalizeFindingCanonicalizesLocationRange(t *testing.T) {
	t.Parallel()

	norm := NormalizeFinding(Finding{
		Severity:      "low",
		FindingType:   "agent_framework",
		ToolType:      "langchain",
		Location:      "agents.py",
		Org:           "acme",
		LocationRange: &LocationRange{StartLine: 40, EndLine: 30},
	})
	if norm.LocationRange == nil {
		t.Fatal("expected normalized location range")
	}
	if norm.LocationRange.StartLine != 30 || norm.LocationRange.EndLine != 40 {
		t.Fatalf("expected canonical range 30..40, got %+v", norm.LocationRange)
	}
}

func TestSortFindingsOrdersByLocationRange(t *testing.T) {
	t.Parallel()

	findings := []Finding{
		{
			Severity:      "low",
			FindingType:   "agent_framework",
			ToolType:      "langchain",
			Location:      "agents.py",
			LocationRange: &LocationRange{StartLine: 40, EndLine: 45},
			Org:           "acme",
		},
		{
			Severity:      "low",
			FindingType:   "agent_framework",
			ToolType:      "langchain",
			Location:      "agents.py",
			LocationRange: &LocationRange{StartLine: 10, EndLine: 12},
			Org:           "acme",
		},
	}
	SortFindings(findings)
	if findings[0].LocationRange == nil || findings[0].LocationRange.StartLine != 10 {
		t.Fatalf("expected lower start line first, got %+v", findings)
	}
}

func TestNormalizeExecutionRelationshipsCanonicalizesAndDeduplicates(t *testing.T) {
	t.Parallel()

	relationships := NormalizeExecutionRelationships([]ExecutionRelationship{
		{RelationshipID: " b ", Kind: " workflow_call ", Caller: " caller-b ", Callee: " callee-b ", Origin: " source ", ResolutionState: " resolved_local ", Confidence: " high ", EvidenceRefs: []string{"z", "a", "a"}, TruncationReasons: []string{" ", "cycle"}},
		{RelationshipID: "a", Kind: "workflow_call", Caller: "caller-a", Callee: "callee-a", ResolutionState: "unresolved_external"},
		{RelationshipID: "a", Kind: "workflow_call", Caller: "caller-a", Callee: "callee-a", ResolutionState: "unresolved_external"},
		{RelationshipID: "invalid", Kind: "", Caller: "caller", Callee: "callee", ResolutionState: "resolved_local"},
	})
	if len(relationships) != 2 {
		t.Fatalf("expected two canonical relationships, got %+v", relationships)
	}
	if relationships[0].RelationshipID != "a" || relationships[1].RelationshipID != "b" {
		t.Fatalf("unexpected relationship ordering: %+v", relationships)
	}
	if len(relationships[1].EvidenceRefs) != 2 || relationships[1].EvidenceRefs[0] != "a" {
		t.Fatalf("unexpected normalized refs: %+v", relationships[1])
	}
	if NormalizeExecutionRelationships(nil) != nil || NormalizeExecutionRelationships([]ExecutionRelationship{{Kind: "missing"}}) != nil {
		t.Fatal("expected empty relationships to normalize to nil")
	}
}

func TestNormalizeFindingTrimsAllContractFields(t *testing.T) {
	t.Parallel()

	normalized := NormalizeFinding(Finding{
		FindingType: " type ", RuleID: " rule ", CheckResult: " pass ", PolicyOutcomeID: " outcome ",
		Severity: "unknown", DiscoveryMethod: " Imported ", Remediation: " fix ", ToolType: " tool ",
		Location: " path ", Repo: " repo ", Org: " org ", Detector: " detector ", Autonomy: " gated ",
		ParseError: &ParseError{Kind: " parse ", Format: " yaml ", Path: " path ", Detector: " parser ", Message: " bad "},
	})
	if normalized.FindingType != "type" || normalized.Severity != SeverityInfo || normalized.DiscoveryMethod != "imported" || normalized.Remediation != "fix" {
		t.Fatalf("unexpected normalized finding: %+v", normalized)
	}
	if normalized.ParseError == nil || normalized.ParseError.Message != "bad" {
		t.Fatalf("unexpected normalized parse error: %+v", normalized.ParseError)
	}
}

func TestNormalizeLocationRangeBoundaries(t *testing.T) {
	t.Parallel()

	if normalizeLocationRange(nil) != nil || normalizeLocationRange(&LocationRange{}) != nil {
		t.Fatal("empty ranges must normalize to nil")
	}
	if got := normalizeLocationRange(&LocationRange{StartLine: -1, EndLine: 7}); got == nil || got.StartLine != 7 || got.EndLine != 7 {
		t.Fatalf("unexpected end-only range: %+v", got)
	}
	if got := normalizeLocationRange(&LocationRange{StartLine: 9, EndLine: -2}); got == nil || got.StartLine != 9 || got.EndLine != 9 {
		t.Fatalf("unexpected start-only range: %+v", got)
	}
	if start, end := locationRangeBounds(nil); start != 0 || end != 0 {
		t.Fatalf("unexpected nil range bounds: %d..%d", start, end)
	}
}
