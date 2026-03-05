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
