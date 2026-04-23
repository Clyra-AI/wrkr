package tickets

import (
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
)

func TestTicketPayloadIncludesClosureCriteriaAndSLA(t *testing.T) {
	t.Parallel()

	export := Build(&controlbacklog.Backlog{Items: []controlbacklog.Item{{
		ID:                "cb-1",
		Repo:              "payments",
		Path:              ".github/workflows/release.yml",
		Owner:             "@acme/payments",
		ControlPathType:   "ci_automation",
		Capability:        "repo_write",
		EvidenceBasis:     []string{"workflow_permission"},
		RecommendedAction: "approve",
		SLA:               "7d",
		ClosureCriteria:   "Record owner-approved evidence and rescan.",
		Confidence:        "medium",
	}}}, "jira", 10)

	if export.TicketExportVersion != "1" || !export.DryRun || len(export.Tickets) != 1 {
		t.Fatalf("unexpected export: %+v", export)
	}
	ticket := export.Tickets[0]
	if ticket.Owner != "@acme/payments" || ticket.SLA != "7d" || ticket.ClosureCriteria == "" || len(ticket.ProofRequirements) == 0 {
		t.Fatalf("expected owner/SLA/closure/proof fields, got %+v", ticket)
	}
}

func TestTicketExportDeterministicGrouping(t *testing.T) {
	t.Parallel()

	backlog := &controlbacklog.Backlog{Items: []controlbacklog.Item{
		{ID: "b", Repo: "repo", Path: "same", Owner: "@team", ControlPathType: "agent_config", RecommendedAction: "approve", SLA: "7d", ClosureCriteria: "Done."},
		{ID: "a", Repo: "repo", Path: "same", Owner: "@team", ControlPathType: "agent_config", RecommendedAction: "approve", SLA: "7d", ClosureCriteria: "Done."},
	}}
	first := Build(backlog, "github", 10)
	second := Build(backlog, "github", 10)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic export\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first.Tickets) != 1 {
		t.Fatalf("expected deduped ticket, got %+v", first.Tickets)
	}
}

func TestValidFormat(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"jira", "github", "servicenow"} {
		if !ValidFormat(format) {
			t.Fatalf("expected valid format %s", format)
		}
	}
	if ValidFormat("email") {
		t.Fatal("expected invalid format")
	}
}
