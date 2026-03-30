package report

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildActivationPrefersConcreteMySetupSignals(t *testing.T) {
	t.Parallel()

	activation := BuildActivation("my_setup", []risk.ScoredFinding{
		{
			Score: 8.1,
			Finding: model.Finding{
				FindingType: "policy_violation",
				Severity:    model.SeverityMedium,
				ToolType:    "policy",
				Location:    "WRKR-005",
				Repo:        "local-machine",
			},
		},
		{
			Score: 7.4,
			Finding: model.Finding{
				FindingType: "mcp_server",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
			},
		},
		{
			Score: 6.2,
			Finding: model.Finding{
				FindingType: "secret_presence",
				Severity:    model.SeverityHigh,
				ToolType:    "secret",
				Location:    "process:env",
				Repo:        "local-machine",
			},
		},
		{
			Score: 5.8,
			Finding: model.Finding{
				FindingType: "source_discovery",
				Severity:    model.SeverityLow,
				ToolType:    "source_repo",
				Location:    "/Users/test",
				Repo:        "local-machine",
			},
		},
	}, nil, nil, 5)
	if activation == nil {
		t.Fatal("expected activation summary for my_setup target")
	}
	if !activation.SuppressedPolicyItems {
		t.Fatal("expected policy-only findings to be suppressed when concrete items exist")
	}
	if activation.EligibleCount != 2 {
		t.Fatalf("expected 2 eligible items, got %d", activation.EligibleCount)
	}
	if len(activation.Items) != 2 {
		t.Fatalf("expected 2 activation items, got %d", len(activation.Items))
	}
	if activation.Items[0].ToolType == "policy" || activation.Items[1].ToolType == "policy" {
		t.Fatalf("policy findings must not appear in activation items: %+v", activation.Items)
	}
	if activation.Items[0].FindingType != "mcp_server" {
		t.Fatalf("expected first concrete activation item to preserve ranked order, got %+v", activation.Items[0])
	}
}

func TestBuildActivationReturnsReasonWhenOnlyPolicyItemsExist(t *testing.T) {
	t.Parallel()

	activation := BuildActivation("my_setup", []risk.ScoredFinding{
		{
			Score: 8.1,
			Finding: model.Finding{
				FindingType: "policy_violation",
				Severity:    model.SeverityMedium,
				ToolType:    "policy",
				Location:    "WRKR-005",
				Repo:        "local-machine",
			},
		},
	}, nil, nil, 5)
	if activation == nil {
		t.Fatal("expected activation summary for my_setup target")
	}
	if activation.Reason != activationReasonNoConcreteItems {
		t.Fatalf("unexpected activation reason: %+v", activation)
	}
	if len(activation.Items) != 0 {
		t.Fatalf("expected no activation items, got %+v", activation.Items)
	}
}

func TestBuildActivationReturnsNilOutsideMySetup(t *testing.T) {
	t.Parallel()

	activation := BuildActivation("path", nil, nil, nil, 5)
	if activation == nil {
		t.Fatal("expected deterministic empty activation summary for path target")
	}
	if activation.Reason != activationReasonNoGovernFirst {
		t.Fatalf("unexpected activation reason: %+v", activation)
	}
}

func TestBuildActivationHonorsExplicitTopZero(t *testing.T) {
	t.Parallel()

	activation := BuildActivation("my_setup", []risk.ScoredFinding{
		{
			Score: 7.4,
			Finding: model.Finding{
				FindingType: "mcp_server",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
			},
		},
	}, nil, nil, 0)
	if activation != nil {
		t.Fatalf("expected nil activation when top=0 explicitly suppresses findings, got %+v", activation)
	}
}

func TestBuildActivationAddsGovernFirstOrgItems(t *testing.T) {
	t.Parallel()

	inventory := &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:alpha:acme",
				Framework:              "langchain",
				Repos:                  []string{"payments"},
				Location:               "agents/payments.py",
				RiskScore:              8.6,
				WriteCapable:           true,
				ProductionWrite:        true,
				ApprovalClassification: "approved",
			},
			{
				AgentID:                  "wrkr:beta:acme",
				Framework:                "crewai",
				Repos:                    []string{"ops"},
				Location:                 "crews/ops.py",
				RiskScore:                7.1,
				WriteCapable:             true,
				SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
				ApprovalClassification:   "unknown",
			},
		},
	}

	activation := BuildActivation("org", nil, inventory, nil, 5)
	if activation == nil {
		t.Fatal("expected activation summary for org target")
	}
	if activation.TargetMode != "org" {
		t.Fatalf("unexpected target mode: %+v", activation)
	}
	if activation.EligibleCount != 2 || len(activation.Items) != 2 {
		t.Fatalf("expected 2 govern-first items, got %+v", activation)
	}
	if activation.Items[0].ItemClass != activationClassProductionBacked {
		t.Fatalf("expected production-target-backed item first, got %+v", activation.Items[0])
	}
	if activation.Items[1].ItemClass != activationClassUnknownWrite {
		t.Fatalf("expected unknown-to-security item second, got %+v", activation.Items[1])
	}
}
