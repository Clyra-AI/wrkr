package controlbacklog

import (
	"encoding/json"
	"reflect"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildControlBacklogSplitsSignalClassesAndSortsDeterministically(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "dependency_manifest",
			Severity:    model.SeverityLow,
			ToolType:    "dependency",
			Location:    "package.json",
			Repo:        "app",
			Org:         "acme",
			Detector:    "dependency",
		},
		{
			FindingType: "mcp_server",
			Severity:    model.SeverityMedium,
			ToolType:    "mcp",
			Location:    ".cursor/mcp.json",
			Repo:        "app",
			Org:         "acme",
			Detector:    "mcp",
		},
	}
	inventory := &agginventory.Inventory{
		Tools: []agginventory.Tool{
			{
				ToolID:                   "mcp:.cursor/mcp.json",
				ToolType:                 "mcp",
				Org:                      "acme",
				ApprovalClass:            "unapproved",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
				Locations: []agginventory.ToolLocation{{
					Repo:            "app",
					Location:        ".cursor/mcp.json",
					Owner:           "@acme/app",
					OwnerSource:     "codeowners",
					OwnershipStatus: "explicit",
				}},
			},
			{
				ToolID:                   "dependency:package.json",
				ToolType:                 "dependency",
				Org:                      "acme",
				ApprovalClass:            "unknown",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
				Locations: []agginventory.ToolLocation{{
					Repo:            "app",
					Location:        "package.json",
					Owner:           "@acme/app",
					OwnerSource:     "repo_fallback",
					OwnershipStatus: "inferred",
				}},
			},
		},
	}
	actionPaths := []risk.ActionPath{{
		PathID:                   "apc-test",
		Org:                      "acme",
		Repo:                     "app",
		ToolType:                 "mcp",
		Location:                 ".cursor/mcp.json",
		WriteCapable:             true,
		OperationalOwner:         "@acme/app",
		OwnerSource:              "codeowners",
		OwnershipStatus:          "explicit",
		ApprovalGap:              true,
		SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
		RecommendedAction:        "approval",
		RiskScore:                7.2,
	}}

	first := Build(Input{Findings: findings, Inventory: inventory, ActionPaths: actionPaths})
	second := Build(Input{Findings: append([]model.Finding(nil), findings...), Inventory: inventory, ActionPaths: append([]risk.ActionPath(nil), actionPaths...)})
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic backlog\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.ControlBacklogVersion != BacklogVersion {
		t.Fatalf("unexpected backlog version: %s", first.ControlBacklogVersion)
	}
	if len(first.Items) < 2 {
		t.Fatalf("expected at least two backlog items, got %+v", first.Items)
	}
	if first.Items[0].SignalClass != SignalClassUniqueWrkrSignal {
		t.Fatalf("expected unique Wrkr signal first, got %+v", first.Items)
	}
	if first.Summary.UniqueWrkrSignalItems == 0 || first.Summary.SupportingSecurityItems == 0 {
		t.Fatalf("expected split signal summary, got %+v", first.Summary)
	}
	if len(first.Items[0].LinkedFindingIDs) == 0 {
		t.Fatalf("expected linked raw finding IDs, got %+v", first.Items[0])
	}
	if len(first.Items[0].GovernanceControls) == 0 {
		t.Fatalf("expected governance controls on backlog item, got %+v", first.Items[0])
	}
	if _, err := json.Marshal(first); err != nil {
		t.Fatalf("marshal backlog: %v", err)
	}
}

func TestWritePathClassifiesPRWriteSecretBearingWorkflow(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{Findings: []model.Finding{
		{
			FindingType: "ci_autonomy",
			ToolType:    "ci_agent",
			Location:    ".github/workflows/pr.yml",
			Repo:        "app",
			Org:         "acme",
			Permissions: []string{"pull_request.write", "secret.read"},
		},
	}})
	if len(backlog.Items) == 0 {
		t.Fatal("expected backlog item")
	}
	item := backlog.Items[0]
	if !containsString(item.WritePathClasses, agginventory.WritePathPullRequestWrite) {
		t.Fatalf("expected pr_write class, got %+v", item.WritePathClasses)
	}
	if !containsString(item.WritePathClasses, agginventory.WritePathSecretBearingExec) {
		t.Fatalf("expected secret-bearing execution class, got %+v", item.WritePathClasses)
	}
	if !containsControl(item.GovernanceControls, agginventory.GovernanceControlLeastPrivilege) {
		t.Fatalf("expected least-privilege control mapping, got %+v", item.GovernanceControls)
	}
}

func TestSecurityVisibilityMapsApprovedToKnownApprovedInBacklog(t *testing.T) {
	t.Parallel()

	finding := model.Finding{
		FindingType: "tool_config",
		ToolType:    "codex",
		Location:    ".codex/config.toml",
		Repo:        "app",
		Org:         "acme",
	}
	backlog := Build(Input{
		Findings: []model.Finding{finding},
		Inventory: &agginventory.Inventory{Tools: []agginventory.Tool{{
			ToolType:                 "codex",
			Org:                      "acme",
			ApprovalStatus:           "valid",
			ApprovalClass:            "approved",
			LifecycleState:           "active",
			SecurityVisibilityStatus: agginventory.SecurityVisibilityApproved,
			Locations: []agginventory.ToolLocation{{
				Repo:            "app",
				Location:        ".codex/config.toml",
				Owner:           "@acme/app",
				OwnerSource:     "codeowners",
				OwnershipStatus: "explicit",
			}},
		}}},
	})
	if len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", backlog.Items)
	}
	if backlog.Items[0].SecurityVisibility != agginventory.SecurityVisibilityKnownApproved {
		t.Fatalf("expected known_approved in governance backlog, got %+v", backlog.Items[0])
	}
}

func TestRecommendedActionTaxonomyCoversKnownFindingFamilies(t *testing.T) {
	t.Parallel()

	for _, action := range []string{
		ActionAttachEvidence,
		ActionApprove,
		ActionRemediate,
		ActionDowngrade,
		ActionDeprecate,
		ActionExclude,
		ActionMonitor,
		ActionInventoryReview,
		ActionSuppress,
		ActionDebugOnly,
	} {
		if !ValidRecommendedAction(action) {
			t.Fatalf("expected valid action %s", action)
		}
	}
	if ValidRecommendedAction("control") {
		t.Fatal("legacy action-path action must not be a backlog action")
	}

	backlog := Build(Input{Mode: "deep", Findings: []model.Finding{
		{FindingType: "parse_error", ToolType: "dependency", Location: "dist/generated.js", Repo: "app", Org: "acme", ParseError: &model.ParseError{Kind: "parse_error", Path: "dist/generated.js"}},
		{FindingType: "dependency_manifest", ToolType: "dependency", Location: "package.json", Repo: "app", Org: "acme"},
		{FindingType: "policy_violation", ToolType: "policy", Location: "WRKR-004", Repo: "app", Org: "acme"},
	}})
	seen := map[string]bool{}
	for _, item := range backlog.Items {
		seen[item.RecommendedAction] = true
	}
	for _, want := range []string{ActionSuppress, ActionInventoryReview, ActionRemediate} {
		if !seen[want] {
			t.Fatalf("expected action %s in %+v", want, backlog.Items)
		}
	}
}

func TestEvidenceQualityExplainsOwnerFallbackConfidence(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		Findings: []model.Finding{{
			FindingType: "mcp_server",
			ToolType:    "mcp",
			Location:    ".mcp.json",
			Repo:        "payments-api",
			Org:         "acme",
		}},
		Inventory: &agginventory.Inventory{Tools: []agginventory.Tool{{
			ToolType:                 "mcp",
			Org:                      "acme",
			ApprovalClass:            "unapproved",
			SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
			Locations: []agginventory.ToolLocation{{
				Repo:            "payments-api",
				Location:        ".mcp.json",
				Owner:           "@acme/payments",
				OwnerSource:     "repo_fallback",
				OwnershipStatus: "inferred",
			}},
		}}},
	})
	if len(backlog.Items) != 1 {
		t.Fatalf("expected one item, got %+v", backlog.Items)
	}
	item := backlog.Items[0]
	if item.Confidence != ConfidenceMedium {
		t.Fatalf("expected medium confidence from fallback owner, got %+v", item)
	}
	if !containsString(item.EvidenceGaps, "explicit_owner_evidence_missing") {
		t.Fatalf("expected owner evidence gap, got %+v", item.EvidenceGaps)
	}
	if len(item.ConfidenceRaise) == 0 {
		t.Fatalf("expected confidence raising guidance, got %+v", item)
	}
}

func TestWorkflowSecretReferenceDoesNotClaimLeakedSecret(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{Findings: []model.Finding{
		{
			FindingType: "ci_autonomy",
			ToolType:    "ci_agent",
			Location:    ".github/workflows/pr.yml",
			Repo:        "app",
			Org:         "acme",
			Permissions: []string{"pull_request.write", "secret.read"},
		},
		{
			FindingType: "secret_presence",
			ToolType:    "secret",
			Location:    ".github/workflows/pr.yml",
			Repo:        "app",
			Org:         "acme",
			Evidence:    []model.Evidence{{Key: "workflow_secret_refs", Value: "GH_TOKEN"}},
		},
	}})
	var secretItem *Item
	for idx := range backlog.Items {
		if backlog.Items[idx].ControlPathType == ControlPathSecretWorkflow {
			secretItem = &backlog.Items[idx]
			break
		}
	}
	if secretItem == nil {
		t.Fatalf("expected secret-bearing workflow item, got %+v", backlog.Items)
	}
	if !containsString(secretItem.SecretSignalTypes, SecretReferenceDetected) {
		t.Fatalf("expected secret reference signal, got %+v", secretItem.SecretSignalTypes)
	}
	if containsString(secretItem.SecretSignalTypes, SecretValueDetected) {
		t.Fatalf("did not expect secret value signal, got %+v", secretItem.SecretSignalTypes)
	}
	if !containsString(secretItem.SecretSignalTypes, SecretUsedByWriteCapableWorkflow) {
		t.Fatalf("expected write-capable workflow signal, got %+v", secretItem.SecretSignalTypes)
	}
	if secretItem.RecommendedAction != ActionAttachEvidence {
		t.Fatalf("expected attach_evidence, got %+v", secretItem)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsControl(values []agginventory.GovernanceControlMapping, want string) bool {
	for _, value := range values {
		if value.Control == want {
			return true
		}
	}
	return false
}
