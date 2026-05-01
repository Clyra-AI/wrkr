package controlbacklog

import (
	"encoding/json"
	"reflect"
	"testing"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
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
		CredentialProvenance: &agginventory.CredentialProvenance{
			Type:           agginventory.CredentialProvenanceUnknown,
			Scope:          agginventory.CredentialScopeUnknown,
			Confidence:     "low",
			RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceUnknown),
		},
	}}
	graph := &aggattack.ControlPathGraph{
		Version: "1",
		Nodes:   []aggattack.ControlPathNode{{NodeID: "cpg-node-1", PathID: "apc-test", Kind: aggattack.ControlPathNodeControlPath}},
		Edges:   []aggattack.ControlPathEdge{{EdgeID: "cpg-edge-1", PathID: "apc-test", Kind: "path_enables_action"}},
	}

	first := Build(Input{Findings: findings, Inventory: inventory, ActionPaths: actionPaths, ControlPathGraph: graph})
	second := Build(Input{Findings: append([]model.Finding(nil), findings...), Inventory: inventory, ActionPaths: append([]risk.ActionPath(nil), actionPaths...), ControlPathGraph: graph})
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
	if len(first.Items[0].LinkedControlPathNodeIDs) == 0 || len(first.Items[0].LinkedControlPathEdgeIDs) == 0 {
		t.Fatalf("expected control path graph refs on backlog item, got %+v", first.Items[0])
	}
	if first.Items[0].CredentialProvenance == nil || first.Items[0].CredentialProvenance.Type != agginventory.CredentialProvenanceUnknown {
		t.Fatalf("expected credential provenance on backlog item, got %+v", first.Items[0])
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

func TestConflictingOwnersLowerConfidenceAndCreateEvidenceGap(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		Findings: []model.Finding{{
			FindingType: "ci_autonomy",
			ToolType:    "ci_agent",
			Location:    ".github/workflows/release.yml",
			Repo:        "payments",
			Org:         "acme",
			Permissions: []string{"deploy.write"},
		}},
		Inventory: &agginventory.Inventory{Tools: []agginventory.Tool{{
			ToolID:                   "ci:.github/workflows/release.yml",
			ToolType:                 "ci_agent",
			Org:                      "acme",
			ApprovalClass:            "unapproved",
			SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
			Locations: []agginventory.ToolLocation{{
				Repo:                "payments",
				Location:            ".github/workflows/release.yml",
				Owner:               "@acme/payments",
				OwnerSource:         "multi_repo_conflict",
				OwnershipStatus:     "unresolved",
				OwnershipState:      "conflicting_owner",
				OwnershipConfidence: 0.2,
				OwnershipEvidence:   []string{"codeowners:CODEOWNERS:*", "service_catalog:service-catalog.yaml:*"},
				OwnershipConflicts:  []string{"@acme/payments", "@acme/security"},
			}},
		}}},
	})

	if len(backlog.Items) == 0 {
		t.Fatal("expected backlog item")
	}
	item := backlog.Items[0]
	if item.OwnershipState != "conflicting_owner" || item.OwnershipConfidence != 0.2 {
		t.Fatalf("expected conflict ownership metadata, got %+v", item)
	}
	if !containsString(item.EvidenceGaps, "owner_conflict") {
		t.Fatalf("expected owner_conflict evidence gap, got %+v", item.EvidenceGaps)
	}
	if item.Confidence != ConfidenceLow {
		t.Fatalf("expected low backlog confidence for conflicting owner, got %+v", item)
	}
	if len(item.OwnershipConflicts) != 2 {
		t.Fatalf("expected conflict owner list, got %+v", item.OwnershipConflicts)
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

func TestControlBacklogRoutesDiagnosticsToDebugOnly(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		Mode: "deep",
		Findings: []model.Finding{
			{
				FindingType: "parse_error",
				ToolType:    "dependency",
				Location:    "dist/generated.js",
				Repo:        "app",
				Org:         "acme",
				ParseError:  &model.ParseError{Kind: "parse_error", Path: "dist/generated.js"},
			},
			{
				FindingType: "dependency_manifest",
				ToolType:    "dependency",
				Location:    "package.json",
				Repo:        "app",
				Org:         "acme",
			},
		},
	})

	if len(backlog.Items) != 2 {
		t.Fatalf("expected two backlog items, got %+v", backlog.Items)
	}
	if backlog.Items[0].Queue != QueueInventoryHygiene && backlog.Items[1].Queue != QueueInventoryHygiene {
		t.Fatalf("expected dependency inventory to route to inventory_hygiene, got %+v", backlog.Items)
	}
	var debugItem Item
	foundDebug := false
	for _, item := range backlog.Items {
		if item.Queue == QueueDebugOnly {
			debugItem = item
			foundDebug = true
			break
		}
	}
	if !foundDebug {
		t.Fatalf("expected parser diagnostic to route to debug_only, got %+v", backlog.Items)
	}
	if debugItem.FindingVisibility != FindingVisibilityDebug {
		t.Fatalf("expected parser diagnostic to use debug visibility, got %+v", debugItem)
	}
	if debugItem.Remediation == "" {
		t.Fatalf("expected parser diagnostic to carry remediation guidance, got %+v", debugItem)
	}
}

func TestSecretScopeGapFollowsSecretScopeUnknownSignal(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
		ActionPaths: []risk.ActionPath{{
			PathID:            "apc-secret-scope",
			Org:               "acme",
			Repo:              "app",
			ToolType:          "ci_agent",
			Location:          ".github/workflows/release.yml",
			CredentialAccess:  true,
			RecommendedAction: "proof",
			CredentialProvenance: &agginventory.CredentialProvenance{
				Type:           agginventory.CredentialProvenanceStaticSecret,
				Scope:          agginventory.CredentialScopeWorkflow,
				Confidence:     ConfidenceHigh,
				RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
			},
		}},
	})
	if len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", backlog.Items)
	}
	if containsString(backlog.Items[0].EvidenceGaps, "secret_scope_evidence_missing") {
		t.Fatalf("expected known-scope credential to avoid secret scope gap, got %+v", backlog.Items[0])
	}
	if !containsString(backlog.Items[0].EvidenceGaps, "secret_rotation_evidence_missing") {
		t.Fatalf("expected rotation gap to remain, got %+v", backlog.Items[0])
	}
}

func TestMergedActionPathsPreserveControlPathRefsAndConflictingProvenance(t *testing.T) {
	t.Parallel()

	graph := &aggattack.ControlPathGraph{
		Version: "1",
		Nodes: []aggattack.ControlPathNode{
			{NodeID: "node-a", PathID: "apc-one", Kind: aggattack.ControlPathNodeControlPath},
			{NodeID: "node-b", PathID: "apc-two", Kind: aggattack.ControlPathNodeControlPath},
		},
		Edges: []aggattack.ControlPathEdge{
			{EdgeID: "edge-a", PathID: "apc-one", Kind: "path_enables_action"},
			{EdgeID: "edge-b", PathID: "apc-two", Kind: "path_enables_action"},
		},
	}
	backlog := Build(Input{
		ControlPathGraph: graph,
		ActionPaths: []risk.ActionPath{
			{
				PathID:            "apc-one",
				Org:               "acme",
				Repo:              "app",
				ToolType:          "ci_agent",
				Location:          ".github/workflows/release.yml",
				CredentialAccess:  true,
				RecommendedAction: "proof",
				CredentialProvenance: &agginventory.CredentialProvenance{
					Type:           agginventory.CredentialProvenanceStaticSecret,
					Scope:          agginventory.CredentialScopeWorkflow,
					Confidence:     ConfidenceHigh,
					RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
				},
			},
			{
				PathID:            "apc-two",
				Org:               "acme",
				Repo:              "app",
				ToolType:          "ci_agent",
				Location:          ".github/workflows/release.yml",
				CredentialAccess:  true,
				RecommendedAction: "proof",
				CredentialProvenance: &agginventory.CredentialProvenance{
					Type:           agginventory.CredentialProvenanceJIT,
					Scope:          agginventory.CredentialScopeWorkflow,
					Confidence:     ConfidenceHigh,
					RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceJIT),
				},
			},
		},
	})
	if len(backlog.Items) != 1 {
		t.Fatalf("expected merged backlog item, got %+v", backlog.Items)
	}
	item := backlog.Items[0]
	if !containsString(item.LinkedControlPathNodeIDs, "node-a") || !containsString(item.LinkedControlPathNodeIDs, "node-b") {
		t.Fatalf("expected merged node refs, got %+v", item)
	}
	if !containsString(item.LinkedControlPathEdgeIDs, "edge-a") || !containsString(item.LinkedControlPathEdgeIDs, "edge-b") {
		t.Fatalf("expected merged edge refs, got %+v", item)
	}
	if item.CredentialProvenance == nil || item.CredentialProvenance.Type != agginventory.CredentialProvenanceUnknown {
		t.Fatalf("expected conflicting merged provenance to become unknown, got %+v", item.CredentialProvenance)
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
