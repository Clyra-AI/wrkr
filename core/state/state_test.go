package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestResolvePath(t *testing.T) {
	if got := ResolvePath("/tmp/custom.json"); got != "/tmp/custom.json" {
		t.Fatalf("unexpected explicit path: %q", got)
	}

	t.Setenv("WRKR_STATE_PATH", "/tmp/from-env.json")
	if got := ResolvePath(""); got != "/tmp/from-env.json" {
		t.Fatalf("unexpected env path: %q", got)
	}
}

func TestStateIntegrationRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")

	snapshot := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Targets: []source.Target{
			{Mode: "org", Value: "acme"},
			{Mode: "path", Value: "./repos"},
		},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if loaded.Target.Value != "acme/backend" {
		t.Fatalf("unexpected target: %+v", loaded.Target)
	}
	if len(loaded.Targets) != 2 || loaded.Targets[0].Mode != "org" || loaded.Targets[1].Mode != "path" {
		t.Fatalf("unexpected additive targets: %+v", loaded.Targets)
	}

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first state: %v", err)
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot second time: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second state: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("state file must be byte-stable\nfirst: %s\nsecond: %s", first, second)
	}
}

func TestSaveAddsPolicyOutcomesAndSuppressedCounts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")

	actionPaths := make([]risk.ActionPath, 0, maxSavedActionPaths+2)
	ranked := make([]risk.ScoredFinding, 0, maxSavedRankedFindings+2)
	backlogItems := make([]controlbacklog.Item, 0, maxSavedBacklogItems+2)
	for idx := 0; idx < maxSavedActionPaths+2; idx++ {
		actionPaths = append(actionPaths, risk.ActionPath{
			PathID:            "apc-" + string(rune('a'+(idx%26))),
			Org:               "acme",
			Repo:              "repo",
			ToolType:          "codex",
			RecommendedAction: "review",
		})
		backlogItems = append(backlogItems, controlbacklog.Item{
			ID:                 "cb-" + string(rune('a'+(idx%26))),
			Repo:               "repo",
			Path:               ".github/workflows/release.yml",
			ControlSurfaceType: "workflow",
		})
	}
	for idx := 0; idx < maxSavedRankedFindings+2; idx++ {
		ranked = append(ranked, risk.ScoredFinding{
			CanonicalKey: "finding-" + string(rune('a'+(idx%26))),
			Score:        float64(idx),
		})
	}

	snapshot := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/repo"},
		Findings: []source.Finding{
			{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-001", Org: "acme", Repo: "repo-a"},
			{FindingType: "policy_violation", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-001", Org: "acme", Repo: "repo-a"},
			{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-001", Org: "acme", Repo: "repo-b"},
			{FindingType: "policy_violation", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-001", Org: "acme", Repo: "repo-b"},
		},
		RiskReport: &risk.Report{
			Ranked:      ranked,
			ActionPaths: actionPaths,
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: backlogItems,
		},
	}

	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if len(loaded.PolicyOutcomes) != 1 {
		t.Fatalf("expected grouped policy outcomes to persist, got %+v", loaded.PolicyOutcomes)
	}
	if loaded.SuppressedCounts == nil || loaded.SuppressedCounts.ActionPaths <= 0 || loaded.SuppressedCounts.RankedFindings <= 0 || loaded.SuppressedCounts.ControlBacklog <= 0 {
		t.Fatalf("expected saved suppressed counts, got %+v", loaded.SuppressedCounts)
	}
	if got := len(loaded.RiskReport.ActionPaths); got != maxSavedActionPaths {
		t.Fatalf("expected capped action paths %d, got %d", maxSavedActionPaths, got)
	}
	if got := len(loaded.RiskReport.Ranked); got != maxSavedRankedFindings {
		t.Fatalf("expected capped ranked findings %d, got %d", maxSavedRankedFindings, got)
	}
	if got := len(loaded.ControlBacklog.Items); got != maxSavedBacklogItems {
		t.Fatalf("expected capped backlog items %d, got %d", maxSavedBacklogItems, got)
	}
}

func TestLoadRawMatchesLoadForCanonicalSnapshot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")

	snapshot := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Targets: []source.Target{
			{Mode: "path", Value: "./repos"},
			{Mode: "org", Value: "acme"},
		},
		Findings: []source.Finding{
			{
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Severity:    "high",
				Permissions: []string{"repo.contents.read", "repo.contents.read"},
			},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	rawLoaded, err := LoadRaw(path)
	if err != nil {
		t.Fatalf("load raw snapshot: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if !reflect.DeepEqual(rawLoaded, loaded) {
		t.Fatalf("expected raw load to match canonical load for saved snapshot\nraw=%+v\nload=%+v", rawLoaded, loaded)
	}
}

func TestLegacyEmbeddedAuthorityStateStillReads(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "legacy-state.json")
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		StandingAccess:         true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		ReasonCodes:            []string{"credential_authority:present"},
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingCloudRole,
		Provider:     "aws",
		Subject:      "release-role",
		TargetSystem: "deployment_platform",
		LikelyScope:  "deploy_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Environment:  "prod",
		Production:   true,
		Confidence:   "high",
	}
	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}
	legacy := Snapshot{
		Version: SnapshotVersion,
		Target:  source.Target{Mode: "path", Value: "./repos"},
		Inventory: &agginventory.Inventory{
			AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
				AgentID:                  "agent-1",
				ToolID:                   "tool-1",
				ToolType:                 "compiled_action",
				Org:                      "acme",
				Repos:                    []string{"acme/release"},
				Permissions:              []string{"repo.contents.write"},
				WriteCapable:             true,
				CredentialAccess:         true,
				MutableEndpointSemantics: semantics,
				CredentialAuthority:      authority,
				AuthorityBindings:        []*agginventory.AuthorityBinding{binding},
			}},
		},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                   "apc-legacy",
				Org:                      "acme",
				Repo:                     "acme/release",
				ToolType:                 "compiled_action",
				Location:                 ".github/workflows/release.yml",
				WriteCapable:             true,
				CredentialAccess:         true,
				ApprovalGap:              true,
				RecommendedAction:        "control",
				MutableEndpointSemantics: semantics,
				CredentialAuthority:      authority,
				AuthorityBindings:        []*agginventory.AuthorityBinding{binding},
			}},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{{
				Repo:                "acme/release",
				Path:                ".github/workflows/release.yml",
				CredentialAuthority: authority,
				AuthorityBindings:   []*agginventory.AuthorityBinding{binding},
			}},
		},
	}

	payload, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy snapshot: %v", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write legacy snapshot: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load legacy snapshot: %v", err)
	}
	if loaded.Inventory == nil || loaded.Inventory.CanonicalStores == nil {
		t.Fatalf("expected canonical stores after load, got %+v", loaded.Inventory)
	}
	if got := loaded.Inventory.AgentPrivilegeMap[0]; len(got.MutableEndpointSemanticRefs) == 0 || got.CredentialAuthorityRef == "" || len(got.AuthorityBindingRefs) == 0 {
		t.Fatalf("expected backfilled canonical refs on inventory, got %+v", got)
	}
	if got := loaded.RiskReport.ActionPaths[0]; len(got.MutableEndpointSemanticRefs) == 0 || got.CredentialAuthorityRef == "" || len(got.AuthorityBindingRefs) == 0 {
		t.Fatalf("expected backfilled canonical refs on action path, got %+v", got)
	}
	if got := loaded.RiskReport.ActionPaths[0]; len(got.MutableEndpointSemantics) == 0 || got.CredentialAuthority == nil || len(got.AuthorityBindings) == 0 {
		t.Fatalf("expected hydrated canonical detail on action path, got %+v", got)
	}
	if got := loaded.ControlBacklog.Items[0]; got.CredentialAuthorityRef == "" || len(got.AuthorityBindingRefs) == 0 {
		t.Fatalf("expected backfilled canonical refs on control backlog, got %+v", got)
	}
	if got := loaded.ControlBacklog.Items[0]; got.CredentialAuthority == nil || len(got.AuthorityBindings) == 0 {
		t.Fatalf("expected hydrated canonical detail on control backlog, got %+v", got)
	}
}

func TestStateSavePreservesProjectionDetailsThroughCanonicalStore(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		StandingAccess:         true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		ReasonCodes:            []string{"credential_authority:present"},
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingCloudRole,
		Provider:     "aws",
		Subject:      "release-role",
		TargetSystem: "deployment_platform",
		LikelyScope:  "deploy_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Environment:  "prod",
		Production:   true,
		Confidence:   "high",
	}
	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}

	snapshot := Snapshot{
		Target: source.Target{Mode: "path", Value: "./repos"},
		Inventory: &agginventory.Inventory{
			AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
				AgentID:      "agent-1",
				ToolID:       "tool-1",
				ToolType:     "compiled_action",
				Org:          "acme",
				Repos:        []string{"acme/release"},
				Permissions:  []string{"repo.contents.write"},
				WriteCapable: true,
			}},
		},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                   "apc-preserve",
				Org:                      "acme",
				Repo:                     "acme/release",
				ToolType:                 "compiled_action",
				Location:                 ".github/workflows/release.yml",
				WriteCapable:             true,
				CredentialAccess:         true,
				ApprovalGap:              true,
				RecommendedAction:        "control",
				MutableEndpointSemantics: semantics,
				CredentialAuthority:      authority,
				AuthorityBindings:        []*agginventory.AuthorityBinding{binding},
			}},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{{
				Repo:                "acme/release",
				Path:                ".github/workflows/release.yml",
				CredentialAuthority: authority,
				AuthorityBindings:   []*agginventory.AuthorityBinding{binding},
			}},
		},
	}

	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if loaded.Inventory == nil || loaded.Inventory.CanonicalStores == nil {
		t.Fatalf("expected canonical stores after save/load, got %+v", loaded.Inventory)
	}
	if got := loaded.RiskReport.ActionPaths[0]; len(got.MutableEndpointSemantics) == 0 || got.CredentialAuthority == nil || len(got.AuthorityBindings) == 0 {
		t.Fatalf("expected hydrated action path details after save/load, got %+v", got)
	}
	if got := loaded.ControlBacklog.Items[0]; got.CredentialAuthority == nil || len(got.AuthorityBindings) == 0 {
		t.Fatalf("expected hydrated control backlog details after save/load, got %+v", got)
	}
}

func TestSavedStateOmitsEmbeddedClonesWhenRefsExist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")
	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		StandingAccess:         true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		ReasonCodes:            []string{"credential_authority:present"},
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingCloudRole,
		Provider:     "aws",
		Subject:      "release-role",
		TargetSystem: "deployment_platform",
		LikelyScope:  "deploy_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Environment:  "prod",
		Production:   true,
		Confidence:   "high",
	}
	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}

	snapshot := Snapshot{
		Target: source.Target{Mode: "path", Value: "./repos"},
		Inventory: &agginventory.Inventory{
			AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
				AgentID:                     "agent-1",
				ToolID:                      "tool-1",
				ToolType:                    "compiled_action",
				Org:                         "acme",
				Repos:                       []string{"acme/release"},
				Permissions:                 []string{"repo.contents.write"},
				WriteCapable:                true,
				MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
				MutableEndpointSemantics:    semantics,
				CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
				CredentialAuthority:         authority,
				AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
				AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
			}},
		},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                      "apc-save-canonical",
				Org:                         "acme",
				Repo:                        "acme/release",
				ToolType:                    "compiled_action",
				Location:                    ".github/workflows/release.yml",
				WriteCapable:                true,
				CredentialAccess:            true,
				ApprovalGap:                 true,
				RecommendedAction:           "control",
				MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
				MutableEndpointSemantics:    semantics,
				CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
				CredentialAuthority:         authority,
				AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
				AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
			}},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{{
				ID:                     "cb-save-canonical",
				Repo:                   "acme/release",
				Path:                   ".github/workflows/release.yml",
				CredentialAuthorityRef: agginventory.CanonicalCredentialAuthorityRef(authority),
				CredentialAuthority:    authority,
				AuthorityBindingRefs:   agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
				AuthorityBindings:      []*agginventory.AuthorityBinding{binding},
			}},
		},
	}

	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	raw, err := LoadRaw(path)
	if err != nil {
		t.Fatalf("load raw snapshot: %v", err)
	}
	entry := raw.Inventory.AgentPrivilegeMap[0]
	if entry.CredentialAuthorityRef == "" || len(entry.AuthorityBindingRefs) == 0 || len(entry.MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs in raw saved inventory, got %+v", entry)
	}
	if entry.CredentialAuthority != nil || len(entry.AuthorityBindings) > 0 || len(entry.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected raw saved inventory to omit embedded clones, got %+v", entry)
	}

	pathOut := raw.RiskReport.ActionPaths[0]
	if pathOut.CredentialAuthorityRef == "" || len(pathOut.AuthorityBindingRefs) == 0 || len(pathOut.MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs in raw saved action path, got %+v", pathOut)
	}
	if pathOut.CredentialAuthority != nil || len(pathOut.AuthorityBindings) > 0 || len(pathOut.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected raw saved action path to omit embedded clones, got %+v", pathOut)
	}

	item := raw.ControlBacklog.Items[0]
	if item.CredentialAuthorityRef == "" || len(item.AuthorityBindingRefs) == 0 {
		t.Fatalf("expected canonical refs in raw saved backlog item, got %+v", item)
	}
	if item.CredentialAuthority != nil || len(item.AuthorityBindings) > 0 {
		t.Fatalf("expected raw saved backlog item to omit embedded clones, got %+v", item)
	}
}

func TestStateSaveIsAtomicUnderInterruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	initial := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial snapshot: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial snapshot bytes: %v", err)
	}

	var injected atomic.Bool
	restore := atomicwrite.SetBeforeRenameHookForTest(func(targetPath string, _ string) error {
		if filepath.Clean(targetPath) != filepath.Clean(path) {
			return nil
		}
		if injected.CompareAndSwap(false, true) {
			return errors.New("simulated interruption before rename")
		}
		return nil
	})
	defer restore()

	updated := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/updated"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/updated", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, updated); err == nil {
		t.Fatal("expected save interruption failure")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot after interruption: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected snapshot bytes to remain unchanged after interruption\nbefore: %s\nafter: %s", before, after)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected state file to remain parseable after interruption: %v", err)
	}
}

func TestLoadScoreViewPreservesStoredScoreAndAttackPaths(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	snapshot := Snapshot{
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Repo: "backend"},
		},
		PostureScore: &score.Result{
			Score: 81.4,
			Grade: "B",
		},
		RiskReport: &risk.Report{
			AttackPaths: []riskattack.ScoredPath{
				{
					PathID:          "path-a",
					Org:             "acme",
					Repo:            "backend",
					PathScore:       9.1,
					EntryNodeID:     "entry-a",
					TargetNodeID:    "target-a",
					EntryExposure:   3.0,
					PivotPrivilege:  2.5,
					TargetImpact:    3.6,
					EdgeRationale:   []string{"agent_to_auth_surface"},
					Explain:         []string{"entry_exposure=3.00"},
					SourceFindings:  []string{"finding-a"},
					GenerationModel: "wrkr_attack_path_v1",
				},
			},
			TopAttackPaths: []riskattack.ScoredPath{
				{
					PathID:          "path-b",
					Org:             "acme",
					Repo:            "backend",
					PathScore:       8.4,
					EntryNodeID:     "entry-b",
					TargetNodeID:    "target-b",
					EntryExposure:   2.8,
					PivotPrivilege:  2.2,
					TargetImpact:    3.4,
					EdgeRationale:   []string{"tool_to_auth_surface"},
					Explain:         []string{"entry_exposure=2.80"},
					SourceFindings:  []string{"finding-b"},
					GenerationModel: "wrkr_attack_path_v1",
				},
			},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	view, err := LoadScoreView(path)
	if err != nil {
		t.Fatalf("load score view: %v", err)
	}
	if view.PostureScore == nil || view.PostureScore.Score != 81.4 {
		t.Fatalf("unexpected stored score view: %+v", view.PostureScore)
	}
	if len(view.AttackPaths) != 1 || view.AttackPaths[0].PathID != "path-a" {
		t.Fatalf("unexpected attack paths: %+v", view.AttackPaths)
	}
	if len(view.TopAttackPaths) != 1 || view.TopAttackPaths[0].PathID != "path-b" {
		t.Fatalf("unexpected top attack paths: %+v", view.TopAttackPaths)
	}
}

func TestLoadScoreViewRejectsMalformedFindings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload string
	}{
		{
			name: "string",
			payload: `{
  "version": "v1",
  "findings": "bad",
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`,
		},
		{
			name: "number",
			payload: `{
  "version": "v1",
  "findings": 42,
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`,
		},
		{
			name: "missing",
			payload: `{
  "version": "v1",
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(tc.payload), 0o600); err != nil {
				t.Fatalf("write malformed snapshot: %v", err)
			}

			if _, err := LoadScoreView(path); err == nil {
				t.Fatal("expected malformed findings to fail score view load")
			}
		})
	}
}

func TestLoadScoreViewRejectsMalformedIdentitiesPrimitive(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	payload := []byte(`{
  "version": "v1",
  "identities": true,
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write malformed snapshot: %v", err)
	}

	if _, err := LoadScoreView(path); err == nil {
		t.Fatal("expected malformed identities to fail score view load")
	}
}

func TestLoadScoreViewRejectsNullTargetInCachedSnapshot(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	payload := []byte(`{
  "version": "v1",
  "target": null,
  "findings": [],
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write malformed snapshot: %v", err)
	}

	if _, err := LoadScoreView(path); err == nil {
		t.Fatal("expected null target to fail score view load")
	}
}
