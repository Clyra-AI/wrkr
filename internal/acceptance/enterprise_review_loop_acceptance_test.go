package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/internal/enterprisepressure"
)

func TestEnterpriseReviewLoopFixtureBudgets(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-review-loop")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, sprint0AcceptanceRepoCount); err != nil {
		t.Fatalf("materialize review-loop fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "last-scan.json")
	_ = runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json")

	mdPath := filepath.Join(tmp, "review-loop.md")
	reportPayload := runJSONOK(
		t,
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--md", "--md-path", mdPath,
		"--json",
	)

	bom := requireObject(t, reportPayload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	if len(items) == 0 {
		t.Fatalf("expected BOM items, got %v", bom)
	}

	foundClosureActions := false
	foundAcceptRiskAction := false
	foundFalsePositiveAction := false
	foundDeclaredControlledAction := false
	for _, raw := range items {
		item := requireObjectItem(t, raw)
		if requireOptionalArrayLength(item["closure_actions"]) > 0 {
			foundClosureActions = true
		}
		for _, action := range requireOptionalObjectArray(item["closure_actions"]) {
			switch action["action_type"] {
			case "accept_risk_with_expiry":
				foundAcceptRiskAction = true
			case "mark_false_positive":
				foundFalsePositiveAction = true
			case "declare_controlled":
				foundDeclaredControlledAction = true
			}
		}
	}
	if !foundClosureActions {
		t.Fatalf("expected closure_actions on at least one enterprise BOM item, got %v", items)
	}
	if !foundAcceptRiskAction || !foundFalsePositiveAction || !foundDeclaredControlledAction {
		t.Fatalf("expected synthetic review-loop closure actions in enterprise fixture, got accept_risk=%t false_positive=%t declare_controlled=%t", foundAcceptRiskAction, foundFalsePositiveAction, foundDeclaredControlledAction)
	}

	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read review-loop markdown: %v", err)
	}
	contextIdx := strings.Index(string(markdownBytes), "## Report Context Appendix")
	if contextIdx < 0 {
		t.Fatalf("expected report context appendix in review-loop markdown, got %q", string(markdownBytes))
	}
	lead := string(markdownBytes[:contextIdx])
	leadLines := strings.Split(strings.TrimRight(lead, "\n"), "\n")
	if len(leadLines) > sprint0AcceptanceLeadLineCap {
		t.Fatalf("expected review-loop lead view under %d lines, got %d", sprint0AcceptanceLeadLineCap, len(leadLines))
	}
}

func TestEnterpriseFixtureGovernedCINotTopControlFirst(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	scanRoot := filepath.Join(tmp, "enterprise-governed-vs-broad")
	if err := enterprisepressure.MaterializeCount(scanRoot, enterprisepressure.VariantBaseline, 160); err != nil {
		t.Fatalf("materialize governed fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "last-scan.json")
	_ = runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json")
	reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "customer-redacted", "--json")
	items := requireArrayFromObject(t, reportPayload, "action_paths")

	highRiskLead := false
	for idx, raw := range items {
		item := requireObjectItem(t, raw)
		if idx < 10 && item["ci_flow_class"] == "standard_governed_ci" {
			t.Fatalf("expected standard governed CI paths to stay out of the first 10 review-first positions, got %v", item)
		}
		if idx < 10 && (item["ci_flow_class"] == "agentic_ci_flow" || item["review_burden"] == "critical") {
			highRiskLead = true
		}
	}
	if !highRiskLead {
		t.Fatalf("expected the enterprise lead to stay dominated by higher-risk paths, got %v", items[:minAcceptanceInt(10, len(items))])
	}
}

func TestEnterpriseFixtureExpiredDeclarationReopens(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	baselineRoot := filepath.Join(tmp, "baseline")
	currentRoot := filepath.Join(tmp, "current")
	if err := enterprisepressure.MaterializeCount(baselineRoot, enterprisepressure.VariantBaseline, 32); err != nil {
		t.Fatalf("materialize baseline review-loop fixture: %v", err)
	}
	if err := enterprisepressure.MaterializeCount(currentRoot, enterprisepressure.VariantCurrent, 32); err != nil {
		t.Fatalf("materialize current review-loop fixture: %v", err)
	}

	baselineState := filepath.Join(tmp, "baseline-state.json")
	currentState := filepath.Join(tmp, "current-state.json")
	_ = runJSONOK(t, "scan", "--path", baselineRoot, "--state", baselineState, "--quiet", "--json")
	_ = runJSONOK(t, "scan", "--path", currentRoot, "--state", currentState, "--quiet", "--json")

	reportPayload := runJSONOK(
		t,
		"report",
		"--state", currentState,
		"--previous-state", baselineState,
		"--template", "agent-action-bom",
		"--share-profile", "internal",
		"--json",
	)

	actionPaths := requireArrayFromObject(t, reportPayload, "action_paths")
	foundLifecycle := false
	for _, raw := range actionPaths {
		item := requireObjectItem(t, raw)
		value, _ := item["review_lifecycle_state"].(string)
		if strings.TrimSpace(value) != "" {
			foundLifecycle = true
			break
		}
	}
	if !foundLifecycle {
		t.Fatalf("expected lifecycle metadata to survive previous-state enterprise review-loop reporting, got %v", actionPaths)
	}
}

func requireOptionalObjectArray(value any) []map[string]any {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if ok {
			out = append(out, entry)
		}
	}
	return out
}

func minAcceptanceInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
