//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/proofemit"
)

func TestScenarioEpic7SkillConflictSignals(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := runScenarioScan(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	conflictCount := 0
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "skill_policy_conflict" {
			conflictCount++
		}
	}
	if conflictCount == 0 {
		t.Fatal("expected at least one skill_policy_conflict finding in mixed-org scenario")
	}

	ranked, ok := payload["ranked_findings"].([]any)
	if !ok {
		t.Fatalf("expected ranked_findings array, got %T", payload["ranked_findings"])
	}
	seen := map[string]int{}
	for _, item := range ranked {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		key, _ := record["canonical_key"].(string)
		if key == "" {
			continue
		}
		seen[key]++
	}
	if seen["skill_policy_conflict:local:frontend"] != 1 {
		t.Fatalf("expected one canonical skill conflict key for frontend, got %d", seen["skill_policy_conflict:local:frontend"])
	}

	summaries, ok := payload["repo_exposure_summaries"].([]any)
	if !ok {
		t.Fatalf("expected repo_exposure_summaries array, got %T", payload["repo_exposure_summaries"])
	}
	hasSkillFields := false
	for _, item := range summaries {
		summary, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if summary["repo"] != "frontend" {
			continue
		}
		_, hasCeiling := summary["skill_privilege_ceiling"]
		_, hasConcentration := summary["skill_privilege_concentration"]
		_, hasSprawl := summary["skill_sprawl"]
		if hasCeiling && hasConcentration && hasSprawl {
			hasSkillFields = true
		}
	}
	if !hasSkillFields {
		t.Fatal("expected frontend repo exposure summary to include skill risk fields")
	}
}

func TestScenarioEpic7PolicyOutcomesAndProofRecords(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := runScenarioScan(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	rules := map[string]string{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] != "policy_check" {
			continue
		}
		ruleID, _ := finding["rule_id"].(string)
		checkResult, _ := finding["check_result"].(string)
		if ruleID != "" {
			rules[ruleID] = checkResult
		}
	}

	want := map[string]string{"WRKR-001": "fail", "WRKR-002": "fail", "WRKR-004": "pass", "WRKR-099": "fail"}
	for ruleID, expected := range want {
		if got := rules[ruleID]; got != expected {
			t.Fatalf("unexpected policy outcome for %s: got %q want %q (all=%v)", ruleID, got, expected, rules)
		}
	}

	chainPath := proofemit.ChainPath(statePath)
	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := cli.Run([]string{"verify", "--chain", "--path", chainPath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify chain failed: %d (%s)", code, verifyErr.String())
	}

	chainPayload, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain map[string]any
	if err := json.Unmarshal(chainPayload, &chain); err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	records, ok := chain["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected chain records, got %v", chain)
	}
	hasPolicyViolationRecord := false
	for _, item := range records {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if record["record_type"] != "scan_finding" {
			continue
		}
		event, ok := record["event"].(map[string]any)
		if !ok {
			continue
		}
		if event["finding_type"] == "policy_violation" {
			hasPolicyViolationRecord = true
			break
		}
	}
	if !hasPolicyViolationRecord {
		t.Fatal("expected policy_violation proof record in chain")
	}
}

func TestScenarioEpic7ProfileAndScoreContractsDeterministic(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	first := runScenarioScan(t, []string{"scan", "--path", scanPath, "--state", statePath, "--profile", "standard", "--json"})
	second := runScenarioScan(t, []string{"scan", "--path", scanPath, "--state", statePath, "--profile", "standard", "--json"})

	profileA, ok := first["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile payload, got %T", first["profile"])
	}
	profileB, ok := second["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile payload, got %T", second["profile"])
	}
	if profileA["compliance_percent"] != profileB["compliance_percent"] {
		t.Fatalf("profile compliance must be deterministic: %v vs %v", profileA["compliance_percent"], profileB["compliance_percent"])
	}
	if !reflect.DeepEqual(profileA["failing_rules"], profileB["failing_rules"]) {
		t.Fatalf("failing_rules must be deterministic: %v vs %v", profileA["failing_rules"], profileB["failing_rules"])
	}
	for _, key := range []string{"compliance_percent", "failing_rules", "compliance_delta", "status"} {
		if _, present := profileA[key]; !present {
			t.Fatalf("profile payload missing %q: %v", key, profileA)
		}
	}

	scoreA, ok := first["posture_score"].(map[string]any)
	if !ok {
		t.Fatalf("expected posture_score payload, got %T", first["posture_score"])
	}
	for _, key := range []string{"score", "grade", "weighted_breakdown", "weights", "trend_delta"} {
		if _, present := scoreA[key]; !present {
			t.Fatalf("posture_score payload missing %q: %v", key, scoreA)
		}
	}

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := cli.Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score command failed: %d (%s)", code, scoreErr.String())
	}
	var scorePayload map[string]any
	if err := json.Unmarshal(scoreOut.Bytes(), &scorePayload); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	if scoreA["score"] != scorePayload["score"] || scoreA["grade"] != scorePayload["grade"] {
		t.Fatalf("scan posture_score and score command output mismatch: scan=%v score=%v", scoreA, scorePayload)
	}
}

func runScenarioScan(t *testing.T, args []string) map[string]any {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("scan command failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse JSON payload: %v", err)
	}
	return payload
}
