package acceptance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	coreaction "github.com/Clyra-AI/wrkr/core/action"
	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
)

type acceptancePaths struct {
	repoRoot       string
	scanMixedRepos string
	policyRepos    string
	crossJSONL     string
}

func TestV1AcceptanceMatrix(t *testing.T) {
	paths := loadAcceptancePaths(t)

	t.Run("AC01_org_scan_flow_outputs_inventory_and_top_findings", func(t *testing.T) {
		tmp := t.TempDir()
		configPath := filepath.Join(tmp, "wrkr-config.yaml")
		statePath := filepath.Join(tmp, "state.json")
		githubAPI := newAcceptanceGitHubAPIServer(t)

		initPayload := runJSONOK(t, "init", "--non-interactive", "--org", "acme", "--config", configPath, "--json")
		if initPayload["status"] != "ok" {
			t.Fatalf("unexpected init payload: %v", initPayload)
		}

		scanPayload := runJSONOK(t, "scan", "--org", "acme", "--github-api", githubAPI, "--state", statePath, "--json")
		requireKey(t, scanPayload, "inventory")
		topFindings, ok := scanPayload["top_findings"].([]any)
		if !ok || len(topFindings) == 0 {
			t.Fatalf("expected non-empty top_findings, got %T (%v)", scanPayload["top_findings"], scanPayload["top_findings"])
		}
	})

	t.Run("AC02_report_pdf_generation", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		reportPDF := filepath.Join(t.TempDir(), "wrkr-report.pdf")
		payload := runJSONOK(t, "report", "--state", statePath, "--top", "5", "--pdf", "--pdf-path", reportPDF, "--json")
		requireKey(t, payload, "pdf_path")
		if _, err := os.Stat(reportPDF); err != nil {
			t.Fatalf("expected report pdf to exist: %v", err)
		}
	})

	t.Run("AC03_evidence_bundle_signed_and_verifiable", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		evidenceDir := filepath.Join(t.TempDir(), "evidence")
		payload := runJSONOK(t, "evidence", "--frameworks", "eu-ai-act,soc2", "--state", statePath, "--output", evidenceDir, "--json")
		requireKey(t, payload, "manifest_path")
		requireKey(t, payload, "chain_path")

		verifyPayload := runJSONOK(t, "verify", "--chain", "--state", statePath, "--json")
		chain, ok := verifyPayload["chain"].(map[string]any)
		if !ok || chain["intact"] != true {
			t.Fatalf("expected intact proof chain, got %v", verifyPayload)
		}
	})

	t.Run("AC04_fix_top3_deterministic_plan", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		first := runJSONOK(t, "fix", "--top", "3", "--state", statePath, "--json")
		second := runJSONOK(t, "fix", "--top", "3", "--state", statePath, "--json")
		if first["fingerprint"] != second["fingerprint"] {
			t.Fatalf("expected deterministic fingerprint, got %v and %v", first["fingerprint"], second["fingerprint"])
		}
		if count, ok := first["remediation_count"].(float64); !ok || int(count) <= 0 {
			t.Fatalf("expected remediation_count > 0, got %v", first["remediation_count"])
		}

		configPath := filepath.Join(t.TempDir(), "config.json")
		githubAPI := newAcceptanceGitHubPRServer(t)
		_ = runJSONOK(
			t,
			"init",
			"--non-interactive",
			"--repo",
			"acme/backend",
			"--scan-token",
			"scan-token",
			"--fix-token",
			"fix-token",
			"--config",
			configPath,
			"--json",
		)

		prPayload := runJSONOK(
			t,
			"fix",
			"--top",
			"3",
			"--state",
			statePath,
			"--config",
			configPath,
			"--open-pr",
			"--repo",
			"acme/backend",
			"--schedule-key",
			"weekly",
			"--github-api",
			githubAPI,
			"--json",
		)
		requireObject(t, prPayload, "pull_request")
		artifacts := requireObject(t, prPayload, "remediation_artifacts")
		changed, ok := artifacts["changed_count"].(float64)
		if !ok || int(changed) <= 0 {
			t.Fatalf("expected remediation_artifacts.changed_count > 0, got %v", artifacts["changed_count"])
		}
	})

	t.Run("AC05_detector_fixture_coverage", func(t *testing.T) {
		payload := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", filepath.Join(t.TempDir(), "state.json"), "--json")
		findings := requireArray(t, payload, "findings")
		seenTool := map[string]bool{}
		seenCompiled := false
		for _, item := range findings {
			finding, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if tool, ok := finding["tool_type"].(string); ok {
				seenTool[tool] = true
			}
			if finding["finding_type"] == "compiled_action" {
				seenCompiled = true
			}
		}
		for _, tool := range []string{"claude", "cursor", "codex", "copilot"} {
			if !seenTool[tool] {
				t.Fatalf("missing detector coverage for %s", tool)
			}
		}
		if !seenCompiled {
			t.Fatal("missing compiled_action finding in mixed-org fixture")
		}
	})

	t.Run("AC06_scan_diff_no_noise", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state.json")
		runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", statePath, "--json")
		diffPayload := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", statePath, "--diff", "--json")
		if diffPayload["diff_empty"] != true {
			t.Fatalf("expected diff_empty=true, got %v", diffPayload["diff_empty"])
		}
	})

	t.Run("AC07_offline_path_and_enrich_dependency_guard", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state.json")
		runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", statePath, "--json")

		t.Setenv("WRKR_GITHUB_API_BASE", "")
		errPayload := runJSONErr(t, 7, "scan", "--path", paths.scanMixedRepos, "--state", statePath, "--enrich", "--json")
		errObj := requireObject(t, errPayload, "error")
		if errObj["code"] != "dependency_missing" {
			t.Fatalf("expected dependency_missing, got %v", errObj)
		}
	})

	t.Run("AC08_verify_chain_cli_and_core_verifier", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		verifyPayload := runJSONOK(t, "verify", "--chain", "--state", statePath, "--json")
		chain := requireObject(t, verifyPayload, "chain")
		if chain["intact"] != true {
			t.Fatalf("expected intact chain: %v", chain)
		}

		result, err := verifycore.Chain(proofemit.ChainPath(statePath))
		if err != nil {
			t.Fatalf("verify core chain: %v", err)
		}
		if !result.Intact {
			t.Fatalf("verify core chain is not intact: %+v", result)
		}
	})

	t.Run("AC09_cross_product_proof_chain_interop", func(t *testing.T) {
		records := loadCrossProductRecords(t, paths.crossJSONL)
		if len(records) < 3 {
			t.Fatalf("expected at least 3 mixed-source records, got %d", len(records))
		}
		chain := proof.NewChain("wrkr-proof")
		for idx, item := range records {
			record, err := proof.NewRecord(proof.RecordOpts{
				Timestamp:     time.Date(2026, 2, 21, 12, 0, idx, 0, time.UTC),
				Source:        "acceptance",
				SourceProduct: item.SourceProduct,
				Type:          item.RecordType,
				Event:         item.Event,
				Controls:      proof.Controls{PermissionsEnforced: true},
			})
			if err != nil {
				t.Fatalf("build proof record %d: %v", idx, err)
			}
			if err := proof.AppendToChain(chain, record); err != nil {
				t.Fatalf("append proof record %d: %v", idx, err)
			}
		}
		chainPath := filepath.Join(t.TempDir(), "mixed-proof-chain.json")
		writeJSON(t, chainPath, chain)
		result, err := verifycore.Chain(chainPath)
		if err != nil {
			t.Fatalf("verify mixed chain: %v", err)
		}
		if !result.Intact {
			t.Fatalf("expected mixed chain intact, got %+v", result)
		}
	})

	t.Run("AC10_regress_exit_5_with_drift_reasons", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		baselinePath := filepath.Join(t.TempDir(), "wrkr-regress-baseline.json")
		runJSONOK(t, "regress", "init", "--baseline", statePath, "--output", baselinePath, "--json")

		altRoot := filepath.Join(t.TempDir(), "repos")
		if err := os.MkdirAll(filepath.Join(altRoot, "empty-repo"), 0o755); err != nil {
			t.Fatalf("mkdir alt repo: %v", err)
		}
		driftState := filepath.Join(t.TempDir(), "drift-state.json")
		runJSONOK(t, "scan", "--path", altRoot, "--state", driftState, "--json")
		payload := runJSONAnyCode(t, 5, "regress", "run", "--baseline", baselinePath, "--state", driftState, "--json")
		if payload["drift_detected"] != true {
			t.Fatalf("expected drift=true, got %v", payload)
		}
	})

	t.Run("AC11_identity_lifecycle_and_history", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		identities := runJSONOK(t, "identity", "list", "--state", statePath, "--json")
		items := requireArray(t, identities, "identities")
		if len(items) == 0 {
			t.Fatal("expected at least one identity")
		}
		first := requireObjectItem(t, items[0])
		agentID, _ := first["agent_id"].(string)
		if strings.TrimSpace(agentID) == "" {
			t.Fatalf("missing agent_id in %v", first)
		}

		runJSONOK(t, "identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json")
		runJSONOK(t, "identity", "deprecate", agentID, "--reason", "tool retired", "--state", statePath, "--json")
		runJSONOK(t, "identity", "revoke", agentID, "--reason", "policy violation", "--state", statePath, "--json")

		showPayload := runJSONOK(t, "identity", "show", agentID, "--state", statePath, "--json")
		history := requireArray(t, showPayload, "history")
		if len(history) == 0 {
			t.Fatal("expected non-empty identity transition history")
		}

		lifecyclePayload := runJSONOK(t, "lifecycle", "--state", statePath, "--org", "local", "--json")
		lifecycleIdentities := requireArray(t, lifecyclePayload, "identities")
		foundRevoked := false
		for _, item := range lifecycleIdentities {
			record := requireObjectItem(t, item)
			if record["agent_id"] == agentID && record["status"] == "revoked" {
				foundRevoked = true
				break
			}
		}
		if !foundRevoked {
			t.Fatalf("expected revoked lifecycle state for %s", agentID)
		}
	})

	t.Run("AC12_headless_ci_autonomy_classification", func(t *testing.T) {
		payload := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", filepath.Join(t.TempDir(), "state.json"), "--json")
		inventory := requireObject(t, payload, "inventory")
		tools := requireArrayFromObject(t, inventory, "tools")
		autonomy := map[string]struct{}{}
		for _, item := range tools {
			record := requireObjectItem(t, item)
			if level, ok := record["autonomy_level"].(string); ok {
				autonomy[level] = struct{}{}
			}
		}
		for _, required := range []string{"interactive", "copilot", "headless_auto"} {
			if _, ok := autonomy[required]; !ok {
				t.Fatalf("missing autonomy level %s in inventory tool set: %v", required, mapKeys(autonomy))
			}
		}
	})

	t.Run("AC13_repo_exposure_summaries_ranked", func(t *testing.T) {
		payload := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", filepath.Join(t.TempDir(), "state.json"), "--json")
		summaries := requireArray(t, payload, "repo_exposure_summaries")
		if len(summaries) == 0 {
			t.Fatal("expected repo_exposure_summaries")
		}
		minScore := 1e9
		maxScore := -1.0
		for _, item := range summaries {
			summary := requireObjectItem(t, item)
			requireObjectKey(t, summary, "permission_union")
			requireObjectKey(t, summary, "combined_risk_score")
			score, ok := summary["combined_risk_score"].(float64)
			if !ok {
				t.Fatalf("expected numeric combined_risk_score, got %v", summary["combined_risk_score"])
			}
			if score < minScore {
				minScore = score
			}
			if score > maxScore {
				maxScore = score
			}
		}
		if maxScore < minScore {
			t.Fatalf("unexpected risk range max=%.4f min=%.4f", maxScore, minScore)
		}
	})

	t.Run("AC14_mcp_trust_scoring_and_determinism", func(t *testing.T) {
		stateA := filepath.Join(t.TempDir(), "a-state.json")
		stateB := filepath.Join(t.TempDir(), "b-state.json")
		first := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", stateA, "--json")
		second := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", stateB, "--json")

		trustA := mcpTrustScores(t, first)
		trustB := mcpTrustScores(t, second)
		if !reflect.DeepEqual(trustA, trustB) {
			t.Fatalf("expected deterministic MCP trust evidence\nfirst=%v\nsecond=%v", trustA, trustB)
		}
		if len(trustA) == 0 {
			t.Fatal("expected at least one MCP trust score")
		}
	})

	t.Run("AC15_skill_signals_refined_and_deduped", func(t *testing.T) {
		payload := runJSONOK(t, "scan", "--path", paths.scanMixedRepos, "--state", filepath.Join(t.TempDir(), "state.json"), "--json")
		ranked := requireArray(t, payload, "ranked_findings")
		seen := map[string]int{}
		for _, item := range ranked {
			record := requireObjectItem(t, item)
			key, _ := record["canonical_key"].(string)
			if strings.TrimSpace(key) == "" {
				continue
			}
			seen[key]++
		}
		for key, count := range seen {
			if count > 1 {
				t.Fatalf("duplicate canonical key %s count=%d", key, count)
			}
		}
		if seen["skill_policy_conflict:local:frontend"] != 1 {
			t.Fatalf("expected one canonical skill conflict key, got %d", seen["skill_policy_conflict:local:frontend"])
		}

		summaries := requireArray(t, payload, "repo_exposure_summaries")
		foundFrontend := false
		for _, item := range summaries {
			summary := requireObjectItem(t, item)
			if summary["repo"] != "frontend" {
				continue
			}
			foundFrontend = true
			requireObjectKey(t, summary, "skill_privilege_ceiling")
			concentration := requireObjectValue(t, summary, "skill_privilege_concentration")
			for _, key := range []string{"exec_ratio", "write_ratio", "exec_write_ratio"} {
				requireObjectKey(t, concentration, key)
			}
			sprawl := requireObjectValue(t, summary, "skill_sprawl")
			for _, key := range []string{"total", "exec", "write", "read", "none"} {
				requireObjectKey(t, sprawl, key)
			}
		}
		if !foundFrontend {
			t.Fatal("missing frontend summary for refined AC15 checks")
		}
	})

	t.Run("AC16_pr_mode_relevance_contract", func(t *testing.T) {
		docsOnly := coreaction.RunPRMode(coreaction.PRModeInput{
			ChangedPaths:    []string{"README.md", "docs/examples/quickstart.md"},
			RiskDelta:       3.0,
			ComplianceDelta: -0.2,
			BlockThreshold:  5.0,
		})
		if docsOnly.ShouldComment || docsOnly.BlockMerge {
			t.Fatalf("docs-only changes should not comment/block, got %+v", docsOnly)
		}

		relevant := coreaction.RunPRMode(coreaction.PRModeInput{
			ChangedPaths:    []string{"README.md", ".codex/config.toml"},
			RiskDelta:       6.2,
			ComplianceDelta: -2.1,
			BlockThreshold:  6.0,
		})
		if !relevant.ShouldComment || !relevant.BlockMerge {
			t.Fatalf("relevant AI config changes must comment and block on threshold breach, got %+v", relevant)
		}
	})

	t.Run("AC17_manifest_generate_under_review_and_manual_approval", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		manifestPayload := runJSONOK(t, "manifest", "generate", "--state", statePath, "--json")
		requireKey(t, manifestPayload, "manifest_path")

		manifestPath := manifest.ResolvePath(statePath)
		loaded, err := manifest.Load(manifestPath)
		if err != nil {
			t.Fatalf("load generated manifest: %v", err)
		}
		if len(loaded.Identities) == 0 {
			t.Fatal("expected generated manifest identities")
		}
		first := loaded.Identities[0]
		for _, item := range loaded.Identities {
			if item.Status != "under_review" || item.ApprovalState != "missing" {
				t.Fatalf("expected under_review + missing approval_state, got %+v", item)
			}
		}

		runJSONOK(t, "identity", "approve", first.AgentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json")
		updated, err := manifest.Load(manifestPath)
		if err != nil {
			t.Fatalf("load updated manifest: %v", err)
		}
		foundApproved := false
		for _, item := range updated.Identities {
			if item.AgentID == first.AgentID {
				if item.Status != "approved" || item.ApprovalState != "valid" {
					t.Fatalf("expected approved+valid after manual approval, got %+v", item)
				}
				foundApproved = true
				break
			}
		}
		if !foundApproved {
			t.Fatalf("approved identity %s not found", first.AgentID)
		}
	})

	t.Run("AC18_policy_rule_outcomes_deterministic", func(t *testing.T) {
		payload := runJSONOK(t, "scan", "--path", paths.policyRepos, "--state", filepath.Join(t.TempDir(), "state.json"), "--json")
		findings := requireArray(t, payload, "findings")
		rules := map[string]string{}
		for _, item := range findings {
			record := requireObjectItem(t, item)
			if record["finding_type"] != "policy_check" {
				continue
			}
			ruleID, _ := record["rule_id"].(string)
			result, _ := record["check_result"].(string)
			if strings.TrimSpace(ruleID) != "" {
				rules[ruleID] = result
			}
		}
		want := map[string]string{"WRKR-001": "fail", "WRKR-002": "fail", "WRKR-004": "pass", "WRKR-099": "fail"}
		for ruleID, expected := range want {
			if got := rules[ruleID]; got != expected {
				t.Fatalf("unexpected result for %s: got %q want %q (all=%v)", ruleID, got, expected, rules)
			}
		}
	})

	t.Run("AC19_profile_compliance_deterministic", func(t *testing.T) {
		stateA := filepath.Join(t.TempDir(), "profile-a-state.json")
		stateB := filepath.Join(t.TempDir(), "profile-b-state.json")
		first := runJSONOK(t, "scan", "--path", paths.policyRepos, "--profile", "standard", "--state", stateA, "--json")
		second := runJSONOK(t, "scan", "--path", paths.policyRepos, "--profile", "standard", "--state", stateB, "--json")

		profileA := requireObject(t, first, "profile")
		profileB := requireObject(t, second, "profile")
		if profileA["compliance_percent"] != profileB["compliance_percent"] {
			t.Fatalf("compliance_percent drifted: %v vs %v", profileA["compliance_percent"], profileB["compliance_percent"])
		}
		if !reflect.DeepEqual(profileA["failing_rules"], profileB["failing_rules"]) {
			t.Fatalf("failing_rules drifted: %v vs %v", profileA["failing_rules"], profileB["failing_rules"])
		}
	})

	t.Run("AC20_posture_score_deterministic_command_output", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.policyRepos, "standard")
		first := runJSONOK(t, "score", "--state", statePath, "--json")
		second := runJSONOK(t, "score", "--state", statePath, "--json")

		if first["score"] != second["score"] || first["grade"] != second["grade"] {
			t.Fatalf("score output drifted: first=%v second=%v", first, second)
		}
		if !reflect.DeepEqual(first["weighted_breakdown"], second["weighted_breakdown"]) {
			t.Fatalf("weighted_breakdown drifted: %v vs %v", first["weighted_breakdown"], second["weighted_breakdown"])
		}
		for _, key := range []string{"score", "grade", "weighted_breakdown", "weights", "trend_delta"} {
			requireKey(t, first, key)
		}
	})

	t.Run("AC21_report_md_pdf_deterministic_with_proof_and_actions", func(t *testing.T) {
		statePath := scanScenarioState(t, paths.scanMixedRepos, "standard")
		tmp := t.TempDir()
		mdA := filepath.Join(tmp, "report-a.md")
		mdB := filepath.Join(tmp, "report-b.md")
		pdfA := filepath.Join(tmp, "report-a.pdf")
		pdfB := filepath.Join(tmp, "report-b.pdf")

		first := runJSONOK(t, "report", "--state", statePath, "--top", "5", "--md", "--md-path", mdA, "--pdf", "--pdf-path", pdfA, "--template", "operator", "--share-profile", "internal", "--json")
		second := runJSONOK(t, "report", "--state", statePath, "--top", "5", "--md", "--md-path", mdB, "--pdf", "--pdf-path", pdfB, "--template", "operator", "--share-profile", "internal", "--json")

		normalizedFirst := normalizeAcceptanceVolatile(first)
		normalizedSecond := normalizeAcceptanceVolatile(second)
		if !reflect.DeepEqual(normalizedFirst, normalizedSecond) {
			t.Fatalf("expected deterministic report payload for AC21\nfirst=%v\nsecond=%v", normalizedFirst, normalizedSecond)
		}

		mdABytes, err := os.ReadFile(mdA)
		if err != nil {
			t.Fatalf("read first markdown: %v", err)
		}
		mdBBytes, err := os.ReadFile(mdB)
		if err != nil {
			t.Fatalf("read second markdown: %v", err)
		}
		if string(mdABytes) != string(mdBBytes) {
			t.Fatal("expected deterministic markdown output for AC21")
		}

		pdfABytes, err := os.ReadFile(pdfA)
		if err != nil {
			t.Fatalf("read first pdf: %v", err)
		}
		pdfBBytes, err := os.ReadFile(pdfB)
		if err != nil {
			t.Fatalf("read second pdf: %v", err)
		}
		if string(pdfABytes) != string(pdfBBytes) {
			t.Fatal("expected deterministic pdf output for AC21")
		}

		summary := requireObject(t, first, "summary")
		requireObjectKey(t, summary, "proof")
		requireObjectKey(t, summary, "deltas")
		actions := requireArrayFromObject(t, summary, "next_actions")
		if len(actions) == 0 {
			t.Fatal("expected prioritized next_actions for AC21")
		}
	})
}

func loadAcceptancePaths(t *testing.T) acceptancePaths {
	t.Helper()
	repoRoot := mustFindRepoRoot(t)
	return acceptancePaths{
		repoRoot:       repoRoot,
		scanMixedRepos: filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos"),
		policyRepos:    filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos"),
		crossJSONL:     filepath.Join(repoRoot, "scenarios", "cross-product", "proof-record-interop", "records-from-all-3.jsonl"),
	}
}

func newAcceptanceGitHubAPIServer(t *testing.T) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/backend"}]`)
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func newAcceptanceGitHubPRServer(t *testing.T) string {
	t.Helper()

	branch := "wrkr-bot/remediation/acme-backend/weekly"
	branchExists := false
	contentStore := map[string]string{}
	pullRequestBody := ""

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case r.Method == http.MethodGet && strings.Contains(path, "/git/ref/heads/") && strings.HasSuffix(path, "/main"):
			_, _ = fmt.Fprint(w, `{"object":{"sha":"base-sha"}}`)
		case r.Method == http.MethodGet && strings.Contains(path, "/git/ref/heads/"):
			if !branchExists || !strings.Contains(path, branch) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, `{"message":"Not Found"}`)
				return
			}
			_, _ = fmt.Fprint(w, `{"object":{"sha":"head-sha"}}`)
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/git/refs"):
			branchExists = true
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"ref":"refs/heads/`+branch+`"}`)
		case strings.Contains(path, "/contents/.wrkr/remediations/"):
			filePath := strings.SplitN(path, "/contents/", 2)[1]
			switch r.Method {
			case http.MethodGet:
				content, exists := contentStore[filePath]
				if !exists {
					w.WriteHeader(http.StatusNotFound)
					_, _ = fmt.Fprint(w, `{"message":"Not Found"}`)
					return
				}
				encoded := jsonString(content)
				_, _ = fmt.Fprintf(w, `{"sha":"sha-%s","encoding":"base64","content":%s}`, strings.ReplaceAll(filePath, "/", "-"), encoded)
			case http.MethodPut:
				var payload struct {
					Content string `json:"content"`
				}
				_ = json.NewDecoder(r.Body).Decode(&payload)
				contentStore[filePath] = payload.Content
				w.WriteHeader(http.StatusCreated)
				_, _ = fmt.Fprint(w, `{"content":{"sha":"next"}}`)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		case r.Method == http.MethodGet && strings.HasSuffix(path, "/pulls"):
			if pullRequestBody == "" {
				_, _ = fmt.Fprint(w, `[]`)
				return
			}
			_, _ = fmt.Fprint(w, `[{"number":55,"html_url":"https://example.test/pr/55","title":"wrkr remediation","body":`+jsonString(pullRequestBody)+`,"head":{"ref":"`+branch+`"},"base":{"ref":"main"}}]`)
		case r.Method == http.MethodPost && strings.HasSuffix(path, "/pulls"):
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			pullRequestBody = payload.Body
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprint(w, `{"number":55,"html_url":"https://example.test/pr/55","title":"wrkr remediation","body":`+jsonString(pullRequestBody)+`,"head":{"ref":"`+branch+`"},"base":{"ref":"main"}}`)
		case r.Method == http.MethodPatch && strings.Contains(path, "/pulls/"):
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			pullRequestBody = payload.Body
			_, _ = fmt.Fprint(w, `{"number":55,"html_url":"https://example.test/pr/55","title":"wrkr remediation","body":`+jsonString(pullRequestBody)+`,"head":{"ref":"`+branch+`"},"base":{"ref":"main"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func scanScenarioState(t *testing.T, scanPath, profile string) string {
	t.Helper()
	statePath := filepath.Join(t.TempDir(), "state.json")
	args := []string{"scan", "--path", scanPath, "--state", statePath}
	if strings.TrimSpace(profile) != "" {
		args = append(args, "--profile", profile)
	}
	args = append(args, "--json")
	runJSONOK(t, args...)
	return statePath
}

func runJSONOK(t *testing.T, args ...string) map[string]any {
	t.Helper()
	payload := runJSONAnyCode(t, 0, args...)
	return payload
}

func runJSONErr(t *testing.T, expectedCode int, args ...string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run(args, &out, &errOut)
	if code != expectedCode {
		t.Fatalf("command %v returned code %d, expected %d (stdout=%q stderr=%q)", args, code, expectedCode, out.String(), errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty stdout on error for %v, got %q", args, out.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload for %v: %v (%q)", args, err, errOut.String())
	}
	return payload
}

func runJSONAnyCode(t *testing.T, expectedCode int, args ...string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run(args, &out, &errOut)
	if code != expectedCode {
		t.Fatalf("command %v returned code %d, expected %d (stdout=%q stderr=%q)", args, code, expectedCode, out.String(), errOut.String())
	}
	if expectedCode != 0 {
		if out.Len() != 0 {
			payload := map[string]any{}
			if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
				t.Fatalf("parse non-zero stdout JSON payload for %v: %v (%q)", args, err, out.String())
			}
			return payload
		}
		payload := map[string]any{}
		if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
			t.Fatalf("parse non-zero JSON payload for %v: %v (%q)", args, err, errOut.String())
		}
		return payload
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected empty stderr for %v, got %q", args, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse JSON payload for %v: %v (%q)", args, err, out.String())
	}
	return payload
}

func normalizeAcceptanceVolatile(input map[string]any) map[string]any {
	normalized := map[string]any{}
	for key, value := range input {
		switch key {
		case "generated_at", "md_path", "pdf_path":
			continue
		default:
			normalized[key] = normalizeAcceptanceAny(value)
		}
	}
	return normalized
}

func normalizeAcceptanceAny(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, v := range typed {
			if strings.HasSuffix(k, "_path") || k == "generated_at" {
				continue
			}
			out[k] = normalizeAcceptanceAny(v)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeAcceptanceAny(item))
		}
		return out
	default:
		return typed
	}
}

type fixtureRecord struct {
	SourceProduct string         `json:"source_product"`
	RecordType    string         `json:"record_type"`
	Event         map[string]any `json:"event"`
}

func loadCrossProductRecords(t *testing.T, path string) []fixtureRecord {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		_ = file.Close()
	}()
	out := make([]fixtureRecord, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var record fixtureRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("parse jsonl line %q: %v", line, err)
		}
		out = append(out, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

func writeJSON(t *testing.T, path string, payload any) {
	t.Helper()
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mcpTrustScores(t *testing.T, scanPayload map[string]any) []string {
	t.Helper()
	findings := requireArray(t, scanPayload, "findings")
	out := make([]string, 0)
	for _, item := range findings {
		record := requireObjectItem(t, item)
		if record["tool_type"] != "mcp" {
			continue
		}
		location, _ := record["location"].(string)
		trust := ""
		evidence := requireArrayFromObject(t, record, "evidence")
		for _, evItem := range evidence {
			ev := requireObjectItem(t, evItem)
			if ev["key"] == "trust_score" {
				trust, _ = ev["value"].(string)
			}
		}
		if strings.TrimSpace(trust) == "" {
			t.Fatalf("mcp finding missing trust_score evidence: %v", record)
		}
		out = append(out, fmt.Sprintf("%s=%s", location, trust))
	}
	sort.Strings(out)
	return out
}

func requireKey(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key]; !ok {
		t.Fatalf("payload missing key %q: %v", key, payload)
	}
}

func requireObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("payload key %q is not an object: %T", key, payload[key])
	}
	return value
}

func requireArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("payload key %q is not an array: %T", key, payload[key])
	}
	return value
}

func requireArrayFromObject(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("object key %q is not an array: %T", key, payload[key])
	}
	return value
}

func requireObjectValue(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("object key %q is not an object: %T", key, payload[key])
	}
	return value
}

func requireObjectItem(t *testing.T, value any) map[string]any {
	t.Helper()
	obj, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object item, got %T", value)
	}
	return obj
}

func requireObjectKey(t *testing.T, payload map[string]any, key string) {
	t.Helper()
	if _, ok := payload[key]; !ok {
		t.Fatalf("missing key %q in object %v", key, payload)
	}
}

func mapKeys(input map[string]struct{}) []string {
	out := make([]string, 0, len(input))
	for key := range input {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func jsonString(in string) string {
	blob, _ := json.Marshal(in)
	return string(blob)
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not locate repo root")
		}
		wd = next
	}
}
