package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestStory7SchemaContractsStable(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schemasRoot := filepath.Join(repoRoot, "schemas", "v1")

	files := make([]string, 0)
	if err := filepath.WalkDir(schemasRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".schema.json") {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var schema map[string]any
		if err := json.Unmarshal(payload, &schema); err != nil {
			t.Fatalf("schema %s must parse as JSON: %v", rel, err)
		}
		if _, ok := schema["$schema"].(string); !ok {
			t.Fatalf("schema %s missing $schema", rel)
		}
		if _, hasType := schema["type"].(string); !hasType {
			if _, hasOneOf := schema["oneOf"]; !hasOneOf {
				if _, hasAnyOf := schema["anyOf"]; !hasAnyOf {
					if _, hasAllOf := schema["allOf"]; !hasAllOf {
						t.Fatalf("schema %s missing root contract discriminator (type/oneOf/anyOf/allOf)", rel)
					}
				}
			}
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		t.Fatalf("walk schemas: %v", err)
	}

	sort.Strings(files)
	want := []string{
		"schemas/v1/cli/command-envelope.schema.json",
		"schemas/v1/config/config.schema.json",
		"schemas/v1/evidence/evidence-bundle.schema.json",
		"schemas/v1/export/inventory-export.schema.json",
		"schemas/v1/findings/finding.schema.json",
		"schemas/v1/identity/identity-manifest.schema.json",
		"schemas/v1/inventory/inventory.schema.json",
		"schemas/v1/manifest/manifest.schema.json",
		"schemas/v1/policy/rule-pack.schema.json",
		"schemas/v1/profile/profile-result.schema.json",
		"schemas/v1/proof-outputs/proof-chain.schema.json",
		"schemas/v1/proof-outputs/proof-record.schema.json",
		"schemas/v1/regress/regress-baseline.schema.json",
		"schemas/v1/regress/regress-result.schema.json",
		"schemas/v1/report/report-summary.schema.json",
		"schemas/v1/risk/risk-report.schema.json",
		"schemas/v1/score/score.schema.json",
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("schema contract drift\ngot:  %v\nwant: %v", files, want)
	}
}

func TestStory7SkillConflictAndExposureContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	payload := runScanJSON(t, scanPath, statePath)

	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	conflicts := 0
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] != "skill_policy_conflict" {
			continue
		}
		conflicts++
		evidence, ok := finding["evidence"].([]any)
		if !ok {
			t.Fatalf("skill_policy_conflict must include evidence array: %v", finding)
		}
		haveGrant := false
		haveRule := false
		for _, item := range evidence {
			record, ok := item.(map[string]any)
			if !ok {
				continue
			}
			switch record["key"] {
			case "grant":
				haveGrant = true
			case "conflicting_policy_rule":
				haveRule = true
			}
		}
		if !haveGrant || !haveRule {
			t.Fatalf("skill_policy_conflict missing evidence keys grant/conflicting_policy_rule: %v", finding)
		}
	}
	if conflicts == 0 {
		t.Fatal("expected at least one skill_policy_conflict finding")
	}

	summaries, ok := payload["repo_exposure_summaries"].([]any)
	if !ok || len(summaries) == 0 {
		t.Fatalf("expected repo_exposure_summaries, got %T", payload["repo_exposure_summaries"])
	}

	foundFrontend := false
	for _, item := range summaries {
		summary, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if summary["repo"] != "frontend" {
			continue
		}
		foundFrontend = true
		if _, ok := summary["skill_privilege_ceiling"].([]any); !ok {
			t.Fatalf("frontend summary missing skill_privilege_ceiling: %v", summary)
		}
		concentration, ok := summary["skill_privilege_concentration"].(map[string]any)
		if !ok {
			t.Fatalf("frontend summary missing skill_privilege_concentration: %v", summary)
		}
		for _, key := range []string{"exec_ratio", "write_ratio", "exec_write_ratio"} {
			if _, present := concentration[key]; !present {
				t.Fatalf("skill_privilege_concentration missing %s: %v", key, concentration)
			}
		}
		sprawl, ok := summary["skill_sprawl"].(map[string]any)
		if !ok {
			t.Fatalf("frontend summary missing skill_sprawl: %v", summary)
		}
		for _, key := range []string{"total", "exec", "write", "read", "none"} {
			if _, present := sprawl[key]; !present {
				t.Fatalf("skill_sprawl missing %s: %v", key, sprawl)
			}
		}
	}
	if !foundFrontend {
		t.Fatal("expected repo_exposure_summaries entry for frontend")
	}
}

func TestStory7ConflictDedupeCanonicalContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	payload := runScanJSON(t, scanPath, statePath)
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
			t.Fatalf("ranked finding missing canonical_key: %v", record)
		}
		seen[key]++
	}

	for key, count := range seen {
		if count > 1 {
			t.Fatalf("ranked findings contain duplicate canonical key %q (%d)", key, count)
		}
	}
	if seen["skill_policy_conflict:local:frontend"] != 1 {
		t.Fatalf("expected exactly one canonical skill conflict key, got %d", seen["skill_policy_conflict:local:frontend"])
	}
}

func TestStory7ExitCodeContractsAcrossCommandFamilies(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		code int
	}{
		{name: "scan_invalid_target_combo", args: []string{"scan", "--repo", "acme/backend", "--org", "acme", "--json"}, code: 6},
		{name: "verify_missing_chain_flag", args: []string{"verify", "--json"}, code: 6},
		{name: "regress_missing_baseline", args: []string{"regress", "run", "--json"}, code: 6},
		{name: "evidence_missing_frameworks", args: []string{"evidence", "--json"}, code: 6},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			var errOut bytes.Buffer
			if code := cli.Run(tc.args, &out, &errOut); code != tc.code {
				t.Fatalf("expected exit %d, got %d (stderr=%q)", tc.code, code, errOut.String())
			}
		})
	}
}

func TestStory7EvidenceOutputDirSafetyContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")

	_ = runScanJSON(t, scanPath, statePath)

	t.Run("reject_non_managed_non_empty", func(t *testing.T) {
		outputDir := filepath.Join(tmp, "non-managed")
		if err := os.MkdirAll(outputDir, 0o750); err != nil {
			t.Fatalf("mkdir output dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
			t.Fatalf("write stale file: %v", err)
		}
		assertEvidenceUnsafeExit8(t, statePath, outputDir)
	})

	t.Run("reject_marker_directory", func(t *testing.T) {
		outputDir := filepath.Join(tmp, "marker-dir")
		if err := os.MkdirAll(filepath.Join(outputDir, ".wrkr-evidence-managed"), 0o750); err != nil {
			t.Fatalf("mkdir marker dir: %v", err)
		}
		assertEvidenceUnsafeExit8(t, statePath, outputDir)
	})

	t.Run("reject_marker_symlink", func(t *testing.T) {
		outputDir := filepath.Join(tmp, "marker-symlink")
		if err := os.MkdirAll(outputDir, 0o750); err != nil {
			t.Fatalf("mkdir output dir: %v", err)
		}
		targetPath := filepath.Join(outputDir, "marker-target.txt")
		if err := os.WriteFile(targetPath, []byte("managed by wrkr evidence build\n"), 0o600); err != nil {
			t.Fatalf("write marker target: %v", err)
		}
		if err := os.Symlink("marker-target.txt", filepath.Join(outputDir, ".wrkr-evidence-managed")); err != nil {
			t.Skipf("symlink not supported in this environment: %v", err)
		}
		assertEvidenceUnsafeExit8(t, statePath, outputDir)
	})
}

func TestStory7EvidenceManifestExcludesOwnershipMarker(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	outputDir := filepath.Join(tmp, "evidence")

	_ = runScanJSON(t, scanPath, statePath)

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", outputDir, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("evidence command failed: %d (%s)", code, errOut.String())
	}

	manifestPath := filepath.Join(outputDir, "manifest.json")
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	files, ok := manifest["files"].([]any)
	if !ok {
		t.Fatalf("manifest missing files array: %v", manifest)
	}
	for _, item := range files {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pathValue, _ := entry["path"].(string)
		if pathValue == ".wrkr-evidence-managed" {
			t.Fatal("ownership marker must be excluded from manifest entries")
		}
	}
}

func TestStory7CommandAnchorDeterminism(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	stateA := filepath.Join(tmp, "state-a.json")
	stateB := filepath.Join(tmp, "state-b.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	firstScan := runScanJSON(t, reposPath, stateA)
	secondScan := runScanJSON(t, reposPath, stateB)
	if !reflect.DeepEqual(normalizeVolatile(firstScan), normalizeVolatile(secondScan)) {
		t.Fatalf("scan --json is not deterministic after volatile-field normalization\nfirst=%v\nsecond=%v", normalizeVolatile(firstScan), normalizeVolatile(secondScan))
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := cli.Run([]string{"regress", "init", "--baseline", stateA, "--output", baselinePath, "--json"}, &initOut, &initErr); code != 0 {
		t.Fatalf("regress init failed: %d (%s)", code, initErr.String())
	}

	firstRun := runRegressJSON(t, baselinePath, stateA)
	secondRun := runRegressJSON(t, baselinePath, stateA)
	if !reflect.DeepEqual(firstRun, secondRun) {
		t.Fatalf("regress run output must be deterministic\nfirst=%v\nsecond=%v", firstRun, secondRun)
	}

	firstVerify := runVerifyJSON(t, stateA)
	secondVerify := runVerifyJSON(t, stateA)
	if !reflect.DeepEqual(firstVerify, secondVerify) {
		t.Fatalf("verify --chain --json output must be deterministic\nfirst=%v\nsecond=%v", firstVerify, secondVerify)
	}
}

func runScanJSON(t *testing.T, scanPath string, statePath string) map[string]any {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	return payload
}

func runRegressJSON(t *testing.T, baselinePath string, statePath string) map[string]any {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("regress run failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse regress payload: %v", err)
	}
	return payload
}

func runVerifyJSON(t *testing.T, statePath string) map[string]any {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("verify failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse verify payload: %v", err)
	}
	return payload
}

func assertEvidenceUnsafeExit8(t *testing.T, statePath string, outputDir string) {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", outputDir, "--json"}, &out, &errOut)
	if code != 8 {
		t.Fatalf("expected exit 8, got %d (stderr=%q)", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty stdout on unsafe output-path failure, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object in %v", payload)
	}
	if errObj["code"] != "unsafe_operation_blocked" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(8) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}

func normalizeVolatile(input map[string]any) map[string]any {
	normalized := normalizeAny(input)
	cast, _ := normalized.(map[string]any)
	return cast
}

func normalizeAny(input any) any {
	switch typed := input.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, value := range typed {
			switch key {
			case "generated_at", "exported_at", "timestamp", "created_at", "updated_at":
				continue
			default:
				out[key] = normalizeAny(value)
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, value := range typed {
			out = append(out, normalizeAny(value))
		}
		return out
	default:
		return typed
	}
}
