package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
	"gopkg.in/yaml.v3"
)

func TestFindingsAndPolicySchemasPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	for _, schemaPath := range []string{
		filepath.Join(repoRoot, "schemas", "v1", "findings", "finding.schema.json"),
		filepath.Join(repoRoot, "schemas", "v1", "policy", "rule-pack.schema.json"),
	} {
		if _, err := os.Stat(schemaPath); err != nil {
			t.Fatalf("expected schema at %s: %v", schemaPath, err)
		}
	}
}

func TestBuiltinPolicyRuleIDsStable(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	path := filepath.Join(repoRoot, "core", "policy", "rules", "builtin.yaml")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read builtin policy pack: %v", err)
	}
	var pack struct {
		Rules []struct {
			ID string `yaml:"id"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(payload, &pack); err != nil {
		t.Fatalf("parse builtin policy pack: %v", err)
	}
	if len(pack.Rules) != 15 {
		t.Fatalf("expected 15 rules, got %d", len(pack.Rules))
	}
	ids := make([]string, 0, len(pack.Rules))
	for _, rule := range pack.Rules {
		ids = append(ids, rule.ID)
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for i := range ids {
		if ids[i] != sorted[i] {
			t.Fatalf("rule IDs must remain sorted for deterministic diffs: %v", ids)
		}
	}
	for _, mustHave := range []string{"WRKR-013", "WRKR-014", "WRKR-015"} {
		found := false
		for _, id := range ids {
			if id == mustHave {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected builtin rule %s", mustHave)
		}
	}
}

func TestScanFindingsCanonicalFields(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", scanPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings payload, got %T", payload["findings"])
	}
	finding, ok := findings[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected finding shape: %T", findings[0])
	}
	for _, key := range []string{"finding_type", "severity", "tool_type", "location", "org"} {
		if _, present := finding[key]; !present {
			t.Fatalf("expected canonical finding field %q in %v", key, finding)
		}
	}
}
