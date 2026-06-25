package contracts

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestSprint2SchemaExamplesValidate(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	t.Run("external control evidence sidecars", func(t *testing.T) {
		t.Parallel()

		for _, rel := range []string{
			"testinfra/contracts/fixtures/external-control-evidence/provider-export.json",
			"testinfra/contracts/fixtures/external-control-evidence/customer-owner-map.json",
			"testinfra/contracts/fixtures/sprint2/external-control-evidence.json",
		} {
			payload, err := os.ReadFile(filepath.Join(repoRoot, rel))
			if err != nil {
				t.Fatalf("read fixture %s: %v", rel, err)
			}
			if err := ingest.ValidateExternalControlEvidenceJSON(payload); err != nil {
				t.Fatalf("fixture %s must validate: %v", rel, err)
			}
		}
	})

	t.Run("control declarations example", func(t *testing.T) {
		t.Parallel()

		schemaPath := filepath.Join(repoRoot, "schemas", "v1", "evidence", "control-declarations.schema.json")
		sourcePath := filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "sprint2", "wrkr-control-declarations.yaml")
		validateYAMLFixtureAgainstSchema(t, schemaPath, sourcePath)

		root := t.TempDir()
		payload, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatalf("read declarations fixture: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), payload, 0o600); err != nil {
			t.Fatalf("write declarations fixture: %v", err)
		}

		loaded, used, err := config.LoadControlDeclarations(root)
		if err != nil {
			t.Fatalf("load declarations fixture: %v", err)
		}
		if len(used) != 1 {
			t.Fatalf("expected exactly one declarations source, got %v", used)
		}
		if loaded.SchemaVersion != config.ControlDeclarationsVersion {
			t.Fatalf("expected schema version %q, got %+v", config.ControlDeclarationsVersion, loaded)
		}
		if len(loaded.Owners) == 0 || len(loaded.Targets) == 0 || len(loaded.Controls) == 0 || len(loaded.ReviewDispositions) == 0 {
			t.Fatalf("expected owners, targets, and controls in declarations fixture, got %+v", loaded)
		}
	})

	t.Run("report action path example", func(t *testing.T) {
		t.Parallel()

		validateFixtureAgainstDefinition(t,
			filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"),
			"actionPath",
			filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "sprint2", "report-action-path.json"),
		)
	})

	t.Run("agent action bom item example", func(t *testing.T) {
		t.Parallel()

		validateFixtureAgainstDefinition(t,
			filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"),
			"item",
			filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "sprint2", "agent-action-bom-item.json"),
		)
	})
}

func TestSprint2EvidenceDecisionContract(t *testing.T) {
	t.Parallel()

	t.Run("precedence and freshness stay explicit", func(t *testing.T) {
		t.Parallel()

		generatedAt := time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC)
		decision := evidencepolicy.ResolveDecision([]evidencepolicy.Candidate{
			{
				Field:        evidencepolicy.FieldApproval,
				Value:        "release-approvers",
				SourceType:   evidencepolicy.SourceTypeSignedDeclaration,
				Source:       "wrkr-control-declarations.yaml",
				ObservedAt:   "2026-05-20T12:00:00Z",
				ValidUntil:   "2026-05-27T12:00:00Z",
				EvidenceRefs: []string{"evidence://fake/declarations#approval"},
			},
			{
				Field:        evidencepolicy.FieldApproval,
				Value:        "required-check:release-approved",
				SourceType:   evidencepolicy.SourceTypeProviderExport,
				Source:       "github_branch_protection_export",
				ObservedAt:   "2026-05-01T12:00:00Z",
				ValidUntil:   "2026-05-15T12:00:00Z",
				EvidenceRefs: []string{"evidence://fake/provider#branch-protection"},
			},
			{
				Field:        evidencepolicy.FieldApproval,
				Value:        "@acme/platform",
				SourceType:   evidencepolicy.SourceTypeCodeowners,
				Source:       "CODEOWNERS",
				ObservedAt:   "2026-05-25T12:00:00Z",
				EvidenceRefs: []string{"codeowners:CODEOWNERS:*"},
			},
		}, generatedAt)

		if decision.SelectedSourceType != evidencepolicy.SourceTypeProviderExport {
			t.Fatalf("expected provider export to win precedence, got %+v", decision)
		}
		if decision.SelectedFreshnessState != evidencepolicy.FreshnessStateExpired {
			t.Fatalf("expected selected evidence to stay expired, got %+v", decision)
		}
		if decision.ConflictState != evidencepolicy.ConflictStateResolved {
			t.Fatalf("expected resolved conflict state, got %+v", decision)
		}
		if len(decision.RejectedCandidates) != 2 {
			t.Fatalf("expected lower-precedence candidates to remain visible, got %+v", decision)
		}
		if !containsString(decision.ReasonCodes, "precedence:selected:provider_export") {
			t.Fatalf("expected precedence reason code, got %+v", decision)
		}
	})

	t.Run("contradictions stay control first", func(t *testing.T) {
		t.Parallel()

		paths := risk.ProjectActionPaths([]risk.ActionPath{{
			PathID:           "apc-sprint2-contradiction",
			Org:              "acme",
			Repo:             "acme/payments",
			ToolType:         "compiled_action",
			Location:         ".github/workflows/release.yml",
			WriteCapable:     true,
			ProductionWrite:  true,
			CredentialAccess: true,
			EvidenceDecisions: []evidencepolicy.Decision{{
				Field:                  evidencepolicy.FieldTarget,
				SelectedValue:          risk.TargetClassTestDemoSandbox,
				SelectedSourceType:     evidencepolicy.SourceTypeSignedDeclaration,
				SelectedSource:         "wrkr-control-declarations.yaml",
				SelectedEvidenceRefs:   []string{"evidence://fake/declarations#non-prod"},
				SelectedFreshnessState: evidencepolicy.FreshnessStateFresh,
				ReasonCodes:            []string{"declaration:non_production"},
			}},
			CredentialAuthority: &agginventory.CredentialAuthority{
				CredentialPresent:      true,
				CredentialUsableByPath: true,
				ReasonCodes:            []string{"credential:static_secret"},
			},
		}})

		if len(paths) != 1 {
			t.Fatalf("expected one path, got %+v", paths)
		}
		if len(paths[0].Contradictions) == 0 {
			t.Fatalf("expected contradiction payload, got %+v", paths[0])
		}
		if paths[0].ControlResolutionState != risk.ControlResolutionStateContradictoryControl {
			t.Fatalf("expected contradictory control resolution state, got %+v", paths[0])
		}
		if paths[0].ReviewBurden != risk.ReviewBurdenCritical {
			t.Fatalf("expected contradiction to require critical review, got %+v", paths[0])
		}
	})
}

func TestSprint2DocsCLIParity(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	cases := []struct {
		path    string
		needles []string
	}{
		{
			path: "docs/commands/scan.md",
			needles: []string{
				".wrkr/provenance/external-control-evidence.json",
				"wrkr-control-declarations.yaml",
				"fresh`, `stale`, `expired`, `unknown`",
				"without live provider calls",
			},
		},
		{
			path: "docs/commands/ingest.md",
			needles: []string{
				"schemas/v1/evidence/external-control-evidence.schema.json",
				"source precedence",
				"freshness metadata",
				"branch_protection",
				"deployment_approval",
				"without live provider calls",
			},
		},
		{
			path: "docs/commands/report.md",
			needles: []string{
				"`evidence_decisions[]`",
				"`contradictions[]`",
				"`accepted_risk`",
				"`closure_requirements`",
				"`lifecycle_queue`",
				"`evidence_completeness`",
			},
		},
		{
			path: "docs/commands/export.md",
			needles: []string{
				"offline-first",
				"closure criteria",
				"accepted-risk",
			},
		},
		{
			path: "docs/commands/evidence.md",
			needles: []string{
				"`runtime-evidence-correlation.json`",
				"external-control evidence classes",
				"does not replace the explicit proof-chain verification gate",
			},
		},
		{
			path: "docs/trust/contracts-and-schemas.md",
			needles: []string{
				"`schemas/v1/evidence/external-control-evidence.schema.json`",
				"`wrkr-control-declarations.yaml`",
				"`accepted_risk`",
				"`closure_requirements`",
				"`evidence_completeness`",
				"source precedence",
			},
		},
		{
			path: "docs/trust/detection-coverage-matrix.md",
			needles: []string{
				"local evidence sidecars",
				"does not default to querying provider APIs",
				"negative claims",
			},
		},
		{
			path: "schemas/v1/README.md",
			needles: []string{
				"`external-control-evidence.schema.json`",
				"`wrkr-control-declarations.yaml`",
				"`evidence_decisions[]`",
				"`contradictions[]`",
				"`closure_requirements`",
				"`evidence_completeness`",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()

			payload, err := os.ReadFile(filepath.Join(repoRoot, tc.path))
			if err != nil {
				t.Fatalf("read %s: %v", tc.path, err)
			}
			text := string(payload)
			for _, needle := range tc.needles {
				if !strings.Contains(text, needle) {
					t.Fatalf("%s missing Sprint 2 doc contract text %q", tc.path, needle)
				}
			}
		})
	}
}

func validateFixtureAgainstDefinition(t *testing.T, schemaPath, definition, fixturePath string) {
	t.Helper()

	schemaDoc := mustReadJSON(t, schemaPath)
	defs, ok := schemaDoc["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs: %s", schemaPath)
	}
	wrapper := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$defs":   defs,
		"$ref":    "#/$defs/" + definition,
	}
	wrapperPayload, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("marshal wrapper schema for %s: %v", definition, err)
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("memory.json", strings.NewReader(string(wrapperPayload))); err != nil {
		t.Fatalf("add wrapper schema resource: %v", err)
	}
	compiled, err := compiler.Compile("memory.json")
	if err != nil {
		t.Fatalf("compile wrapper schema for %s: %v", definition, err)
	}

	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse fixture %s: %v", fixturePath, err)
	}
	if err := compiled.Validate(decoded); err != nil {
		t.Fatalf("fixture %s must validate against %s: %v", fixturePath, definition, err)
	}
}

func validateYAMLFixtureAgainstSchema(t *testing.T, schemaPath, fixturePath string) {
	t.Helper()

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaPath, strings.NewReader(string(mustReadBytes(t, schemaPath)))); err != nil {
		t.Fatalf("add schema resource %s: %v", schemaPath, err)
	}
	compiled, err := compiler.Compile(schemaPath)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}

	var decoded any
	if err := yaml.Unmarshal(mustReadBytes(t, fixturePath), &decoded); err != nil {
		t.Fatalf("parse yaml fixture %s: %v", fixturePath, err)
	}
	decoded = normalizeYAMLScalars(decoded)
	if err := compiled.Validate(decoded); err != nil {
		t.Fatalf("fixture %s must validate against schema %s: %v", fixturePath, schemaPath, err)
	}
}

func mustReadBytes(t *testing.T, path string) []byte {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return payload
}

func normalizeYAMLScalars(value any) any {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC().Format(time.RFC3339)
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = normalizeYAMLScalars(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[normalizeMapKey(key)] = normalizeYAMLScalars(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeYAMLScalars(item))
		}
		return out
	default:
		return value
	}
}

func normalizeMapKey(value any) string {
	return strings.TrimSpace(fmt.Sprint(value))
}

/*
	func normalizeMapKeyLegacy(value any) string {
		switch typed := value.(type) {
		case string:
			return typed
		default:
			return strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(strings.Trim(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace(strings.TrimSpace("")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "")), "\n", " ")
		}
	}
*/
func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestSprint2ControlDeclarationsFixtureYAMLIsParseable(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	payload, err := os.ReadFile(filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "sprint2", "wrkr-control-declarations.yaml"))
	if err != nil {
		t.Fatalf("read declarations fixture: %v", err)
	}
	var decoded any
	if err := yaml.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse declarations fixture: %v", err)
	}
}
