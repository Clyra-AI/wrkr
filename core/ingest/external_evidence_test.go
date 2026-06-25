package ingest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestExternalEvidenceSidecarSchemaValidation(t *testing.T) {
	t.Parallel()

	valid := []byte(`{
  "schema_version": "v1",
  "generated_at": "2026-05-25T17:30:30Z",
  "records": [
    {
      "record_kind": "external_control",
      "source_type": "provider_export",
      "source": "github_branch_protection_export",
      "issuer": "github",
      "repo": "acme/payments",
      "workflow": ".github/workflows/release.yml",
      "environment": "production",
      "observed_at": "2026-05-25T17:00:00Z",
      "evidence_class": "branch_protection",
      "evidence_refs": ["evidence://fake/provider-export.json#branch/main"]
    }
  ]
}`)
	if err := ValidateExternalControlEvidenceJSON(valid); err != nil {
		t.Fatalf("validate external evidence sidecar: %v", err)
	}

	invalid := []byte(`{
  "schema_version": "v1",
  "generated_at": "2026-05-25T17:30:30Z",
  "records": [
    {
      "record_kind": "external_control",
      "source": "missing-source-type",
      "repo": "acme/payments",
      "observed_at": "2026-05-25T17:00:00Z",
      "evidence_class": "branch_protection"
    }
  ]
}`)
	if err := ValidateExternalControlEvidenceJSON(invalid); err == nil {
		t.Fatal("expected schema validation error for missing source_type")
	}
}

func TestExternalEvidenceNormalizeStableOrder(t *testing.T) {
	t.Parallel()

	bundle := Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   "2026-05-25T17:30:30Z",
		Records: []Record{
			{
				RecordKind:    RecordKindExternalControl,
				SourceType:    "repo_policy",
				Source:        "local_gait_policy",
				Repo:          "acme/payments",
				Workflow:      ".github/workflows/release.yml",
				Environment:   "production",
				ObservedAt:    "2026-05-25T17:05:00Z",
				EvidenceClass: EvidenceClassProtectedEnvironment,
				EvidenceRefs:  []string{"evidence://fake/policy.yaml#release"},
			},
			{
				RecordKind:    RecordKindExternalControl,
				SourceType:    "provider_export",
				Source:        "github_branch_protection_export",
				Repo:          "acme/payments",
				Workflow:      ".github/workflows/release.yml",
				Environment:   "production",
				ObservedAt:    "2026-05-25T17:00:00Z",
				EvidenceClass: EvidenceClassBranchProtection,
				EvidenceRefs:  []string{"evidence://fake/provider.json#branch/main"},
			},
			{
				Source:        "runtime_probe",
				PathID:        "apc-runtime-1",
				ObservedAt:    "2026-05-25T17:10:00Z",
				EvidenceClass: EvidenceClassPolicyDecision,
			},
		},
	}

	first, err := Normalize(bundle)
	if err != nil {
		t.Fatalf("normalize first bundle: %v", err)
	}
	second, err := Normalize(bundle)
	if err != nil {
		t.Fatalf("normalize second bundle: %v", err)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first bundle: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second bundle: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("expected stable normalization\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
	if len(first.Records) != 3 {
		t.Fatalf("expected 3 normalized records, got %+v", first.Records)
	}
	if first.Records[0].SourceType != "provider_export" || first.Records[1].SourceType != "repo_policy" {
		t.Fatalf("expected source precedence sort order, got %+v", first.Records)
	}
	for _, record := range first.Records {
		if strings.TrimSpace(record.RecordID) == "" {
			t.Fatalf("expected normalized record id for %+v", record)
		}
	}
}

func TestExternalEvidenceRejectsSecretLikeValues(t *testing.T) {
	t.Parallel()

	_, err := Normalize(Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   "2026-05-25T17:30:30Z",
		Records: []Record{{
			RecordKind:    RecordKindExternalControl,
			SourceType:    "customer_owner_map",
			Source:        "customer_owner_map",
			Repo:          "acme/payments",
			Path:          ".github/workflows/release.yml",
			ObservedAt:    "2026-05-25T17:00:00Z",
			EvidenceClass: EvidenceClassOwnerAssignment,
			Owner:         "ghp_super_secret_token_value",
		}},
	})
	if err == nil {
		t.Fatal("expected secret-like value rejection")
	}
	if !strings.Contains(err.Error(), "secret-like") {
		t.Fatalf("expected secret-like rejection error, got %v", err)
	}
}

func TestExternalEvidenceCorrelatesByPathAndGraphNode(t *testing.T) {
	t.Parallel()

	summary := Correlate(state.Snapshot{
		Findings: []model.Finding{{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Repo:        "acme/payments",
			Org:         "acme",
			Location:    ".github/workflows/release.yml",
			Evidence: []model.Evidence{
				{Key: "workflow_environment", Value: "production"},
			},
		}},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                   "apc-release-1",
				AgentID:                  "wrkr:workflow-release:acme",
				Repo:                     "acme/payments",
				Location:                 ".github/workflows/release.yml",
				ToolType:                 "compiled_action",
				ActionClasses:            []string{"deploy"},
				MatchedProductionTargets: []string{"production"},
			}},
			ControlPathGraph: &aggattack.ControlPathGraph{
				Nodes: []aggattack.ControlPathNode{{
					NodeID: "workflow-node-1",
					PathID: "apc-release-1",
				}},
			},
		},
	}, "external-control-evidence.json", Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 25, 17, 30, 30, 0, time.UTC).Format(time.RFC3339),
		Records: []Record{
			{
				RecordKind:    RecordKindExternalControl,
				SourceType:    "provider_export",
				Source:        "github_environment_export",
				Repo:          "acme/payments",
				Workflow:      ".github/workflows/release.yml",
				Environment:   "production",
				ObservedAt:    time.Date(2026, 5, 25, 17, 0, 0, 0, time.UTC).Format(time.RFC3339),
				EvidenceClass: EvidenceClassProtectedEnvironment,
			},
			{
				RecordKind:    RecordKindExternalControl,
				SourceType:    "provider_export",
				Source:        "github_environment_export",
				ObservedAt:    time.Date(2026, 5, 25, 17, 1, 0, 0, time.UTC).Format(time.RFC3339),
				EvidenceClass: EvidenceClassDeploymentApproval,
				GraphNodeRefs: []string{"workflow-node-1"},
			},
		},
	})
	if summary.MatchedRecords != 2 || len(summary.Correlations) != 1 {
		t.Fatalf("expected both records to correlate, got %+v", summary)
	}
	if summary.Correlations[0].PathID != "apc-release-1" {
		t.Fatalf("expected path correlation, got %+v", summary.Correlations[0])
	}
}

func TestExternalEvidenceUnmatchedRecordsRemainAuditable(t *testing.T) {
	t.Parallel()

	summary := Correlate(state.Snapshot{
		RiskReport: &risk.Report{},
	}, "external-control-evidence.json", Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 25, 17, 30, 30, 0, time.UTC).Format(time.RFC3339),
		Records: []Record{{
			RecordKind:    RecordKindExternalControl,
			SourceType:    "ticket_export",
			Source:        "jira_approval_export",
			Repo:          "acme/payments",
			Service:       "payments-api",
			Workflow:      ".github/workflows/release.yml",
			Environment:   "production",
			ObservedAt:    time.Date(2026, 5, 25, 17, 0, 0, 0, time.UTC).Format(time.RFC3339),
			EvidenceClass: EvidenceClassApproval,
			EvidenceRefs:  []string{"evidence://fake/jira/TKT-42"},
		}},
	})
	if summary.UnmatchedRecords != 1 || len(summary.Correlations) != 1 {
		t.Fatalf("expected unmatched record to remain in summary, got %+v", summary)
	}
	if summary.Correlations[0].Status != CorrelationStatusUnmatched {
		t.Fatalf("expected unmatched correlation status, got %+v", summary.Correlations[0])
	}
	if len(summary.Correlations[0].RecordIDs) != 1 {
		t.Fatalf("expected unmatched correlation to retain record ids, got %+v", summary.Correlations[0])
	}
}

func TestExternalEvidenceCorrelatesServiceOnlyRecords(t *testing.T) {
	t.Parallel()

	summary := Correlate(state.Snapshot{
		Findings: []model.Finding{{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Repo:        "acme/payments-service",
			Org:         "acme",
			Location:    ".github/workflows/deploy.yml",
		}},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:   "apc-service-1",
				AgentID:  "wrkr:workflow-deploy:acme",
				Repo:     "acme/payments-service",
				Location: ".github/workflows/deploy.yml",
				ToolType: "compiled_action",
			}},
		},
	}, "external-control-evidence.json", Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 25, 17, 30, 30, 0, time.UTC).Format(time.RFC3339),
		Records: []Record{{
			RecordKind:    RecordKindExternalControl,
			SourceType:    "app_catalog",
			Source:        "catalog_export",
			Service:       "payments-service",
			ObservedAt:    time.Date(2026, 5, 25, 17, 0, 0, 0, time.UTC).Format(time.RFC3339),
			EvidenceClass: EvidenceClassOwnerAssignment,
			Owner:         "@acme/platform",
		}},
	})
	if summary.MatchedRecords != 1 || len(summary.Correlations) != 1 {
		t.Fatalf("expected service-only correlation, got %+v", summary)
	}
	if summary.Correlations[0].PathID != "apc-service-1" {
		t.Fatalf("expected service-only record to match apc-service-1, got %+v", summary.Correlations[0])
	}
}

func TestExternalEvidenceCorrelatesByResolutionKey(t *testing.T) {
	t.Parallel()

	summary := Correlate(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:        "apc-release-resolution",
				ResolutionKey: "rk-release-resolution",
				Repo:          "acme/payments",
				Location:      ".github/workflows/release-renamed.yml",
				ToolType:      "compiled_action",
				ActionClasses: []string{"deploy"},
			}},
		},
	}, "external-control-evidence.json", Bundle{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Date(2026, 6, 25, 17, 30, 30, 0, time.UTC).Format(time.RFC3339),
		Records: []Record{{
			RecordKind:    RecordKindExternalControl,
			SourceType:    "provider_export",
			Source:        "github_branch_protection_export",
			ResolutionKey: "rk-release-resolution",
			ObservedAt:    time.Date(2026, 6, 25, 17, 0, 0, 0, time.UTC).Format(time.RFC3339),
			EvidenceClass: EvidenceClassBranchProtection,
		}},
	})
	if summary.MatchedRecords != 1 || len(summary.Correlations) != 1 {
		t.Fatalf("expected resolution-key correlation, got %+v", summary)
	}
	if summary.Correlations[0].PathID != "apc-release-resolution" {
		t.Fatalf("expected resolution-key record to match path, got %+v", summary.Correlations[0])
	}
}

func TestNormalizeEvidenceClassPreservesWave3ProviderClasses(t *testing.T) {
	t.Parallel()

	for _, want := range []string{EvidenceClassWorkflowPermission, EvidenceClassMergeMetadata} {
		if got := normalizeEvidenceClass(want); got != want {
			t.Fatalf("expected normalizeEvidenceClass(%q)=%q, got %q", want, want, got)
		}
	}
}
