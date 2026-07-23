package privilegebudget

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy/productiontargets"
)

func TestBuildComputesPrivilegeBudgetAndPerAgentMap(t *testing.T) {
	t.Parallel()

	mcpToolID := identity.ToolID("mcp", ".mcp.json")
	mcpAgentID := identity.AgentID(mcpToolID, "acme")

	tools := []agginventory.Tool{
		{
			ToolID:      mcpToolID,
			AgentID:     mcpAgentID,
			ToolType:    "mcp",
			Org:         "acme",
			Repos:       []string{"acme/payments"},
			Permissions: []string{"db.write"},
			DataClass:   "code",
		},
		{
			ToolID:      "ci-1",
			AgentID:     "wrkr:ci-1:acme",
			ToolType:    "ci_agent",
			Org:         "acme",
			Repos:       []string{"acme/platform"},
			Permissions: []string{"proc.exec", "secret.read"},
			DataClass:   "credentials",
		},
	}
	findings := []model.Finding{
		{
			ToolType:    "mcp",
			Location:    ".mcp.json",
			Repo:        "acme/payments",
			Org:         "acme",
			Permissions: []string{"db.write"},
			Evidence: []model.Evidence{
				{Key: "server", Value: "postgres-prod"},
			},
		},
	}
	rules := &productiontargets.Config{
		SchemaVersion: "v1",
		Targets: productiontargets.Targets{
			MCPServers: productiontargets.MatchSet{Exact: []string{"postgres-prod"}},
		},
		WritePermissions: []string{"db.write", "filesystem.write"},
	}
	rules.Normalize()

	budget, entries := Build(tools, nil, findings, rules)
	if budget.TotalTools != 2 {
		t.Fatalf("expected total_tools=2 got %d", budget.TotalTools)
	}
	if budget.WriteCapableTools != 1 {
		t.Fatalf("expected write_capable_tools=1 got %d", budget.WriteCapableTools)
	}
	if budget.CredentialAccessTools != 1 {
		t.Fatalf("expected credential_access_tools=1 got %d", budget.CredentialAccessTools)
	}
	if budget.ExecCapableTools != 1 {
		t.Fatalf("expected exec_capable_tools=1 got %d", budget.ExecCapableTools)
	}
	if !budget.ProductionWrite.Configured {
		t.Fatal("expected production_write.configured=true")
	}
	if budget.ProductionWrite.Status != agginventory.ProductionTargetsStatusConfigured {
		t.Fatalf("expected production_write.status=%q got %q", agginventory.ProductionTargetsStatusConfigured, budget.ProductionWrite.Status)
	}
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 1 {
		t.Fatalf("expected production_write.count=1 got %v", budget.ProductionWrite.Count)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 agent map entries, got %d", len(entries))
	}
	foundProduction := false
	foundCredentialProvenance := false
	for _, item := range entries {
		if item.AgentID == mcpAgentID {
			if !item.WriteCapable {
				t.Fatal("expected mcp tool write_capable=true")
			}
			if !item.ProductionWrite {
				t.Fatal("expected mcp tool production_write=true")
			}
			foundProduction = true
		}
		if item.AgentID == "wrkr:ci-1:acme" {
			if item.CredentialProvenance == nil || item.CredentialProvenance.Type != agginventory.CredentialProvenanceUnknown {
				t.Fatalf("expected unknown credential provenance on ci entry, got %+v", item.CredentialProvenance)
			}
			foundCredentialProvenance = true
		}
	}
	if !foundProduction {
		t.Fatal("expected to find mcp production-write entry")
	}
	if !foundCredentialProvenance {
		t.Fatal("expected to find ci entry provenance")
	}
}

func TestBuildDefaultConfigUsesBuiltInProductionTargetPacks(t *testing.T) {
	t.Parallel()

	cfg := productiontargets.DefaultConfig()
	budget, entries := Build([]agginventory.Tool{}, nil, nil, &cfg)
	if !budget.ProductionWrite.Configured {
		t.Fatal("expected production_write.configured=true from built-in packs")
	}
	if budget.ProductionWrite.Status != agginventory.ProductionTargetsStatusConfigured {
		t.Fatalf("expected production_write.status=%q got %q", agginventory.ProductionTargetsStatusConfigured, budget.ProductionWrite.Status)
	}
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 0 {
		t.Fatalf("expected production count 0 when no targets matched, got %v", budget.ProductionWrite.Count)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

func TestBuildWithoutRulesLeavesProductionBudgetUnconfigured(t *testing.T) {
	t.Parallel()

	budget, entries := Build([]agginventory.Tool{}, nil, nil, nil)
	if budget.ProductionWrite.Configured {
		t.Fatal("expected production_write.configured=false without production target rules")
	}
	if budget.ProductionWrite.Status != agginventory.ProductionTargetsStatusNotConfigured {
		t.Fatalf("expected production_write.status=%q got %q", agginventory.ProductionTargetsStatusNotConfigured, budget.ProductionWrite.Status)
	}
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 0 {
		t.Fatalf("expected production count 0 when production targets are disabled, got %v", budget.ProductionWrite.Count)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

func TestBuildCustomTargetsRemainAuthoritativeOverBuiltIns(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("codex", ".github/workflows/release.yml")
	agentID := identity.AgentID(toolID, "acme")

	tools := []agginventory.Tool{
		{
			ToolID:      toolID,
			AgentID:     agentID,
			ToolType:    "codex",
			Org:         "acme",
			Repos:       []string{"acme/payments"},
			Permissions: []string{"deploy.write"},
			DataClass:   "code",
		},
	}
	findings := []model.Finding{
		{
			ToolType:    "codex",
			Location:    ".github/workflows/release.yml",
			Repo:        "acme/payments",
			Org:         "acme",
			Permissions: []string{"deploy.write"},
			Evidence: []model.Evidence{
				{Key: "env_value", Value: "production"},
				{Key: "workflow_triggers", Value: "release"},
			},
		},
	}
	rules := &productiontargets.Config{
		SchemaVersion: "v1",
		Targets: productiontargets.Targets{
			Repos: productiontargets.MatchSet{Exact: []string{"acme/other"}},
		},
	}
	rules.Normalize()

	budget, entries := Build(tools, nil, findings, rules)
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 0 {
		t.Fatalf("expected production write count=0 with non-matching custom targets, got %v", budget.ProductionWrite.Count)
	}
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	if entries[0].ProductionWrite {
		t.Fatalf("expected custom targets to suppress built-in classification, got %+v", entries[0])
	}
	if len(entries[0].MatchedProductionTargets) != 0 {
		t.Fatalf("expected no matched production targets, got %+v", entries[0].MatchedProductionTargets)
	}
}

func TestBuildKeepsRequiredArrayFieldsAsArrays(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{
		{
			ToolID:      "tool-1",
			AgentID:     "wrkr:tool-1:acme",
			ToolType:    "mcp",
			Org:         "acme",
			Permissions: nil,
			Repos:       nil,
		},
	}
	_, entries := Build(tools, nil, nil, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	if entries[0].Permissions == nil {
		t.Fatal("expected permissions to be empty array, got nil")
	}
	if entries[0].Repos == nil {
		t.Fatal("expected repos to be empty array, got nil")
	}
	encoded, err := json.Marshal(entries[0])
	if err != nil {
		t.Fatalf("marshal entry: %v", err)
	}
	asJSON := string(encoded)
	if !strings.Contains(asJSON, "\"permissions\":[]") {
		t.Fatalf("expected permissions to serialize as [], got %s", asJSON)
	}
	if !strings.Contains(asJSON, "\"repos\":[]") {
		t.Fatalf("expected repos to serialize as [], got %s", asJSON)
	}
}

func TestBuildPreservesMixedCaseOrgSignalAgentMatch(t *testing.T) {
	t.Parallel()

	mcpToolID := identity.ToolID("mcp", ".mcp.json")
	mixedCaseOrg := "Acme"
	mcpAgentID := identity.AgentID(mcpToolID, mixedCaseOrg)

	tools := []agginventory.Tool{
		{
			ToolID:      mcpToolID,
			AgentID:     mcpAgentID,
			ToolType:    "mcp",
			Org:         mixedCaseOrg,
			Repos:       []string{"acme/shared"},
			Permissions: []string{"db.write"},
		},
	}
	findings := []model.Finding{
		{
			ToolType: "mcp",
			Location: ".mcp.json",
			Org:      mixedCaseOrg,
			Repo:     "acme/shared",
			Evidence: []model.Evidence{
				{Key: "server", Value: "postgres-prod"},
			},
		},
	}
	rules := &productiontargets.Config{
		SchemaVersion: "v1",
		Targets: productiontargets.Targets{
			MCPServers: productiontargets.MatchSet{Exact: []string{"postgres-prod"}},
		},
		WritePermissions: []string{"db.write"},
	}
	rules.Normalize()

	budget, entries := Build(tools, nil, findings, rules)
	if budget.ProductionWrite.Count == nil || *budget.ProductionWrite.Count != 1 {
		t.Fatalf("expected production write count=1, got %v", budget.ProductionWrite.Count)
	}
	if len(entries) != 1 || !entries[0].ProductionWrite {
		t.Fatalf("expected entry production_write=true, got %+v", entries)
	}
}

func TestBuildIncludesAgentLayerContextDeterministically(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{
		{
			ToolID:        "langchain-1",
			AgentID:       "wrkr:langchain-inst-a:acme",
			ToolType:      "langchain",
			Org:           "acme",
			Repos:         []string{"acme/backend"},
			Permissions:   []string{"deploy.write"},
			ApprovalClass: "unapproved",
		},
	}
	agents := []agginventory.Agent{
		{
			AgentID:                "wrkr:langchain-inst-a:acme",
			AgentInstanceID:        "langchain-inst-a",
			Framework:              "langchain",
			BoundTools:             []string{"deploy.write"},
			BoundDataSources:       []string{"warehouse.events"},
			BoundAuthSurfaces:      []string{"oauth2"},
			BindingEvidenceKeys:    []string{"tool:deploy.write", "data:warehouse.events", "auth:oauth2"},
			MissingBindings:        []string{},
			DeploymentStatus:       "deployed",
			DeploymentArtifacts:    []string{".github/workflows/Release.yml"},
			DeploymentEvidenceKeys: []string{"deployment:.github/workflows/Release.yml"},
		},
	}

	_, entries := Build(tools, agents, nil, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege map entry, got %d", len(entries))
	}
	entry := entries[0]
	if entry.Framework != "langchain" {
		t.Fatalf("expected framework=langchain, got %q", entry.Framework)
	}
	if entry.DeploymentStatus != "deployed" {
		t.Fatalf("expected deployment_status=deployed, got %q", entry.DeploymentStatus)
	}
	if !reflect.DeepEqual(entry.BoundDataSources, []string{"warehouse.events"}) {
		t.Fatalf("unexpected bound_data_sources: %+v", entry.BoundDataSources)
	}
	if entry.ApprovalClassification != "unapproved" {
		t.Fatalf("unexpected approval classification: %q", entry.ApprovalClassification)
	}
	if entry.CredentialProvenance == nil || entry.CredentialProvenance.Type != agginventory.CredentialProvenanceOAuthDelegation {
		t.Fatalf("expected oauth credential provenance, got %+v", entry.CredentialProvenance)
	}
}

func TestBuildClassifiesStaticSecretCredentialProvenance(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:tool-1:acme",
		ToolType:    "ci_agent",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml", Owner: "@acme/release"}},
		Permissions: []string{"secret.read"},
		DataClass:   "credentials",
	}}
	findings := []model.Finding{{
		FindingType: "secret_presence",
		ToolType:    "secret",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "workflow_secret_refs", Value: "RELEASE_TOKEN"},
			{Key: "credential_provenance_type", Value: "static_secret"},
			{Key: "credential_subject", Value: "RELEASE_TOKEN"},
			{Key: "credential_scope", Value: "workflow"},
			{Key: "credential_confidence", Value: "high"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if entries[0].CredentialProvenance == nil {
		t.Fatal("expected credential provenance")
	}
	if entries[0].CredentialProvenance.Type != agginventory.CredentialProvenanceStaticSecret {
		t.Fatalf("expected static_secret provenance, got %+v", entries[0].CredentialProvenance)
	}
	if entries[0].CredentialProvenance.Scope != agginventory.CredentialScopeWorkflow {
		t.Fatalf("expected workflow scope, got %+v", entries[0].CredentialProvenance)
	}
}

func TestCredentialKindClassifierDoesNotRequireSecretValues(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:ci:acme",
		ToolType:    "ci_agent",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Permissions: []string{"deploy.write", "secret.read"},
		DataClass:   "credentials",
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml"}},
	}}
	findings := []model.Finding{{
		FindingType: "secret_presence",
		ToolType:    "secret",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "workflow_secret_refs", Value: "GH_APP_PRIVATE_KEY"},
			{Key: "credential_subject", Value: "GH_APP_PRIVATE_KEY"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 || entries[0].CredentialProvenance == nil {
		t.Fatalf("expected one classified entry, got %+v", entries)
	}
	if entries[0].CredentialProvenance.CredentialKind != agginventory.CredentialKindGitHubAppKey {
		t.Fatalf("expected github_app_key classification, got %+v", entries[0].CredentialProvenance)
	}
	if entries[0].CredentialProvenance.AccessType != agginventory.CredentialAccessTypeStanding {
		t.Fatalf("expected standing access type, got %+v", entries[0].CredentialProvenance)
	}
}

func TestBuildClassifiesWorkloadIdentityCredentialProvenance(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:tool-1:acme",
		ToolType:    "compiled_action",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml", Owner: "@acme/release"}},
		Permissions: []string{"deploy.write", "secret.read"},
		DataClass:   "credentials",
	}}
	findings := []model.Finding{{
		FindingType: "non_human_identity",
		ToolType:    "non_human_identity",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "identity_type", Value: "github_app"},
			{Key: "subject", Value: "release-app"},
			{Key: "credential_provenance_type", Value: "workload_identity"},
			{Key: "credential_subject", Value: "release-app"},
			{Key: "credential_scope", Value: "workflow"},
			{Key: "credential_confidence", Value: "high"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if entries[0].CredentialProvenance == nil || entries[0].CredentialProvenance.Type != agginventory.CredentialProvenanceWorkloadIdentity {
		t.Fatalf("expected workload_identity provenance, got %+v", entries[0].CredentialProvenance)
	}
}

func TestBuildClassifiesBuiltInGitHubWorkflowTokenSeparatelyFromPATs(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:ci:acme",
		ToolType:    "ci_agent",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Permissions: []string{"deploy.write"},
		DataClass:   "credentials",
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml"}},
	}}
	findings := []model.Finding{{
		FindingType: "ci_autonomy",
		ToolType:    "ci_agent",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "workflow_builtin_token", Value: "github_token"},
			{Key: "workflow_token_permission", Value: "contents=write"},
			{Key: "workflow_secret_refs", Value: "PROD_DEPLOY_PAT"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 || entries[0].CredentialProvenance == nil {
		t.Fatalf("expected one classified entry, got %+v", entries)
	}
	if entries[0].CredentialProvenance.CredentialKind != agginventory.CredentialKindGitHubPAT {
		t.Fatalf("expected higher-risk PAT rollup to win, got %+v", entries[0].CredentialProvenance)
	}
	if len(entries[0].Credentials) != 2 {
		t.Fatalf("expected both workflow token and PAT credentials on the same path, got %+v", entries[0].Credentials)
	}
	seenWorkflowToken := false
	for _, credential := range entries[0].Credentials {
		if credential != nil && credential.CredentialKind == agginventory.CredentialKindGitHubWorkflowToken {
			seenWorkflowToken = true
			if credential.AccessType != agginventory.CredentialAccessTypeJIT || credential.StandingAccess {
				t.Fatalf("expected JIT workflow token semantics, got %+v", credential)
			}
		}
	}
	if !seenWorkflowToken {
		t.Fatalf("expected explicit workflow token credential in %+v", entries[0].Credentials)
	}
}

func TestBuildClassifiesWorkflowSecretRefsByIndividualSubject(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:ci:acme",
		ToolType:    "ci_agent",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Permissions: []string{"deploy.write", "secret.read"},
		DataClass:   "credentials",
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml"}},
	}}
	findings := []model.Finding{{
		FindingType: "ci_autonomy",
		ToolType:    "ci_agent",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "workflow_secret_refs", Value: "BROAD_PAT"},
			{Key: "workflow_secret_refs", Value: "BROAD_PAT,CLOUD_ADMIN_KEY"},
			{Key: "workflow_secret_refs", Value: "CLOUD_ADMIN_KEY"},
			{Key: "workflow_secret_refs", Value: "AWS_ACCESS_KEY_ID"},
			{Key: "workflow_secret_refs", Value: "GCP_SERVICE_ACCOUNT"},
			{Key: "workflow_secret_refs", Value: "PROD_DEPLOY_KEY"},
			{Key: "workflow_secret_refs", Value: "RELEASE_TOKEN"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one classified entry, got %+v", entries)
	}
	kindBySubject := map[string]string{}
	for _, credential := range entries[0].Credentials {
		if credential == nil {
			continue
		}
		kindBySubject[credential.Subject] = credential.CredentialKind
	}
	expected := map[string]string{
		"broad_pat":           agginventory.CredentialKindGitHubPAT,
		"cloud_admin_key":     agginventory.CredentialKindCloudAdminKey,
		"aws_access_key_id":   agginventory.CredentialKindCloudAccessKey,
		"gcp_service_account": agginventory.CredentialKindCloudAccessKey,
		"prod_deploy_key":     agginventory.CredentialKindDeployKey,
		"release_token":       agginventory.CredentialKindStaticSecret,
	}
	for subject, want := range expected {
		if got := kindBySubject[subject]; got != want {
			t.Fatalf("expected %s to classify as %s, got %s from %+v", subject, want, got, entries[0].Credentials)
		}
	}
	if got := kindBySubject["broad_pat,cloud_admin_key"]; got != "" {
		t.Fatalf("did not expect comma-joined synthetic credential subject, got kind %s from %+v", got, entries[0].Credentials)
	}
	if entries[0].CredentialProvenance == nil || entries[0].CredentialProvenance.CredentialKind != agginventory.CredentialKindCloudAdminKey {
		t.Fatalf("expected cloud_admin_key to win the rollup, got %+v", entries[0].CredentialProvenance)
	}
}

func TestClassifyCredentialKindKeepsAuthSurfaceFallbackForGenericSubjects(t *testing.T) {
	t.Parallel()

	kind, accessType, reasons := classifyCredentialKind(
		"RELEASE_TOKEN",
		[]string{"personal_access_token"},
		[]string{"deploy.write", "id-token.write"},
		findingSignals{},
	)
	if kind != agginventory.CredentialKindGitHubPAT || accessType != agginventory.CredentialAccessTypeStanding {
		t.Fatalf("expected PAT standing access from auth surface fallback, got kind=%s access=%s reasons=%v", kind, accessType, reasons)
	}
	if !containsString(reasons, "subject:github_pat") {
		t.Fatalf("expected github_pat reason in %v", reasons)
	}
}

func TestCredentialKindClassifierUsesExactIdentifierTokens(t *testing.T) {
	t.Parallel()

	for _, subject := range []string{"path", "artifact_path", "cache_dependency_path", "pattern", "restore_keys", "persist_credentials"} {
		kind, _, reasons, matched := classifyCredentialKindFromText(subject, subject, findingSignals{})
		if matched {
			t.Fatalf("ordinary input %q must not classify as credential kind %q (%v)", subject, kind, reasons)
		}
	}
	kind, accessType, _, matched := classifyCredentialKindFromText("prod_deploy_pat", "PROD_DEPLOY_PAT", findingSignals{})
	if !matched || kind != agginventory.CredentialKindGitHubPAT || accessType != agginventory.CredentialAccessTypeStanding {
		t.Fatalf("expected exact PAT token classification, got matched=%t kind=%s access=%s", matched, kind, accessType)
	}
}

func TestTypedWorkflowCredentialKindOverridesGenericFallback(t *testing.T) {
	t.Parallel()

	signals := findingSignals{EvidenceKV: map[string][]string{
		"workflow_credential_kind": {"release_token|static_secret"},
	}}
	kind, ok := typedCredentialKind(signals, "RELEASE_TOKEN")
	if !ok || kind != agginventory.CredentialKindStaticSecret {
		t.Fatalf("expected typed static secret classification, got kind=%s ok=%t", kind, ok)
	}
}

func TestTypedWorkflowCredentialsKeepSubjectSpecificReasonsAndTargets(t *testing.T) {
	t.Parallel()

	signals := findingSignals{
		Locations: []string{".github/workflows/release.yml"},
		EvidenceKV: map[string][]string{
			"workflow_credential_kind": {
				"COSIGN_PRIVATE_KEY|static_secret",
				"GITHUB_TOKEN|github_workflow_token",
				"PYPI_API_TOKEN|static_secret",
			},
			"workflow_secret_refs": {
				"COSIGN_PRIVATE_KEY,GITHUB_TOKEN,PYPI_API_TOKEN",
			},
		},
	}
	tests := []struct {
		subject      string
		targetSystem string
		likelyScope  string
	}{
		{subject: "COSIGN_PRIVATE_KEY", targetSystem: "artifact_signing", likelyScope: "artifact_sign"},
		{subject: "GITHUB_TOKEN", targetSystem: "source_control", likelyScope: "source_control_write"},
		{subject: "PYPI_API_TOKEN", targetSystem: "package_registry", likelyScope: "package_publish"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.subject, func(t *testing.T) {
			t.Parallel()

			got := credentialCandidateForSubject(
				tc.subject,
				agginventory.CredentialScopeWorkflow,
				[]string{"workflow_secret_refs"},
				[]string{"github_app_private_key"},
				nil,
				".github/workflows/release.yml",
				signals,
			)
			if got == nil {
				t.Fatal("expected credential provenance")
			}
			if got.TargetSystem != tc.targetSystem || got.LikelyScope != tc.likelyScope {
				t.Fatalf("expected %s/%s target metadata, got %+v", tc.targetSystem, tc.likelyScope, got)
			}
			if containsString(got.ClassificationReasons, "subject:github_app_private_key") {
				t.Fatalf("did not expect sibling auth context to override %s, got %+v", tc.subject, got)
			}
		})
	}
}

func TestWorkflowCredentialSubjectsExcludeKnownNonAuthoritySecretRefs(t *testing.T) {
	t.Parallel()

	signals := findingSignals{EvidenceKV: map[string][]string{
		"workflow_secret_refs": {
			"AWS_E2E_ROLE_ARN",
			"RELEASE_TOKEN",
			"SECURITY_EMAIL_TO,DOCKERHUB_USERNAME",
		},
		"workflow_noncredential_secret_refs": {
			"AWS_E2E_ROLE_ARN",
			"DOCKERHUB_USERNAME",
			"SECURITY_EMAIL_TO",
		},
	}}
	got := workflowCredentialSubjects(signals)
	if len(got) != 1 || got[0] != "release_token" {
		t.Fatalf("expected only authority-bearing workflow reference, got %v", got)
	}
}

func TestCredentialClassificationTreatsOIDCRoleARNAsTargetIdentifier(t *testing.T) {
	t.Parallel()

	signals := findingSignals{
		Locations: []string{".github/workflows/e2e-aws.yml"},
		EvidenceKV: map[string][]string{
			"workflow_secret_refs":               {"AWS_E2E_ROLE_ARN"},
			"workflow_noncredential_secret_refs": {"AWS_E2E_ROLE_ARN"},
		},
	}
	permissions := []string{"contents.read", "id-token.write", "secret.read"}
	credentials := classifyCredentialProvenances("credentials", permissions, nil, signals)
	if len(credentials) != 1 {
		t.Fatalf("expected one OIDC workload credential, got %+v", credentials)
	}
	credential := credentials[0]
	if credential.CredentialKind != agginventory.CredentialKindOIDCWorkloadID ||
		credential.AccessType != agginventory.CredentialAccessTypeWorkload ||
		credential.StandingAccess {
		t.Fatalf("expected workload identity without standing access, got %+v", credential)
	}
	if credential.Subject != "id-token.write" {
		t.Fatalf("role ARN must not become credential subject, got %+v", credential)
	}
	authority := classifyCredentialAuthority(nil, signals, true, credentials, nil)
	if authority == nil || !authority.CredentialPresent || !authority.CredentialReferencedByWorkflow || authority.StandingAccess {
		t.Fatalf("expected non-standing workflow OIDC authority, got %+v", authority)
	}
}

func TestCredentialClassificationDoesNotRecreateNonAuthoritySecretFallback(t *testing.T) {
	t.Parallel()

	signals := findingSignals{
		Locations: []string{".github/workflows/notify.yml"},
		EvidenceKV: map[string][]string{
			"workflow_secret_refs":               {"SECURITY_EMAIL_TO"},
			"workflow_noncredential_secret_refs": {"SECURITY_EMAIL_TO"},
		},
	}
	credentials := classifyCredentialProvenances("credentials", []string{"secret.read"}, nil, signals)
	if len(credentials) != 0 {
		t.Fatalf("notification recipient must not become durable credential fallback: %+v", credentials)
	}
	authority := classifyCredentialAuthority(nil, signals, true, credentials, nil)
	if authority == nil || authority.CredentialPresent || authority.CredentialReferencedByWorkflow || authority.CredentialUsableByPath {
		t.Fatalf("notification recipient must not imply credential authority: %+v", authority)
	}
}

func TestCredentialClassificationKeepsSecretsGitHubTokenJIT(t *testing.T) {
	t.Parallel()

	signals := findingSignals{
		Locations: []string{".github/workflows/release.yml"},
		EvidenceKV: map[string][]string{
			"workflow_secret_refs":     {"GITHUB_TOKEN"},
			"workflow_credential_kind": {"GITHUB_TOKEN|github_workflow_token"},
			"workflow_builtin_token":   {"github_token"},
		},
	}
	credentials := classifyCredentialProvenances("credentials", []string{"contents.write", "secret.read"}, nil, signals)
	for _, credential := range credentials {
		if credential != nil && credential.Subject == "github_token" {
			if credential.CredentialKind != agginventory.CredentialKindGitHubWorkflowToken ||
				credential.AccessType != agginventory.CredentialAccessTypeJIT ||
				credential.StandingAccess {
				t.Fatalf("expected JIT GitHub workflow token, got %+v", credential)
			}
			return
		}
	}
	t.Fatalf("expected GitHub workflow token credential in %+v", credentials)
}

func TestBuildDerivesActionClassesAndStandingPrivilegeFromCredentialSignals(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:ci:acme",
		ToolType:    "ci_agent",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Permissions: []string{"deploy.write", "secret.read"},
		DataClass:   "credentials",
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml"}},
	}}
	findings := []model.Finding{{
		FindingType: "secret_presence",
		ToolType:    "secret",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "workflow_secret_refs", Value: "PROD_DEPLOY_PAT"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %+v", entries)
	}
	entry := entries[0]
	for _, want := range []string{"deploy", "write", "credential_access"} {
		if !containsString(entry.ActionClasses, want) {
			t.Fatalf("expected action class %q in %+v", want, entry.ActionClasses)
		}
	}
	if !entry.StandingPrivilege || len(entry.StandingPrivilegeReasons) == 0 {
		t.Fatalf("expected standing privilege reasoning, got %+v", entry)
	}
}

func TestBuildConflictingDirectCredentialProvenanceFallsBackToUnknown(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:tool-1:acme",
		ToolType:    "compiled_action",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml", Owner: "@acme/release"}},
		Permissions: []string{"deploy.write", "secret.read", "id-token.write"},
		DataClass:   "credentials",
	}}
	findings := []model.Finding{
		{
			FindingType: "secret_presence",
			ToolType:    "secret",
			Location:    ".github/workflows/release.yml",
			Repo:        "acme/release",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "credential_provenance_type", Value: "static_secret"},
				{Key: "credential_subject", Value: "RELEASE_TOKEN"},
				{Key: "credential_scope", Value: "workflow"},
			},
		},
		{
			FindingType: "ci_autonomy",
			ToolType:    "ci_agent",
			Location:    ".github/workflows/release.yml",
			Repo:        "acme/release",
			Org:         "acme",
			Permissions: []string{"id-token.write"},
			Evidence: []model.Evidence{
				{Key: "credential_provenance_type", Value: "jit"},
				{Key: "credential_subject", Value: "workflow_federation"},
				{Key: "credential_scope", Value: "workflow"},
			},
		},
	}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if entries[0].CredentialProvenance == nil || entries[0].CredentialProvenance.Type != agginventory.CredentialProvenanceUnknown {
		t.Fatalf("expected conflicting direct provenance to fall back to unknown, got %+v", entries[0].CredentialProvenance)
	}
}

func TestBuildDerivesOperationalOwnerAndApprovalGapReasons(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{
		{
			ToolID:      "workflow-1",
			AgentID:     identity.AgentID(identity.ToolID("compiled_action", ".github/workflows/release.yml"), "local"),
			ToolType:    "compiled_action",
			Org:         "local",
			Repos:       []string{"alpha-service", "beta-service"},
			Permissions: []string{"deploy.write", "pull_request.write"},
			Locations: []agginventory.ToolLocation{
				{Repo: "alpha-service", Location: ".github/workflows/release.yml", Owner: "@local/alpha", OwnerSource: "codeowners", OwnershipStatus: "explicit"},
				{Repo: "beta-service", Location: ".github/workflows/release.yml", Owner: "@local/beta", OwnerSource: "codeowners", OwnershipStatus: "explicit"},
			},
		},
	}
	findings := []model.Finding{
		{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Location:    ".github/workflows/release.yml",
			Repo:        "alpha-service",
			Org:         "local",
			Permissions: []string{"deploy.write", "pull_request.write"},
			Evidence: []model.Evidence{
				{Key: "auto_deploy", Value: "true"},
				{Key: "approval_source", Value: "missing"},
				{Key: "deployment_gate", Value: "ambiguous"},
				{Key: "proof_requirement", Value: "missing"},
			},
		},
	}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if entries[0].OwnershipStatus != "unresolved" || entries[0].OwnerSource != "multi_repo_conflict" {
		t.Fatalf("expected unresolved operational owner, got %+v", entries[0])
	}
	for _, reason := range []string{"approval_source_missing", "deployment_gate_ambiguous", "proof_requirement_missing"} {
		if !containsString(entries[0].ApprovalGapReasons, reason) {
			t.Fatalf("expected approval gap reason %q in %+v", reason, entries[0].ApprovalGapReasons)
		}
	}
}

func TestBuildPrefersExplicitOwnerOverFallbackConflict(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{
		{
			ToolID:      "workflow-2",
			AgentID:     identity.AgentID(identity.ToolID("compiled_action", ".github/workflows/deploy.yml"), "local"),
			ToolType:    "compiled_action",
			Org:         "local",
			Repos:       []string{"alpha-service", "beta-service"},
			Permissions: []string{"deploy.write"},
			Locations: []agginventory.ToolLocation{
				{Repo: "alpha-service", Location: ".github/workflows/deploy.yml", Owner: "@local/security", OwnerSource: "codeowners", OwnershipStatus: "explicit"},
				{Repo: "beta-service", Location: ".github/workflows/deploy.yml", Owner: "@local/beta", OwnerSource: "repo_fallback", OwnershipStatus: "inferred"},
			},
		},
	}

	_, entries := Build(tools, nil, nil, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if entries[0].OperationalOwner != "@local/security" || entries[0].OwnerSource != "codeowners" || entries[0].OwnershipStatus != "explicit" {
		t.Fatalf("expected explicit owner to win over fallback conflict, got %+v", entries[0])
	}
}

func TestBuildDerivesWorkflowTriggerClass(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{
		{
			ToolID:      "workflow-3",
			AgentID:     identity.AgentID(identity.ToolID("compiled_action", ".github/workflows/nightly.yml"), "local"),
			ToolType:    "compiled_action",
			Org:         "local",
			Repos:       []string{"alpha-service"},
			Permissions: []string{"pull_request.write"},
		},
	}
	findings := []model.Finding{
		{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Location:    ".github/workflows/nightly.yml",
			Repo:        "alpha-service",
			Org:         "local",
			Permissions: []string{"pull_request.write"},
			Evidence: []model.Evidence{
				{Key: "workflow_triggers", Value: "schedule,workflow_dispatch"},
			},
		},
	}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if entries[0].WorkflowTriggerClass != "scheduled" {
		t.Fatalf("expected scheduled workflow trigger class, got %+v", entries[0])
	}
}

func TestBuildResolvesInstanceScopedAgentContextForToolEntries(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("langchain", "agents/main.py")
	toolAgentID := identity.AgentID(toolID, "acme")
	instanceID := identity.AgentInstanceID("langchain", "agents/main.py", "release_agent", 12, 64)

	tools := []agginventory.Tool{{
		ToolID:      toolID,
		AgentID:     toolAgentID,
		ToolType:    "langchain",
		Org:         "acme",
		Repos:       []string{"acme/backend"},
		Permissions: []string{"deploy.write"},
	}}
	agents := []agginventory.Agent{{
		AgentID:                identity.AgentID(instanceID, "acme"),
		AgentInstanceID:        instanceID,
		Framework:              "langchain",
		Org:                    "acme",
		Location:               "agents/main.py",
		BoundDataSources:       []string{"warehouse.events"},
		BindingEvidenceKeys:    []string{"data:warehouse.events"},
		DeploymentStatus:       "deployed",
		DeploymentArtifacts:    []string{".github/workflows/Deploy.yml"},
		DeploymentEvidenceKeys: []string{"deployment:.github/workflows/Deploy.yml"},
	}}

	_, entries := Build(tools, agents, nil, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege map entry, got %d", len(entries))
	}
	entry := entries[0]
	if entry.DeploymentStatus != "deployed" {
		t.Fatalf("expected deployment_status=deployed, got %q", entry.DeploymentStatus)
	}
	if !reflect.DeepEqual(entry.BoundDataSources, []string{"warehouse.events"}) {
		t.Fatalf("unexpected bound_data_sources: %+v", entry.BoundDataSources)
	}
	if !reflect.DeepEqual(entry.DeploymentEvidenceKeys, []string{"deployment:.github/workflows/Deploy.yml"}) {
		t.Fatalf("unexpected deployment_evidence_keys: %+v", entry.DeploymentEvidenceKeys)
	}
	if !reflect.DeepEqual(entry.DeploymentArtifacts, []string{".github/workflows/Deploy.yml"}) {
		t.Fatalf("unexpected deployment_artifacts: %+v", entry.DeploymentArtifacts)
	}
	if entry.AgentInstanceID != instanceID {
		t.Fatalf("expected agent_instance_id=%q, got %+v", instanceID, entry)
	}
	if entry.Location != "agents/main.py" {
		t.Fatalf("expected location=agents/main.py, got %+v", entry)
	}
}

func TestBuildCreatesSeparateInstanceScopedEntriesForAgentsInSameFile(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("crewai", "agents/crew.py")
	toolAgentID := identity.AgentID(toolID, "acme")
	researchID := identity.AgentInstanceID("crewai", "agents/crew.py", "research_agent", 4, 9)
	publishID := identity.AgentInstanceID("crewai", "agents/crew.py", "publisher_agent", 11, 16)

	tools := []agginventory.Tool{{
		ToolID:        toolID,
		AgentID:       toolAgentID,
		ToolType:      "crewai",
		Org:           "acme",
		Repos:         []string{"acme/source-only-agents"},
		Permissions:   []string{"deploy.write", "search.read", "secret.read"},
		ApprovalClass: "unapproved",
		DataClass:     "database",
	}}
	agents := []agginventory.Agent{
		{
			AgentID:           identity.AgentID(researchID, "acme"),
			AgentInstanceID:   researchID,
			Framework:         "crewai",
			Symbol:            "research_agent",
			Org:               "acme",
			Repo:              "acme/source-only-agents",
			Location:          "agents/crew.py",
			LocationRange:     &model.LocationRange{StartLine: 4, EndLine: 9},
			BoundTools:        []string{"search.read"},
			BoundDataSources:  []string{"warehouse.events"},
			BoundAuthSurfaces: []string{"OPENAI_API_KEY"},
		},
		{
			AgentID:           identity.AgentID(publishID, "acme"),
			AgentInstanceID:   publishID,
			Framework:         "crewai",
			Symbol:            "publisher_agent",
			Org:               "acme",
			Repo:              "acme/source-only-agents",
			Location:          "agents/crew.py",
			LocationRange:     &model.LocationRange{StartLine: 11, EndLine: 16},
			BoundTools:        []string{"deploy.write"},
			BoundDataSources:  []string{"prod-db"},
			BoundAuthSurfaces: []string{"GITHUB_TOKEN"},
		},
	}
	findings := []model.Finding{
		{
			FindingType:   "agent_framework",
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 4, EndLine: 9},
			Repo:          "acme/source-only-agents",
			Org:           "acme",
			Permissions:   []string{"search.read", "secret.read"},
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "research_agent"},
				{Key: "bound_tools", Value: "search.read"},
				{Key: "data_sources", Value: "warehouse.events"},
				{Key: "auth_surfaces", Value: "OPENAI_API_KEY"},
			},
		},
		{
			FindingType:   "agent_framework",
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 11, EndLine: 16},
			Repo:          "acme/source-only-agents",
			Org:           "acme",
			Permissions:   []string{"deploy.write", "secret.read"},
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "publisher_agent"},
				{Key: "bound_tools", Value: "deploy.write"},
				{Key: "data_sources", Value: "prod-db"},
				{Key: "auth_surfaces", Value: "GITHUB_TOKEN"},
			},
		},
	}

	_, entries := Build(tools, agents, findings, nil)
	if len(entries) != 2 {
		t.Fatalf("expected two instance-scoped privilege entries, got %+v", entries)
	}
	if entries[0].AgentInstanceID != researchID || entries[1].AgentInstanceID != publishID {
		t.Fatalf("unexpected entry ordering or identity: %+v", entries)
	}
	if !reflect.DeepEqual(entries[0].Permissions, []string{"search.read", "secret.read"}) {
		t.Fatalf("unexpected first entry permissions: %+v", entries[0])
	}
	if !entries[1].WriteCapable {
		t.Fatalf("expected second entry to be write-capable: %+v", entries[1])
	}
	if entries[0].WriteCapable {
		t.Fatalf("expected first entry to stay non-write-capable: %+v", entries[0])
	}
	if entries[0].Symbol != "research_agent" || entries[1].Symbol != "publisher_agent" {
		t.Fatalf("unexpected symbols: %+v", entries)
	}
}

func TestCredentialAuthoritySeparatesReferenceFromUsability(t *testing.T) {
	t.Parallel()

	signals := findingSignals{
		Locations: []string{".github/workflows/release.yml"},
		EvidenceKV: map[string][]string{
			"workflow_secret_refs": {"PROD_DEPLOY_PAT"},
		},
	}
	credentials := classifyCredentialProvenances("code", []string{"contents.read"}, nil, signals)
	provenance := classifyCredentialProvenance("code", []string{"contents.read"}, nil, signals)
	authority := classifyCredentialAuthority(nil, signals, false, credentials, provenance)

	if authority == nil {
		t.Fatal("expected normalized credential authority")
		return
	}
	if !authority.CredentialPresent || !authority.CredentialReferencedByWorkflow {
		t.Fatalf("expected workflow reference authority, got %+v", authority)
	}
	if authority.CredentialUsableByPath {
		t.Fatalf("expected workflow reference without execution linkage to remain unusable, got %+v", authority)
	}
	if authority.CredentialSource != agginventory.CredentialSourceWorkflowSecretRef {
		t.Fatalf("expected workflow secret reference source, got %+v", authority)
	}
}

func TestBuildClassifiesSaaSTokenScopeWithoutSecretValues(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:tool-1:acme",
		ToolType:    "compiled_action",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml", Owner: "@acme/release"}},
		Permissions: []string{"deploy.write", "secret.read"},
		DataClass:   "credentials",
	}}
	findings := []model.Finding{{
		FindingType: "secret_presence",
		ToolType:    "secret",
		Location:    ".github/workflows/release.yml",
		Repo:        "acme/release",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "workflow_secret_refs", Value: "SLACK_BOT_TOKEN"},
			{Key: "credential_subject", Value: "SLACK_BOT_TOKEN"},
			{Key: "credential_provenance_type", Value: "static_secret"},
			{Key: "credential_scope", Value: "workflow"},
			{Key: "credential_confidence", Value: "high"},
		},
	}}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 || entries[0].CredentialProvenance == nil || entries[0].CredentialAuthority == nil {
		t.Fatalf("expected one privilege entry with credential metadata, got %+v", entries)
	}
	if entries[0].CredentialProvenance.TargetSystem != "slack" || entries[0].CredentialProvenance.LikelyScope != "notification_write" {
		t.Fatalf("expected slack notification scope on provenance, got %+v", entries[0].CredentialProvenance)
	}
	if entries[0].CredentialAuthority.TargetSystem != "slack" || entries[0].CredentialAuthority.LikelyScope != "notification_write" {
		t.Fatalf("expected slack notification scope on authority, got %+v", entries[0].CredentialAuthority)
	}
	if len(entries[0].AuthorityBindings) != 1 || entries[0].AuthorityBindings[0].Kind != agginventory.AuthorityBindingSaaSToken {
		t.Fatalf("expected saas token authority binding, got %+v", entries[0].AuthorityBindings)
	}
}

func TestBuildKeepsIdenticalWorkflowCredentialsRepoScoped(t *testing.T) {
	t.Parallel()

	location := ".github/workflows/release.yml"
	legacyInstanceID := identity.AgentInstanceID("compiled_action", location, "release", 0, 0)
	repos := []string{"acme/service-a", "acme/service-b"}
	credentialsByRepo := map[string]string{
		"acme/service-a": "SERVICE_A_DEPLOY_PAT",
		"acme/service-b": "SERVICE_B_PYPI_API_TOKEN",
	}
	tools := []agginventory.Tool{{
		ToolID:    identity.ToolID("compiled_action", location),
		ToolType:  "compiled_action",
		Org:       "acme",
		Repos:     repos,
		Locations: []agginventory.ToolLocation{{Repo: repos[0], Location: location}, {Repo: repos[1], Location: location}},
	}}
	agents := make([]agginventory.Agent, 0, len(repos))
	findings := make([]model.Finding, 0, len(repos))
	for _, repo := range repos {
		credential := credentialsByRepo[repo]
		agents = append(agents, agginventory.Agent{
			AgentID:         identity.AgentID(legacyInstanceID, "acme"),
			AgentInstanceID: legacyInstanceID,
			ToolInstanceID:  identity.ToolInstanceID("compiled_action", repo, location, "release", 0, 0),
			Framework:       "compiled_action",
			Symbol:          "release",
			Org:             "acme",
			Repo:            repo,
			Location:        location,
		})
		findings = append(findings, model.Finding{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Location:    location,
			Repo:        repo,
			Org:         "acme",
			Permissions: []string{"deploy.write", "secret.read"},
			Evidence: []model.Evidence{
				{Key: "workflow_name", Value: "release"},
				{Key: "workflow_secret_refs", Value: credential},
				{Key: "workflow_credential_kind", Value: credential + "|static_secret"},
				{Key: "credential_subject", Value: credential},
				{Key: "credential_provenance_type", Value: "static_secret"},
				{Key: "credential_scope", Value: agginventory.CredentialScopeWorkflow},
				{Key: "credential_confidence", Value: "high"},
			},
		})
	}

	_, entries := Build(tools, agents, findings, nil)
	if len(entries) != 2 {
		t.Fatalf("expected one privilege entry per repository, got %+v", entries)
	}
	for _, entry := range entries {
		if len(entry.Repos) != 1 {
			t.Fatalf("expected repo-local path attribution, got %+v", entry)
		}
		repo := entry.Repos[0]
		want := strings.ToLower(credentialsByRepo[repo])
		got := map[string]struct{}{}
		for _, credential := range entry.Credentials {
			if credential != nil {
				got[credential.Subject] = struct{}{}
			}
		}
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %s credential %q, got %+v", repo, want, entry.Credentials)
		}
		for otherRepo, otherCredential := range credentialsByRepo {
			if otherRepo == repo {
				continue
			}
			if _, leaked := got[strings.ToLower(otherCredential)]; leaked {
				t.Fatalf("credential %q from %s leaked into %s path: %+v", otherCredential, otherRepo, repo, entry)
			}
		}
	}
}

func TestBuildCorrelatesRepoWideAuthorityBindingsIntoWorkflowEntry(t *testing.T) {
	t.Parallel()

	tools := []agginventory.Tool{{
		ToolID:      "tool-1",
		AgentID:     "wrkr:ci:acme",
		ToolType:    "compiled_action",
		Org:         "acme",
		Repos:       []string{"acme/release"},
		Locations:   []agginventory.ToolLocation{{Repo: "acme/release", Location: ".github/workflows/release.yml", Owner: "@acme/release"}},
		Permissions: []string{"deploy.write", "id-token.write"},
		DataClass:   "credentials",
	}}
	findings := []model.Finding{
		{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Location:    ".github/workflows/release.yml",
			Repo:        "acme/release",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "authority_binding", Value: "workload_identity|aws|workflow_aws_oidc|aws|aws_role|cloud_or_infra_access|write|production|true|high"},
			},
		},
		{
			FindingType: "route_endpoint",
			ToolType:    "route",
			Location:    "api/routes/payments.ts",
			Repo:        "acme/release",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "mutable_endpoint_semantic", Value: "payment|high|route|POST /payments"},
			},
		},
	}

	_, entries := Build(tools, nil, findings, nil)
	if len(entries) != 1 {
		t.Fatalf("expected one privilege entry, got %+v", entries)
	}
	if len(entries[0].AuthorityBindings) == 0 {
		t.Fatalf("expected authority bindings to survive repo-wide correlation, got %+v", entries[0])
	}
	if entries[0].AuthorityBindings[0].Provider != "aws" {
		t.Fatalf("expected aws provider on authority binding, got %+v", entries[0].AuthorityBindings)
	}
}

func TestOpenAPIRouteAuthorityRequiresDirectCorrelation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		toolType      string
		location      string
		useAgentMatch bool
	}{
		{
			name:     "openapi tool match",
			toolType: "openapi",
			location: "openapi/payments.yaml",
		},
		{
			name:     "route tool match",
			toolType: "route",
			location: "api/routes/payments.ts",
		},
		{
			name:          "openapi agent match",
			toolType:      "openapi",
			location:      "openapi/payments.yaml",
			useAgentMatch: true,
		},
		{
			name:          "route agent match",
			toolType:      "route",
			location:      "api/routes/payments.ts",
			useAgentMatch: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			findings := []model.Finding{
				{
					FindingType: "compiled_action",
					ToolType:    "compiled_action",
					Location:    ".github/workflows/release.yml",
					Repo:        "acme/payments",
					Org:         "acme",
					Evidence: []model.Evidence{
						{Key: "workflow_secret_refs", Value: "PROD_DEPLOY_PAT"},
						{Key: "credential_subject", Value: "PROD_DEPLOY_PAT"},
						{Key: "credential_provenance_type", Value: "static_secret"},
						{Key: "credential_scope", Value: agginventory.CredentialScopeWorkflow},
						{Key: "credential_confidence", Value: "high"},
						{Key: "workflow_environment", Value: "production"},
					},
				},
				{
					FindingType: tc.toolType + "_surface",
					ToolType:    tc.toolType,
					Location:    tc.location,
					Repo:        "acme/payments",
					Org:         "acme",
					Evidence: []model.Evidence{
						{Key: "mutable_endpoint_semantic", Value: "payment|high|" + tc.toolType + "|POST /v1/payments"},
					},
				},
			}

			signalsByAgent := buildSignalsByAgent(findings)
			signalsByRepoLocation := buildSignalsByRepoLocation(findings)
			signalsByRepo := buildSignalsByRepo(findings)
			tool := agginventory.Tool{
				ToolID:    tc.toolType + "-tool",
				AgentID:   "wrkr:" + tc.toolType + ":acme",
				ToolType:  tc.toolType,
				Org:       "acme",
				Repos:     []string{"acme/payments"},
				Locations: []agginventory.ToolLocation{{Repo: "acme/payments", Location: tc.location}},
			}

			var signal findingSignals
			if tc.useAgentMatch {
				signal = matchingSignalsForAgent(
					agginventory.Agent{
						AgentID:  tc.toolType + "-instance",
						Org:      "acme",
						Repo:     "acme/payments",
						Location: tc.location,
					},
					tool,
					signalsByRepoLocation,
					signalsByRepo,
				)
			} else {
				signal = matchingSignalsForTool(tool, signalsByAgent, signalsByRepoLocation, signalsByRepo)
			}

			if got := signal.EvidenceKV["workflow_secret_refs"]; len(got) > 0 {
				t.Fatalf("expected repo-wide workflow secrets to stay off %s target context, got %v", tc.toolType, got)
			}
			if got := signal.EvidenceKV["credential_subject"]; len(got) > 0 {
				t.Fatalf("expected repo-wide credential subjects to stay off %s target context, got %v", tc.toolType, got)
			}
			if got := signal.EvidenceKV["credential_provenance_type"]; len(got) > 0 {
				t.Fatalf("expected repo-wide credential provenance to stay off %s target context, got %v", tc.toolType, got)
			}
			if got := signal.EvidenceKV["workflow_environment"]; len(got) == 0 || got[0] != "production" {
				t.Fatalf("expected non-authority production context to remain available, got %v", got)
			}
		})
	}
}

func TestOpenAPIDirectAuthorityKeepsTargetLocationWhenRepoHasUnrelatedWorkflow(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "compiled_action",
			ToolType:    "compiled_action",
			Location:    ".github/workflows/release.yml",
			Repo:        "acme/payments",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "workflow_environment", Value: "production"},
				{Key: "workflow_secret_refs", Value: "PROD_DEPLOY_PAT"},
			},
		},
		{
			FindingType: "openapi_surface",
			ToolType:    "openapi",
			Location:    "openapi/payments.yaml",
			Repo:        "acme/payments",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "credential_subject", Value: "PAYMENTS_SERVICE_TOKEN"},
				{Key: "credential_provenance_type", Value: "static_secret"},
				{Key: "credential_scope", Value: agginventory.CredentialScopeTool},
				{Key: "credential_confidence", Value: "high"},
			},
		},
	}

	signalsByAgent := buildSignalsByAgent(findings)
	signalsByRepoLocation := buildSignalsByRepoLocation(findings)
	signalsByRepo := buildSignalsByRepo(findings)
	tool := agginventory.Tool{
		ToolID:    "openapi-tool",
		AgentID:   "wrkr:openapi:acme",
		ToolType:  "openapi",
		Org:       "acme",
		Repos:     []string{"acme/payments"},
		Locations: []agginventory.ToolLocation{{Repo: "acme/payments", Location: "openapi/payments.yaml"}},
	}

	signal := matchingSignalsForTool(tool, signalsByAgent, signalsByRepoLocation, signalsByRepo)
	if got := credentialEvidenceLocation(signal); got != "openapi/payments.yaml" {
		t.Fatalf("expected direct openapi credential evidence to keep target location, got %q from %+v", got, signal)
	}
	if len(signal.Locations) != 1 || signal.Locations[0] != "openapi/payments.yaml" {
		t.Fatalf("expected filtered repo-wide signals to avoid unrelated workflow locations, got %+v", signal.Locations)
	}
}
