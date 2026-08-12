package workflowcap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/executiontopology"
)

func TestCatalogDiscoversNestedCaseVariedJenkinsAndParsesGroovy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCatalogFixture(t, root, "services/payments/JENKINSFILE", `
@Library('delivery-lib@v2') _
pipeline {
  stages {
    stage('deploy') {
      steps {
        input message: 'approve production'
        withCredentials([string(credentialsId: 'PROD_DEPLOY_TOKEN', variable: 'TOKEN')]) {
          sh 'kubectl apply -f deploy/'
        }
      }
    }
  }
}`)
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatalf("build workflow catalog: %v", err)
	}
	entry, ok := catalog.Lookup("services/payments/JENKINSFILE")
	if !ok {
		t.Fatalf("nested case-varied Jenkinsfile was not discovered: %v", catalog.Paths())
	}
	if entry.ParseError != nil {
		t.Fatalf("Jenkinsfile must use the Groovy adapter, not YAML: %+v", entry.ParseError)
	}
	if !entry.Result.HasSecretAccess || !entry.Result.HasApprovalGate || !containsCatalogValue(entry.Result.Capabilities, "deploy.write") {
		t.Fatalf("expected Jenkins credential, approval, and deploy facts: %+v", entry.Result)
	}
	joined := evidenceText(entry.Result)
	for _, want := range []string{"PROD_DEPLOY_TOKEN", "jenkins_shared_library|services/payments/JENKINSFILE|delivery-lib|unresolved_external", "ci_platform=jenkins"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %s", want, joined)
		}
	}
}

func TestJenkinsLibraryArrayEmitsEveryRelationship(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCatalogFixture(t, root, "Jenkinsfile", "@Library(['lib-a@v1', 'lib-b@v2']) _\npipeline { agent any }\n")

	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := catalog.Lookup("Jenkinsfile")
	if !ok || entry.ParseError != nil {
		t.Fatalf("expected parsed Jenkinsfile, got %+v", entry)
	}
	joined := evidenceText(entry.Result)
	for _, library := range []string{"|lib-a|unresolved_external", "|lib-b|unresolved_external"} {
		if !strings.Contains(joined, library) {
			t.Fatalf("missing Jenkins library relationship %q in %s", library, joined)
		}
	}
	if len(entry.Result.ExecutionRelationships) != 2 {
		t.Fatalf("expected two normalized library relationships, got %+v", entry.Result.ExecutionRelationships)
	}
}

func TestDeclaredJenkinsLibraryInheritsFactsOnlyFromSelectedSource(t *testing.T) {
	t.Parallel()
	callerRoot := t.TempDir()
	sourceRoot := t.TempDir()
	writeCatalogFixture(t, callerRoot, "Jenkinsfile", "@Library('delivery-lib@v2') _\npipeline { stages { stage('release') { steps { echo 'release' } } } }\n")
	writeCatalogFixture(t, sourceRoot, "vars/deliveryLib.groovy", "def call() { withCredentials([string(credentialsId: 'SHARED_RELEASE_TOKEN', variable: 'TOKEN')]) { sh 'helm upgrade --install service chart/' } }\n")
	topology := &executiontopology.Topology{Version: 1, Digest: "sha256:test", Mappings: []executiontopology.Mapping{{Kind: "jenkins_shared_library", Alias: "delivery-lib", SourceRepo: "acme/pipeline-lib", SourcePath: "vars/deliveryLib.groovy"}}}
	caller, err := BuildCatalog(callerRoot, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	source, err := BuildCatalog(sourceRoot, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: callerRoot, Catalog: caller}, {Repo: "acme/pipeline-lib", Root: sourceRoot, Catalog: source}})
	entry, ok := resolved[callerRoot].Lookup("Jenkinsfile")
	if !ok {
		t.Fatal("missing resolved caller")
	}
	joined := evidenceText(entry.Result)
	if !strings.Contains(joined, "SHARED_RELEASE_TOKEN") || !strings.Contains(joined, "execution_origin=inherited|acme/pipeline-lib:vars/deliveryLib.groovy|resolved_declared") {
		t.Fatalf("expected inherited source facts and origin, got %s", joined)
	}
	if !containsCatalogValue(entry.Result.Capabilities, "deploy.write") {
		t.Fatalf("expected inherited deploy capability, got %+v", entry.Result.Capabilities)
	}
}

func TestDeclaredJenkinsLibraryOutsideScanRemainsResolvedWithoutInheritance(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeCatalogFixture(t, root, "Jenkinsfile", "@Library('delivery-lib@v2') _\npipeline { stages { stage('release') { steps { echo 'release' } } } }\n")
	topology := &executiontopology.Topology{Version: 1, Digest: "sha256:test", Mappings: []executiontopology.Mapping{{Kind: "jenkins_shared_library", Alias: "delivery-lib", SourceRepo: "external/pipeline-lib", SourcePath: "vars/deliveryLib.groovy"}}}
	catalog, err := BuildCatalog(root, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	entry, ok := resolved[root].Lookup("Jenkinsfile")
	if !ok {
		t.Fatal("missing resolved caller")
	}
	if len(entry.Result.ExecutionRelationships) != 1 || entry.Result.ExecutionRelationships[0].ResolutionState != "resolved_declared" {
		t.Fatalf("external topology declaration must remain resolved without source inheritance: %+v", entry.Result.ExecutionRelationships)
	}
	if strings.Contains(evidenceText(entry.Result), "execution_origin=inherited") {
		t.Fatalf("absent source repository must not contribute inherited facts: %s", evidenceText(entry.Result))
	}
}

func TestWorkflowAliasTopologyResolvesProviderSpecificRelationship(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	alias := "acme/shared/.github/workflows/release.yml@v2"
	writeCatalogFixture(t, root, ".github/workflows/caller.yml", "name: caller\non: push\njobs:\n  release:\n    uses: "+alias+"\n")
	topology := &executiontopology.Topology{Version: 1, Digest: "sha256:test", Mappings: []executiontopology.Mapping{{Kind: "workflow_alias", Alias: alias, SourceRepo: "acme/shared", SourcePath: ".github/workflows/release.yml"}}}
	catalog, err := BuildCatalog(root, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := catalog.Lookup(".github/workflows/caller.yml")
	if !ok {
		t.Fatal("missing caller workflow")
	}
	joined := evidenceText(entry.Result)
	if !strings.Contains(joined, "github_reusable_workflow|.github/workflows/caller.yml|acme/shared:.github/workflows/release.yml|resolved_declared|topology:sha256:test") {
		t.Fatalf("generic workflow_alias mapping did not resolve provider-specific relationship: %s", joined)
	}
}

func TestAzureStaticExternalTemplateResolvesThroughTopology(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	alias := "templates/build.yml@shared"
	writeCatalogFixture(t, root, "azure-pipelines.yml", "steps:\n  - template: "+alias+"\n")
	topology := &executiontopology.Topology{Version: 1, Digest: "sha256:test", Mappings: []executiontopology.Mapping{{Kind: "workflow_alias", Alias: alias, SourceRepo: "acme/shared", SourcePath: "templates/build.yml"}}}
	catalog, err := BuildCatalog(root, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := catalog.Lookup("azure-pipelines.yml")
	if !ok || entry.ParseError != nil {
		t.Fatalf("static Azure external template must not be a parser failure: %+v %v", entry, ok)
	}
	joined := evidenceText(entry.Result)
	if !strings.Contains(joined, "azure_template|azure-pipelines.yml|acme/shared:templates/build.yml|resolved_declared|topology:sha256:test") {
		t.Fatalf("Azure topology mapping did not resolve: %s", joined)
	}
}

func TestDeclaredReusableWorkflowInheritsFactsFromScannedEntrypoint(t *testing.T) {
	t.Parallel()

	callerRoot := t.TempDir()
	sourceRoot := t.TempDir()
	alias := "acme/shared/.github/workflows/release.yml@v2"
	writeCatalogFixture(t, callerRoot, ".github/workflows/caller.yml", "name: caller\non: push\njobs:\n  release:\n    uses: "+alias+"\n")
	writeCatalogFixture(t, sourceRoot, ".github/workflows/release.yml", "name: release\non: workflow_call\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: kubectl apply -f deploy/\n")
	topology := &executiontopology.Topology{Version: 1, Digest: "sha256:test", Mappings: []executiontopology.Mapping{{Kind: "workflow_alias", Alias: alias, SourceRepo: "acme/shared", SourcePath: ".github/workflows/release.yml"}}}
	caller, err := BuildCatalog(callerRoot, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	source, err := BuildCatalog(sourceRoot, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/caller", Root: callerRoot, Catalog: caller}, {Repo: "acme/shared", Root: sourceRoot, Catalog: source}})
	entry, ok := resolved[callerRoot].Lookup(".github/workflows/caller.yml")
	if !ok || !containsCatalogValue(entry.Result.Capabilities, "deploy.write") {
		t.Fatalf("mapped reusable workflow must contribute inherited capabilities: %+v", entry)
	}
	if len(entry.Result.ExecutionRelationships) != 1 || entry.Result.ExecutionRelationships[0].ResolutionState != "resolved_declared" {
		t.Fatalf("mapped reusable workflow must remain resolved: %+v", entry.Result.ExecutionRelationships)
	}
}

func TestGitHubReusableWorkflowAndCompositeRelationshipsResolveLocally(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCatalogFixture(t, root, ".github/workflows/caller.yml", `
name: caller
on: push
jobs:
  shared:
    uses: ./.github/workflows/shared.yml
  local:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/release
`)
	writeCatalogFixture(t, root, ".github/workflows/shared.yml", "name: shared\non: workflow_call\njobs: {}\n")
	writeCatalogFixture(t, root, ".github/actions/release/action.yml", "name: release\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: kubectl apply -f deploy/\n")
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatalf("build workflow catalog: %v", err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	entry, ok := resolved[root].Lookup(".github/workflows/caller.yml")
	if !ok || entry.ParseError != nil {
		t.Fatalf("caller parse result: %+v %v", entry, ok)
	}
	joined := evidenceText(entry.Result)
	for _, want := range []string{
		"github_reusable_workflow|.github/workflows/caller.yml|.github/workflows/shared.yml|resolved_local",
		"github_composite_action|.github/workflows/caller.yml|.github/actions/release/action.yml|resolved_local",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing relationship %q in %s", want, joined)
		}
	}
	if len(entry.Result.ExecutionRelationships) != 2 {
		t.Fatalf("expected two typed local relationships, got %+v", entry.Result.ExecutionRelationships)
	}
	if !containsCatalogValue(entry.Result.Capabilities, "deploy.write") {
		t.Fatalf("caller must inherit composite action capabilities, got %+v", entry.Result.Capabilities)
	}
	for _, relationship := range entry.Result.ExecutionRelationships {
		if relationship.RelationshipID == "" || relationship.ResolutionState != "resolved_local" || relationship.Confidence != "high" {
			t.Fatalf("unexpected typed relationship: %+v", relationship)
		}
	}
}

func TestNestedCompositeActionRelationshipsResolveTransitively(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeCatalogFixture(t, root, ".github/workflows/caller.yml", `
name: caller
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/outer
`)
	writeCatalogFixture(t, root, ".github/actions/outer/action.yml", `
name: outer
runs:
  using: composite
  steps:
    - uses: ./.github/actions/publisher
`)
	writeCatalogFixture(t, root, ".github/actions/publisher/action.yml", `
name: publisher
runs:
  using: composite
  steps:
    - shell: bash
      run: npm publish
`)

	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatalf("build workflow catalog: %v", err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	entry, ok := resolved[root].Lookup(".github/workflows/caller.yml")
	if !ok || entry.ParseError != nil {
		t.Fatalf("caller parse result: %+v %v", entry, ok)
	}
	if !containsCatalogValue(entry.Result.Capabilities, "package.write") {
		t.Fatalf("caller must inherit nested composite capabilities, got %+v", entry.Result.Capabilities)
	}
	joined := evidenceText(entry.Result)
	for _, want := range []string{
		"github_composite_action|.github/workflows/caller.yml|.github/actions/outer/action.yml|resolved_local",
		"github_composite_action|.github/actions/outer/action.yml|.github/actions/publisher/action.yml|resolved_local",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing nested relationship %q in %s", want, joined)
		}
	}
}

func TestPlatformLocalIncludesFailClosedWhenMissingOrMalformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entrypoint string
		content    string
		child      string
		childBody  string
		kind       string
	}{
		{name: "gitlab missing", entrypoint: ".gitlab-ci.yml", content: "include:\n  - local: ci/missing.yml\n", kind: "gitlab_include"},
		{name: "gitlab malformed", entrypoint: ".gitlab-ci.yml", content: "include:\n  - local: ci/bad.yml\n", child: "ci/bad.yml", childBody: "jobs: [", kind: "gitlab_include"},
		{name: "azure missing", entrypoint: "azure-pipelines.yml", content: "steps:\n  - template: pipelines/missing.yml\n", kind: "azure_template"},
		{name: "azure malformed", entrypoint: "azure-pipelines.yml", content: "steps:\n  - template: pipelines/bad.yml\n", child: "pipelines/bad.yml", childBody: "steps: [", kind: "azure_template"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeCatalogFixture(t, root, tc.entrypoint, tc.content)
			if tc.child != "" {
				writeCatalogFixture(t, root, tc.child, tc.childBody)
			}
			catalog, err := BuildCatalog(root, detect.Options{})
			if err != nil {
				t.Fatal(err)
			}
			entry, ok := catalog.Lookup(tc.entrypoint)
			if !ok {
				t.Fatalf("missing entrypoint %s", tc.entrypoint)
			}
			if entry.ParseError == nil {
				t.Fatalf("failed include must produce a parse error: %+v", entry)
			}
			relationships := entry.Result.ExecutionRelationships
			if len(relationships) != 1 || relationships[0].Kind != tc.kind || relationships[0].ResolutionState != "unresolved_external" {
				t.Fatalf("failed include must remain unresolved: %+v", relationships)
			}
		})
	}
}

func TestResolverDoesNotDowngradeAdapterResolvedLocalIncludes(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeCatalogFixture(t, root, ".gitlab-ci.yml", "include:\n  - local: ci/release.yml\n")
	writeCatalogFixture(t, root, "ci/release.yml", "release:\n  script: echo release\n")
	writeCatalogFixture(t, root, "azure-pipelines.yml", "steps:\n  - template: pipelines/release.yml\n")
	writeCatalogFixture(t, root, "pipelines/release.yml", "steps:\n  - script: echo release\n")
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	for _, path := range []string{".gitlab-ci.yml", "azure-pipelines.yml"} {
		entry, ok := resolved[root].Lookup(path)
		if !ok {
			t.Fatalf("missing %s", path)
		}
		for _, relationship := range entry.Result.ExecutionRelationships {
			if relationship.ResolutionState == "unresolved_external" {
				t.Fatalf("resolved local relationship was downgraded for %s: %+v", path, relationship)
			}
		}
	}
}

func TestGitLabIncludeFragmentIsSharedSourceWithoutFalseParseError(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeCatalogFixture(t, root, ".gitlab-ci.yml", "include:\n  - local: .gitlab/ci/deploy.yml\n")
	writeCatalogFixture(t, root, ".gitlab/ci/deploy.yml", "deploy:\n  script: kubectl apply -f deploy/\n")
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fragment, ok := catalog.Lookup(".gitlab/ci/deploy.yml")
	if !ok || fragment.SurfaceRole != "shared_source" || fragment.ParseError != nil {
		t.Fatalf("resolved GitLab include must remain a clean shared source: %+v %v", fragment, ok)
	}
	entrypoint, ok := catalog.Lookup(".gitlab-ci.yml")
	if !ok || entrypoint.ParseError != nil || !containsCatalogValue(entrypoint.Result.Capabilities, "deploy.write") {
		t.Fatalf("entrypoint must own parsed include capabilities: %+v %v", entrypoint, ok)
	}
}

func TestResolverMarksMissingJenkinsLoadUnresolved(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeCatalogFixture(t, root, "Jenkinsfile", "load 'vars/missing.groovy'\n")
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	entry, ok := resolved[root].Lookup("Jenkinsfile")
	if !ok {
		t.Fatal("missing Jenkins entrypoint")
	}
	if len(entry.Result.ExecutionRelationships) != 1 || entry.Result.ExecutionRelationships[0].ResolutionState != "unresolved_external" {
		t.Fatalf("missing Jenkins load must fail closed: %+v", entry.Result.ExecutionRelationships)
	}
}

func TestResolverDoesNotDuplicateMalformedReusableWorkflowRelationship(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeCatalogFixture(t, root, ".github/workflows/caller.yml", "name: caller\non: push\njobs:\n  shared:\n    uses: ./.github/workflows/shared.yml\n")
	writeCatalogFixture(t, root, ".github/workflows/shared.yml", "jobs: [")
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	entry, ok := resolved[root].Lookup(".github/workflows/caller.yml")
	if !ok {
		t.Fatal("missing reusable-workflow caller")
	}
	if len(entry.Result.ExecutionRelationships) != 1 || entry.Result.ExecutionRelationships[0].ResolutionState != "unresolved_external" {
		t.Fatalf("malformed reusable workflow must produce one unresolved relationship: %+v", entry.Result.ExecutionRelationships)
	}
}

func TestJenkinsScannerIgnoresCommentsAndMarksDynamicRelationships(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCatalogFixture(t, root, "Jenkinsfile", `
// withCredentials([string(credentialsId: 'COMMENTED_TOKEN', variable: 'TOKEN')])
/* load 'vars/commented.groovy' */
pipeline {
  stages {
    stage('build') {
      steps {
        script { library("${env.LIBRARY_NAME}") }
        echo 'credentialsId: NOT_A_BINDING'
      }
    }
  }
}`)
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := catalog.Lookup("Jenkinsfile")
	if !ok || entry.ParseError != nil {
		t.Fatalf("missing Jenkins result: %+v", entry)
	}
	joined := evidenceText(entry.Result)
	if strings.Contains(joined, "COMMENTED_TOKEN") || strings.Contains(joined, "commented.groovy") || strings.Contains(joined, "NOT_A_BINDING") {
		t.Fatalf("comments or ordinary strings produced Jenkins facts: %s", joined)
	}
	if !strings.Contains(joined, "jenkins_shared_library|Jenkinsfile|${env.LIBRARY_NAME}|unsupported_dynamic") {
		t.Fatalf("dynamic shared library must remain explicitly unresolved: %s", joined)
	}
}

func TestJenkinsApprovalRequiresDSLIdentifierOutsideStringLiteral(t *testing.T) {
	t.Parallel()

	result, parseErr := AnalyzeInRoot("", "Jenkinsfile", []byte(`pipeline {
  stages {
    stage('deploy') {
      steps {
        sh 'claude -p --dangerouslySkipPermissions'
        echo 'input is not configured'
      }
    }
  }
}`))
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if result.HasApprovalGate {
		t.Fatalf("ordinary string literal must not become a Jenkins approval gate: %+v", result)
	}

	approved, parseErr := AnalyzeInRoot("", "Jenkinsfile", []byte("pipeline { stages { stage('deploy') { steps { input message: 'approve' } } } }"))
	if parseErr != nil || !approved.HasApprovalGate {
		t.Fatalf("real Jenkins input step must remain an approval gate: result=%+v err=%+v", approved, parseErr)
	}
}

func TestRelationshipResolverBlocksCyclesAndDepth(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCatalogFixture(t, root, "Jenkinsfile", "load 'vars/step-01.groovy'\n")
	for index := 1; index <= maxRelationshipDepth+2; index++ {
		next := index + 1
		if index == maxRelationshipDepth+2 {
			next = 1
		}
		writeCatalogFixture(t, root, fmt.Sprintf("vars/step-%02d.groovy", index), fmt.Sprintf("load 'vars/step-%02d.groovy'\n", next))
	}
	catalog, err := BuildCatalog(root, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	resolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/service", Root: root, Catalog: catalog}})
	entry, _ := resolved[root].Lookup("Jenkinsfile")
	joined := evidenceText(entry.Result)
	if !strings.Contains(joined, "depth_limited") {
		t.Fatalf("expected bounded relationship depth receipt, got %s", joined)
	}
	foundDepthLimit := false
	for _, relationship := range entry.Result.ExecutionRelationships {
		if relationship.ResolutionState == "depth_limited" || containsCatalogValue(relationship.TruncationReasons, "depth_limited") {
			foundDepthLimit = true
		}
	}
	if !foundDepthLimit {
		t.Fatalf("expected typed depth-limit relationship, got %+v", entry.Result.ExecutionRelationships)
	}

	cycleRoot := t.TempDir()
	writeCatalogFixture(t, cycleRoot, "Jenkinsfile", "load 'vars/a.groovy'\n")
	writeCatalogFixture(t, cycleRoot, "vars/a.groovy", "load 'vars/b.groovy'\n")
	writeCatalogFixture(t, cycleRoot, "vars/b.groovy", "load 'vars/a.groovy'\n")
	cycleCatalog, err := BuildCatalog(cycleRoot, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cycleResolved := ResolveCatalogs([]CatalogScope{{Repo: "acme/cycle", Root: cycleRoot, Catalog: cycleCatalog}})
	cycleEntry, _ := cycleResolved[cycleRoot].Lookup("Jenkinsfile")
	if joined := evidenceText(cycleEntry.Result); !strings.Contains(joined, "cycle_blocked") {
		t.Fatalf("expected cycle receipt, got %s", joined)
	}
}

func writeCatalogFixture(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func evidenceText(result Result) string {
	values := []string{}
	for _, evidence := range result.Evidence {
		values = append(values, evidence.Key+"="+evidence.Value)
	}
	return strings.Join(values, "\n")
}

func containsCatalogValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
