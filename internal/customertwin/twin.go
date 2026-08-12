package customertwin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	CustomerRepoCount        = 96
	CustomerJenkinsCallers   = 64
	CustomerCredentialRefs   = 66
	CustomerSharedCallers    = 32
	CustomerAPISpecs         = 38
	OperationsPerSpec        = 10
	CustomerAPIOperations    = CustomerAPISpecs * OperationsPerSpec
	CustomerRuntimeConsumers = 1
)

// Oracle is declarative customer-shape truth. It intentionally contains no
// detector, classifier, resolver, or report implementation logic.
type Oracle struct {
	Version                 int           `json:"version"`
	Organizations           int           `json:"organizations"`
	Repositories            int           `json:"repositories"`
	JenkinsCallers          int           `json:"jenkins_callers"`
	DirectCredentialRefs    int           `json:"direct_credential_refs"`
	InheritedCredentialRefs int           `json:"inherited_credential_refs"`
	ExplicitAuthorities     int           `json:"explicit_authorities"`
	OIDCReferences          int           `json:"oidc_references"`
	DuplicatePathRefs       int           `json:"duplicate_path_refs"`
	SharedLibraryCallers    int           `json:"shared_library_callers"`
	UnmappedLibraryCallers  int           `json:"unmapped_library_callers"`
	APISpecFiles            int           `json:"api_spec_files"`
	APIOperations           int           `json:"api_operations"`
	RuntimeConsumers        int           `json:"runtime_consumers"`
	SchemaIdentityClaims    int           `json:"schema_identity_claims"`
	DynamicRelationships    int           `json:"dynamic_relationships"`
	ParserFailures          int           `json:"parser_failures"`
	GitHubReusableCallers   int           `json:"github_reusable_callers"`
	GitHubCompositeCalls    int           `json:"github_composite_calls"`
	GitLabIncludeCallers    int           `json:"gitlab_include_callers"`
	AzureTemplateCallers    int           `json:"azure_template_callers"`
	GeneratedSpecs          int           `json:"generated_specs"`
	APIGenerators           int           `json:"api_generators"`
	ExpectedStages          []OracleStage `json:"expected_stages"`
}

type OracleStage struct {
	StageID string `json:"stage_id"`
	Unit    string `json:"unit"`
	Count   int    `json:"count"`
}

func CustomerOracle() Oracle {
	return Oracle{
		Version: 1, Organizations: 4, Repositories: CustomerRepoCount,
		JenkinsCallers: CustomerJenkinsCallers, DirectCredentialRefs: CustomerCredentialRefs, InheritedCredentialRefs: CustomerSharedCallers / 2,
		ExplicitAuthorities: 1, OIDCReferences: 1, DuplicatePathRefs: 2,
		SharedLibraryCallers: CustomerSharedCallers, UnmappedLibraryCallers: CustomerSharedCallers / 2,
		APISpecFiles: CustomerAPISpecs, APIOperations: CustomerAPIOperations,
		RuntimeConsumers: CustomerRuntimeConsumers, SchemaIdentityClaims: 0,
		DynamicRelationships: 4, ParserFailures: 1,
		GitHubReusableCallers: 1, GitHubCompositeCalls: 1, GitLabIncludeCallers: 1, AzureTemplateCallers: 1,
		GeneratedSpecs: 1, APIGenerators: 1,
		ExpectedStages: []OracleStage{
			{StageID: "jenkins_sources", Unit: "files", Count: CustomerJenkinsCallers},
			{StageID: "direct_credential_refs", Unit: "references", Count: CustomerCredentialRefs},
			{StageID: "inherited_credential_refs", Unit: "caller_occurrences", Count: CustomerSharedCallers / 2},
			{StageID: "resolved_shared_callers", Unit: "relationships", Count: CustomerSharedCallers / 2},
			{StageID: "unmapped_shared_callers", Unit: "relationships", Count: CustomerSharedCallers / 2},
			{StageID: "api_specifications", Unit: "files", Count: CustomerAPISpecs},
			{StageID: "api_operations", Unit: "operations", Count: CustomerAPIOperations},
			{StageID: "schema_identity_claims", Unit: "identities", Count: 0},
		},
	}
}

func MaterializeCustomerShape(root string) (Oracle, error) {
	return Materialize(root, CustomerRepoCount)
}

func Materialize(root string, repoCount int) (Oracle, error) {
	if strings.TrimSpace(root) == "" || repoCount < 1 {
		return Oracle{}, fmt.Errorf("root and positive repository count are required")
	}
	oracle := CustomerOracle()
	oracle.Repositories = repoCount
	oracle.JenkinsCallers = min(repoCount, CustomerJenkinsCallers)
	oracle.DuplicatePathRefs = boolCount(repoCount >= 71) + boolCount(repoCount >= 72)
	oracle.DirectCredentialRefs = oracle.JenkinsCallers + oracle.DuplicatePathRefs
	oracle.ExplicitAuthorities = boolCount(repoCount >= 69)
	oracle.OIDCReferences = boolCount(repoCount >= 70)
	oracle.SharedLibraryCallers = min(oracle.JenkinsCallers/2, CustomerSharedCallers)
	oracle.UnmappedLibraryCallers = oracle.SharedLibraryCallers / 2
	oracle.InheritedCredentialRefs = oracle.SharedLibraryCallers - oracle.UnmappedLibraryCallers
	oracle.APISpecFiles = min(repoCount, CustomerAPISpecs)
	oracle.APIOperations = oracle.APISpecFiles * OperationsPerSpec
	if oracle.APISpecFiles == 0 {
		oracle.RuntimeConsumers = 0
		oracle.APIGenerators = 0
	}
	if repoCount < CustomerRepoCount {
		oracle.DynamicRelationships = min(repoCount, 4)
		oracle.ParserFailures = boolCount(repoCount >= 68)
		oracle.GitHubReusableCallers = boolCount(repoCount >= 65)
		oracle.GitHubCompositeCalls = boolCount(repoCount >= 65)
		oracle.GitLabIncludeCallers = boolCount(repoCount >= 66)
		oracle.AzureTemplateCallers = boolCount(repoCount >= 67)
	}
	oracle.ExpectedStages = expectedStages(oracle)

	for index := 1; index <= repoCount; index++ {
		repo := RepoName(index)
		repoRoot := filepath.Join(root, repo)
		if err := writeFile(repoRoot, "README.md", "# Synthetic customer-shaped repository\n"); err != nil {
			return Oracle{}, err
		}
		if index <= oracle.JenkinsCallers {
			libraryAlias := ""
			if index <= oracle.SharedLibraryCallers-oracle.UnmappedLibraryCallers {
				libraryAlias = "delivery-lib"
			} else if index <= oracle.SharedLibraryCallers {
				libraryAlias = "legacy-unmapped-lib"
			}
			if err := writeFile(repoRoot, nestedJenkinsPath(index), jenkinsfile(index, libraryAlias)); err != nil {
				return Oracle{}, err
			}
		}
		if index <= oracle.APISpecFiles {
			specPath := fmt.Sprintf("proto-spec/service-%02d.json", index)
			if index == oracle.APISpecFiles {
				specPath = fmt.Sprintf("build/api/service-%02d.json", index)
			}
			if err := writeFile(repoRoot, specPath, openAPISpec(index)); err != nil {
				return Oracle{}, err
			}
			if index == CustomerAPISpecs {
				if err := writeFile(repoRoot, "tools/openapi-generator-config.json", `{"generatorName":"typescript-fetch","outputSpec":"../build/api/service-38.json"}`+"\n"); err != nil {
					return Oracle{}, err
				}
			}
		}
		if index == 1 {
			if err := writeFile(repoRoot, "ui/swagger-config.js", `window.ui = SwaggerUIBundle({url: "/proto-spec/service-01.json"});`+"\n"); err != nil {
				return Oracle{}, err
			}
		}
		if index == 2 {
			if err := writeFile(repoRoot, "schemas/credential-example.json", `{"$schema":"https://json-schema.org/draft/2020-12/schema","properties":{"app_id":{"type":"string"},"private_key":{"type":"string"},"token":{"type":"string"}}}`+"\n"); err != nil {
				return Oracle{}, err
			}
		}
		if index == 65 {
			if err := writeGitHubReuseFixture(repoRoot); err != nil {
				return Oracle{}, err
			}
		}
		if index == 66 {
			if err := writeGitLabIncludeFixture(repoRoot); err != nil {
				return Oracle{}, err
			}
		}
		if index == 67 {
			if err := writeAzureTemplateFixture(repoRoot); err != nil {
				return Oracle{}, err
			}
		}
		if index == 68 {
			if err := writeFile(repoRoot, ".github/workflows/broken.yml", "name: broken\njobs: [\n"); err != nil {
				return Oracle{}, err
			}
		}
		if index == 69 {
			if err := writeFile(repoRoot, ".wrkr-twin/standing-authority.json", `{"credential_reference":"EXPLICIT_RELEASE_REF","existence_evidence_state":"verified","binding_evidence_state":"verified","lifetime_evidence_state":"verified","lifetime_kind":"standing","value_redacted":true}`+"\n"); err != nil {
				return Oracle{}, err
			}
		}
		if index == 70 {
			if err := writeFile(repoRoot, ".github/workflows/oidc-release.yml", "name: oidc release\non: workflow_dispatch\npermissions:\n  id-token: write\n  contents: read\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo workload identity\n"); err != nil {
				return Oracle{}, err
			}
		}
		if index == 71 || index == 72 {
			ref := fmt.Sprintf("REPO_%03d_RELEASE_REF", index)
			if err := writeFile(repoRoot, ".github/workflows/release.yml", fmt.Sprintf("name: release\non: workflow_dispatch\njobs:\n  release:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          RELEASE_REF: ${{ secrets.%s }}\n        run: echo release\n", ref)); err != nil {
				return Oracle{}, err
			}
		}
		if index == 73 {
			if err := writeFile(repoRoot, "vars/cycle-a.groovy", "load 'vars/cycle-b.groovy'\n"); err != nil {
				return Oracle{}, err
			}
			if err := writeFile(repoRoot, "vars/cycle-b.groovy", "load 'vars/cycle-a.groovy'\n"); err != nil {
				return Oracle{}, err
			}
		}
		if index == 74 {
			for depth := 1; depth <= 11; depth++ {
				next := depth + 1
				if next > 11 {
					next = 11
				}
				if err := writeFile(repoRoot, fmt.Sprintf("vars/depth-%02d.groovy", depth), fmt.Sprintf("load 'vars/depth-%02d.groovy'\n", next)); err != nil {
					return Oracle{}, err
				}
			}
		}
	}

	libRepo := filepath.Join(root, RepoName(repoCount))
	if err := writeFile(libRepo, "vars/deliveryLib.groovy", `def call() { withCredentials([string(credentialsId: 'SHARED_RELEASE_TOKEN', variable: 'TOKEN')]) { sh 'helm upgrade --install service chart/' } }`+"\n"); err != nil {
		return Oracle{}, err
	}
	if err := writeTopology(root, repoCount, oracle.SharedLibraryCallers-oracle.UnmappedLibraryCallers); err != nil {
		return Oracle{}, err
	}
	if err := writeManifest(root, repoCount); err != nil {
		return Oracle{}, err
	}
	return oracle, nil
}

func RepoName(index int) string {
	return fmt.Sprintf("org-%d-service-%03d", ((index-1)%4)+1, index)
}

func nestedJenkinsPath(index int) string {
	if index%2 == 0 {
		return fmt.Sprintf("services/component-%03d/JENKINSFILE", index)
	}
	return fmt.Sprintf("delivery/component-%03d/Jenkinsfile", index)
}

func jenkinsfile(index int, libraryAlias string) string {
	library := ""
	if strings.TrimSpace(libraryAlias) != "" {
		library = "@Library('" + strings.TrimSpace(libraryAlias) + "@v2') _\n"
	}
	dynamicLoad := ""
	if index > CustomerJenkinsCallers-4 {
		dynamicLoad = "        load \"scripts/${env.DEPLOY_SCRIPT}.groovy\"\n"
	}
	credential := fmt.Sprintf("SERVICE_%03d_DEPLOY_TOKEN", index)
	return fmt.Sprintf(`%spipeline {
  agent any
  stages {
    stage('release') {
      steps {
        input message: 'approve release'
%s        withCredentials([string(credentialsId: '%s', variable: 'TOKEN')]) {
          sh 'kubectl apply -f deploy/'
        }
      }
    }
  }
}
`, library, dynamicLoad, credential)
}

func writeGitHubReuseFixture(root string) error {
	files := map[string]string{
		".github/workflows/caller.yml":       "name: caller\non: push\njobs:\n  shared:\n    uses: ./.github/workflows/shared.yml\n  local:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/release\n",
		".github/workflows/shared.yml":       "name: shared\non: workflow_call\njobs: {}\n",
		".github/actions/release/action.yml": "name: release\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: npm publish\n",
	}
	for rel, content := range files {
		if err := writeFile(root, rel, content); err != nil {
			return err
		}
	}
	return nil
}

func writeGitLabIncludeFixture(root string) error {
	if err := writeFile(root, ".gitlab-ci.yml", "include:\n  - local: ci/release.yml\n"); err != nil {
		return err
	}
	return writeFile(root, "ci/release.yml", "release:\n  script:\n    - twine upload dist/*\n")
}

func writeAzureTemplateFixture(root string) error {
	if err := writeFile(root, "azure-pipelines.yml", "steps:\n  - template: pipelines/release.yml\n"); err != nil {
		return err
	}
	return writeFile(root, "pipelines/release.yml", "steps:\n  - script: docker push example/service\n")
}

func expectedStages(oracle Oracle) []OracleStage {
	return []OracleStage{
		{StageID: "jenkins_sources", Unit: "files", Count: oracle.JenkinsCallers},
		{StageID: "direct_credential_refs", Unit: "references", Count: oracle.DirectCredentialRefs},
		{StageID: "inherited_credential_refs", Unit: "caller_occurrences", Count: oracle.InheritedCredentialRefs},
		{StageID: "resolved_shared_callers", Unit: "relationships", Count: oracle.SharedLibraryCallers - oracle.UnmappedLibraryCallers},
		{StageID: "unmapped_shared_callers", Unit: "relationships", Count: oracle.UnmappedLibraryCallers},
		{StageID: "api_specifications", Unit: "files", Count: oracle.APISpecFiles},
		{StageID: "api_operations", Unit: "operations", Count: oracle.APIOperations},
		{StageID: "schema_identity_claims", Unit: "identities", Count: oracle.SchemaIdentityClaims},
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func openAPISpec(index int) string {
	paths := map[string]map[string]map[string]string{}
	for operation := 1; operation <= OperationsPerSpec; operation++ {
		route := fmt.Sprintf("/v1/service-%02d/resources/%03d", index, operation)
		paths[route] = map[string]map[string]string{"post": {"operationId": fmt.Sprintf("createService%02dResource%03d", index, operation), "summary": "Create resource"}}
	}
	doc := map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "Synthetic API", "version": "1.0.0"}, "paths": paths}
	payload, _ := json.MarshalIndent(doc, "", "  ")
	return string(payload) + "\n"
}

func writeTopology(root string, repoCount, mappedCallers int) error {
	var builder strings.Builder
	builder.WriteString("version: 1\nmappings:\n")
	if mappedCallers > 0 {
		builder.WriteString("  - kind: jenkins_shared_library\n")
		builder.WriteString("    alias: delivery-lib\n")
		builder.WriteString("    source_repo: " + RepoName(repoCount) + "\n")
		builder.WriteString("    source_path: vars/deliveryLib.groovy\n")
		builder.WriteString("    version: v2\n")
	}
	if repoCount >= 1 {
		builder.WriteString("  - kind: api_runtime\n")
		builder.WriteString("    alias: proto-spec/service-01.json\n")
		builder.WriteString("    source_repo: " + RepoName(1) + "\n")
		builder.WriteString("    source_path: ui/swagger-config.js\n")
	}
	return os.WriteFile(filepath.Join(root, "execution-topology.yaml"), []byte(builder.String()), 0o600)
}

func writeFile(root, rel, content string) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", rel, err)
	}
	return nil
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
