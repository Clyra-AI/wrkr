package customertwin

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const ManifestVersion = 1

type Manifest struct {
	Version        int                     `json:"version"`
	Repositories   []ManifestRepository    `json:"repositories"`
	Artifacts      []ManifestArtifact      `json:"artifacts"`
	Facts          []ManifestFact          `json:"facts"`
	Relationships  []ManifestRelationship  `json:"relationships"`
	Bindings       []ManifestBinding       `json:"bindings"`
	Authorities    []ManifestAuthority     `json:"authorities"`
	NegativeClaims []ManifestNegativeClaim `json:"negative_claims"`
}

type ManifestRepository struct {
	ID           string `json:"id"`
	Organization string `json:"organization"`
	Inert        bool   `json:"inert,omitempty"`
}

type ManifestArtifact struct {
	ID   string `json:"id"`
	Repo string `json:"repo"`
	Path string `json:"path"`
	Role string `json:"role"`
}

type ManifestFact struct {
	ID          string   `json:"id"`
	Stage       string   `json:"stage"`
	Unit        string   `json:"unit"`
	ArtifactIDs []string `json:"artifact_ids"`
}

type ManifestRelationship struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	CallerArtifactID string   `json:"caller_artifact_id"`
	SourceArtifactID string   `json:"source_artifact_id,omitempty"`
	State            string   `json:"state"`
	FactIDs          []string `json:"fact_ids,omitempty"`
}

type ManifestBinding struct {
	ID              string   `json:"id"`
	ReferenceFactID string   `json:"reference_fact_id"`
	RelationshipID  string   `json:"relationship_id,omitempty"`
	EvidenceFactIDs []string `json:"evidence_fact_ids"`
	State           string   `json:"state"`
}

type ManifestAuthority struct {
	ID                      string `json:"id"`
	BindingID               string `json:"binding_id"`
	ExistenceEvidenceFactID string `json:"existence_evidence_fact_id"`
	LifetimeEvidenceFactID  string `json:"lifetime_evidence_fact_id"`
	LifetimeKind            string `json:"lifetime_kind"`
	Effective               bool   `json:"effective"`
}

type ManifestNegativeClaim struct {
	ID         string `json:"id"`
	ArtifactID string `json:"artifact_id"`
	Claim      string `json:"claim"`
	Count      int    `json:"count"`
}

func CustomerManifest(repoCount int) Manifest {
	manifest := Manifest{Version: ManifestVersion}
	for index := 1; index <= repoCount; index++ {
		manifest.Repositories = append(manifest.Repositories, ManifestRepository{ID: RepoName(index), Organization: fmt.Sprintf("synthetic-org-%d", ((index-1)%4)+1), Inert: index > CustomerRepoCount})
	}
	semanticRepos := min(repoCount, CustomerRepoCount)
	for index := 1; index <= min(semanticRepos, CustomerJenkinsCallers); index++ {
		artifactID := fmt.Sprintf("artifact-jenkins-%03d", index)
		factID := fmt.Sprintf("fact-credential-reference-%03d", index)
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: artifactID, Repo: RepoName(index), Path: nestedJenkinsPath(index), Role: "workflow_entrypoint"})
		manifest.Facts = append(manifest.Facts, ManifestFact{ID: factID, Stage: "reference", Unit: "credential_reference", ArtifactIDs: []string{artifactID}})
		if index <= CustomerSharedCallers {
			state := "unresolved_external"
			sourceArtifactID := ""
			if index <= CustomerSharedCallers/2 {
				state = "resolved_declared"
				sourceArtifactID = "artifact-shared-library"
			}
			manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: fmt.Sprintf("relationship-jenkins-%03d", index), Kind: "jenkins_shared_library", CallerArtifactID: artifactID, SourceArtifactID: sourceArtifactID, State: state, FactIDs: []string{factID}})
		}
	}
	if repoCount > 0 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-shared-library", Repo: RepoName(repoCount), Path: "vars/deliveryLib.groovy", Role: "shared_workflow_source"})
		manifest.Facts = append(manifest.Facts, ManifestFact{ID: "fact-shared-library-reference", Stage: "reference", Unit: "inherited_credential_reference", ArtifactIDs: []string{"artifact-shared-library"}})
	}
	for index := 1; index <= min(semanticRepos, CustomerAPISpecs); index++ {
		path := fmt.Sprintf("proto-spec/service-%02d.json", index)
		if index == min(semanticRepos, CustomerAPISpecs) && semanticRepos >= CustomerAPISpecs {
			path = fmt.Sprintf("build/api/service-%02d.json", index)
		}
		artifactID := fmt.Sprintf("artifact-api-spec-%02d", index)
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: artifactID, Repo: RepoName(index), Path: path, Role: "api_specification"})
		manifest.Facts = append(manifest.Facts, ManifestFact{ID: fmt.Sprintf("fact-api-operations-%02d", index), Stage: "observation", Unit: "api_operation", ArtifactIDs: []string{artifactID}})
	}
	if semanticRepos >= 2 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-schema-negative", Repo: RepoName(2), Path: "schemas/credential-example.json", Role: "schema_declaration"})
		manifest.NegativeClaims = append(manifest.NegativeClaims, ManifestNegativeClaim{ID: "negative-schema-identity", ArtifactID: "artifact-schema-negative", Claim: "effective_identity", Count: 0})
	}
	if semanticRepos >= 69 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-explicit-authority", Repo: RepoName(69), Path: ".wrkr-twin/standing-authority.json", Role: "importable_authority_evidence"})
		manifest.Facts = append(manifest.Facts,
			ManifestFact{ID: "fact-explicit-reference", Stage: "reference", Unit: "imported_credential_reference", ArtifactIDs: []string{"artifact-explicit-authority"}},
			ManifestFact{ID: "fact-explicit-existence", Stage: "binding", Unit: "credential_existence", ArtifactIDs: []string{"artifact-explicit-authority"}},
			ManifestFact{ID: "fact-explicit-lifetime", Stage: "binding", Unit: "credential_lifetime", ArtifactIDs: []string{"artifact-explicit-authority"}},
		)
		manifest.Bindings = append(manifest.Bindings, ManifestBinding{ID: "binding-explicit-standing", ReferenceFactID: "fact-explicit-reference", EvidenceFactIDs: []string{"fact-explicit-existence"}, State: "verified"})
		manifest.Authorities = append(manifest.Authorities, ManifestAuthority{ID: "authority-explicit-standing", BindingID: "binding-explicit-standing", ExistenceEvidenceFactID: "fact-explicit-existence", LifetimeEvidenceFactID: "fact-explicit-lifetime", LifetimeKind: "standing", Effective: true})
	}
	if semanticRepos >= 1 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-api-consumer", Repo: RepoName(1), Path: "ui/swagger-config.js", Role: "static_api_consumer"})
		manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: "relationship-api-consumer", Kind: "api_spec_consumer", CallerArtifactID: "artifact-api-spec-01", SourceArtifactID: "artifact-api-consumer", State: "resolved_local", FactIDs: []string{"fact-api-operations-01"}})
	}
	if semanticRepos >= CustomerAPISpecs {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-api-generator", Repo: RepoName(CustomerAPISpecs), Path: "tools/openapi-generator-config.json", Role: "static_api_generator"})
		manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: "relationship-api-generator", Kind: "api_spec_generator", CallerArtifactID: "artifact-api-generator", SourceArtifactID: fmt.Sprintf("artifact-api-spec-%02d", CustomerAPISpecs), State: "resolved_local", FactIDs: []string{fmt.Sprintf("fact-api-operations-%02d", CustomerAPISpecs)}})
	}
	if semanticRepos >= 65 {
		manifest.Artifacts = append(manifest.Artifacts,
			ManifestArtifact{ID: "artifact-github-caller", Repo: RepoName(65), Path: ".github/workflows/caller.yml", Role: "workflow_entrypoint"},
			ManifestArtifact{ID: "artifact-github-reusable", Repo: RepoName(65), Path: ".github/workflows/shared.yml", Role: "reusable_workflow"},
			ManifestArtifact{ID: "artifact-github-composite", Repo: RepoName(65), Path: ".github/actions/release/action.yml", Role: "composite_action"},
		)
		manifest.Relationships = append(manifest.Relationships,
			ManifestRelationship{ID: "relationship-github-reusable", Kind: "github_reusable_workflow", CallerArtifactID: "artifact-github-caller", SourceArtifactID: "artifact-github-reusable", State: "resolved_local"},
			ManifestRelationship{ID: "relationship-github-composite", Kind: "github_composite_action", CallerArtifactID: "artifact-github-caller", SourceArtifactID: "artifact-github-composite", State: "resolved_local"},
		)
	}
	if semanticRepos >= 66 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-gitlab-caller", Repo: RepoName(66), Path: ".gitlab-ci.yml", Role: "workflow_entrypoint"}, ManifestArtifact{ID: "artifact-gitlab-template", Repo: RepoName(66), Path: "ci/release.yml", Role: "reusable_workflow"})
		manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: "relationship-gitlab-include", Kind: "gitlab_include", CallerArtifactID: "artifact-gitlab-caller", SourceArtifactID: "artifact-gitlab-template", State: "resolved_local"})
	}
	if semanticRepos >= 67 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-azure-caller", Repo: RepoName(67), Path: "azure-pipelines.yml", Role: "workflow_entrypoint"}, ManifestArtifact{ID: "artifact-azure-template", Repo: RepoName(67), Path: "pipelines/release.yml", Role: "reusable_workflow"})
		manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: "relationship-azure-template", Kind: "azure_template", CallerArtifactID: "artifact-azure-caller", SourceArtifactID: "artifact-azure-template", State: "resolved_local"})
	}
	if semanticRepos >= 70 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-oidc-workflow", Repo: RepoName(70), Path: ".github/workflows/oidc-release.yml", Role: "workflow_entrypoint"})
		manifest.Facts = append(manifest.Facts, ManifestFact{ID: "fact-oidc-reference", Stage: "reference", Unit: "workload_identity_reference", ArtifactIDs: []string{"artifact-oidc-workflow"}})
	}
	for _, index := range []int{71, 72} {
		if semanticRepos < index {
			continue
		}
		artifactID := fmt.Sprintf("artifact-duplicate-workflow-%03d", index)
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: artifactID, Repo: RepoName(index), Path: ".github/workflows/release.yml", Role: "workflow_entrypoint"})
		manifest.Facts = append(manifest.Facts, ManifestFact{ID: fmt.Sprintf("fact-duplicate-reference-%03d", index), Stage: "reference", Unit: "credential_reference", ArtifactIDs: []string{artifactID}})
	}
	if semanticRepos >= 73 {
		manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: "artifact-cycle-a", Repo: RepoName(73), Path: "vars/cycle-a.groovy", Role: "shared_workflow_source"}, ManifestArtifact{ID: "artifact-cycle-b", Repo: RepoName(73), Path: "vars/cycle-b.groovy", Role: "shared_workflow_source"})
		manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: "relationship-cycle-a", Kind: "local_script", CallerArtifactID: "artifact-cycle-a", SourceArtifactID: "artifact-cycle-b", State: "cycle_blocked"}, ManifestRelationship{ID: "relationship-cycle-b", Kind: "local_script", CallerArtifactID: "artifact-cycle-b", SourceArtifactID: "artifact-cycle-a", State: "cycle_blocked"})
	}
	if semanticRepos >= 74 {
		for depth := 1; depth <= 11; depth++ {
			artifactID := fmt.Sprintf("artifact-depth-%02d", depth)
			manifest.Artifacts = append(manifest.Artifacts, ManifestArtifact{ID: artifactID, Repo: RepoName(74), Path: fmt.Sprintf("vars/depth-%02d.groovy", depth), Role: "shared_workflow_source"})
			if depth > 1 {
				manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: fmt.Sprintf("relationship-depth-%02d", depth-1), Kind: "local_script", CallerArtifactID: fmt.Sprintf("artifact-depth-%02d", depth-1), SourceArtifactID: artifactID, State: "resolved_local"})
			}
		}
		manifest.Relationships = append(manifest.Relationships, ManifestRelationship{ID: "relationship-depth-limit", Kind: "local_script", CallerArtifactID: "artifact-depth-01", SourceArtifactID: "artifact-depth-10", State: "depth_limited"})
	}
	sortManifest(&manifest)
	return manifest
}

func ValidateManifest(manifest Manifest) error {
	if manifest.Version != ManifestVersion {
		return fmt.Errorf("manifest version %d is unsupported", manifest.Version)
	}
	artifacts := map[string]ManifestArtifact{}
	for _, artifact := range manifest.Artifacts {
		if artifact.ID == "" || artifact.Repo == "" || artifact.Path == "" {
			return fmt.Errorf("manifest artifact is incomplete")
		}
		if _, exists := artifacts[artifact.ID]; exists {
			return fmt.Errorf("duplicate artifact %s", artifact.ID)
		}
		artifacts[artifact.ID] = artifact
	}
	facts := map[string]ManifestFact{}
	for _, fact := range manifest.Facts {
		if fact.ID == "" || fact.Stage == "" || fact.Unit == "" || len(fact.ArtifactIDs) == 0 {
			return fmt.Errorf("manifest fact is incomplete")
		}
		for _, artifactID := range fact.ArtifactIDs {
			if _, exists := artifacts[artifactID]; !exists {
				return fmt.Errorf("fact %s references missing artifact %s", fact.ID, artifactID)
			}
		}
		facts[fact.ID] = fact
	}
	relationships := map[string]ManifestRelationship{}
	for _, relationship := range manifest.Relationships {
		if _, exists := artifacts[relationship.CallerArtifactID]; !exists {
			return fmt.Errorf("relationship %s has missing caller", relationship.ID)
		}
		if relationship.SourceArtifactID != "" {
			if _, exists := artifacts[relationship.SourceArtifactID]; !exists {
				return fmt.Errorf("relationship %s has missing source", relationship.ID)
			}
		}
		for _, factID := range relationship.FactIDs {
			if _, exists := facts[factID]; !exists {
				return fmt.Errorf("relationship %s has missing fact %s", relationship.ID, factID)
			}
		}
		relationships[relationship.ID] = relationship
	}
	bindings := map[string]ManifestBinding{}
	for _, binding := range manifest.Bindings {
		if _, exists := facts[binding.ReferenceFactID]; !exists {
			return fmt.Errorf("binding %s has missing reference fact", binding.ID)
		}
		if binding.RelationshipID != "" {
			if _, exists := relationships[binding.RelationshipID]; !exists {
				return fmt.Errorf("binding %s has missing relationship", binding.ID)
			}
		}
		for _, factID := range binding.EvidenceFactIDs {
			if _, exists := facts[factID]; !exists {
				return fmt.Errorf("binding %s has missing evidence fact %s", binding.ID, factID)
			}
		}
		bindings[binding.ID] = binding
	}
	for _, authority := range manifest.Authorities {
		if _, exists := bindings[authority.BindingID]; !exists {
			return fmt.Errorf("authority %s has missing binding", authority.ID)
		}
		if _, exists := facts[authority.ExistenceEvidenceFactID]; !exists {
			return fmt.Errorf("authority %s has missing existence evidence", authority.ID)
		}
		if _, exists := facts[authority.LifetimeEvidenceFactID]; !exists {
			return fmt.Errorf("authority %s has missing lifetime evidence", authority.ID)
		}
	}
	for _, claim := range manifest.NegativeClaims {
		if _, exists := artifacts[claim.ArtifactID]; !exists {
			return fmt.Errorf("negative claim %s has missing artifact", claim.ID)
		}
	}
	return nil
}

func writeManifest(root string, repoCount int) error {
	manifest := CustomerManifest(repoCount)
	if err := ValidateManifest(manifest); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	return os.WriteFile(root+string(os.PathSeparator)+"twin-manifest.json", payload, 0o600)
}

func sortManifest(manifest *Manifest) {
	if manifest == nil {
		return
	}
	sort.Slice(manifest.Repositories, func(i, j int) bool { return manifest.Repositories[i].ID < manifest.Repositories[j].ID })
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].ID < manifest.Artifacts[j].ID })
	sort.Slice(manifest.Facts, func(i, j int) bool { return manifest.Facts[i].ID < manifest.Facts[j].ID })
	sort.Slice(manifest.Relationships, func(i, j int) bool { return manifest.Relationships[i].ID < manifest.Relationships[j].ID })
	sort.Slice(manifest.Bindings, func(i, j int) bool { return manifest.Bindings[i].ID < manifest.Bindings[j].ID })
	sort.Slice(manifest.Authorities, func(i, j int) bool { return manifest.Authorities[i].ID < manifest.Authorities[j].ID })
	sort.Slice(manifest.NegativeClaims, func(i, j int) bool { return manifest.NegativeClaims[i].ID < manifest.NegativeClaims[j].ID })
	for index := range manifest.Facts {
		sort.Strings(manifest.Facts[index].ArtifactIDs)
	}
	for index := range manifest.Relationships {
		sort.Strings(manifest.Relationships[index].FactIDs)
	}
	for index := range manifest.Bindings {
		sort.Strings(manifest.Bindings[index].EvidenceFactIDs)
	}
}

func manifestContainsCustomerMaterial(payload []byte) bool {
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"activity", "guardium", "agentic", "service mesh", "/users/", "private_key_value"} {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	return false
}
