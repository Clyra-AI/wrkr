package customertwin

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestMaterializeCustomerShapeMatchesIndependentOracle(t *testing.T) {
	root := t.TempDir()
	oracle, err := MaterializeCustomerShape(root)
	if err != nil {
		t.Fatalf("materialize customer twin: %v", err)
	}
	if oracle.Repositories != 96 || oracle.JenkinsCallers != 64 || oracle.APISpecFiles != 38 || oracle.APIOperations != 380 {
		t.Fatalf("unexpected declarative oracle: %+v", oracle)
	}
	if _, err := os.Stat(filepath.Join(root, RepoName(2), "services", "component-002", "JENKINSFILE")); err != nil {
		t.Fatalf("expected nested case-varied Jenkinsfile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "execution-topology.yaml")); err != nil {
		t.Fatalf("expected topology declaration: %v", err)
	}
	manifestPayload, err := os.ReadFile(filepath.Join(root, "twin-manifest.json"))
	if err != nil {
		t.Fatalf("expected materialized independent manifest: %v", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifest(manifest); err != nil {
		t.Fatalf("manifest invariants: %v", err)
	}
	if len(manifest.Authorities) != 1 || !manifest.Authorities[0].Effective {
		t.Fatalf("expected one predecessor-backed effective authority, got %+v", manifest.Authorities)
	}
}

func TestManifestOrderingIsIndependentAndCanonical(t *testing.T) {
	manifest := CustomerManifest(CustomerRepoCount)
	want, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool { return manifest.Artifacts[i].ID > manifest.Artifacts[j].ID })
	sort.Slice(manifest.Facts, func(i, j int) bool { return manifest.Facts[i].ID > manifest.Facts[j].ID })
	sort.Slice(manifest.Relationships, func(i, j int) bool { return manifest.Relationships[i].ID > manifest.Relationships[j].ID })
	sortManifest(&manifest)
	got, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("manifest output changed after input ordering shuffle")
	}
}

func TestManifestRejectsAuthorityWithoutPredecessorEvidence(t *testing.T) {
	manifest := CustomerManifest(CustomerRepoCount)
	manifest.Authorities[0].LifetimeEvidenceFactID = "missing"
	if err := ValidateManifest(manifest); err == nil {
		t.Fatal("expected missing lifetime predecessor to fail closed")
	}
}

func TestShapeReceiptContainsCountsOnly(t *testing.T) {
	receipt := CompareShape(ShapeReceiptInput{Repositories: 100, JenkinsFiles: 60, DirectCredentialReferences: 60, InheritedCredentialReferences: 12, ResolvedRelationships: 10, UnresolvedRelationships: 25, APISpecifications: 40, APIOperations: 400, ParserFailures: 2})
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if manifestContainsCustomerMaterial(payload) || strings.Contains(string(payload), `"repo":`) || strings.Contains(string(payload), `"path":`) {
		t.Fatalf("shape receipt must contain aggregate counts only: %s", payload)
	}
	if len(receipt.Deltas) != 9 {
		t.Fatalf("unexpected shape receipt: %+v", receipt)
	}
}

func TestOraclePackageDoesNotImportProductionClassifiers(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		payload, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"/core/detect", "/core/aggregate", "/core/risk", "/core/report"} {
			if bytes.Contains(payload, []byte(forbidden)) {
				t.Fatalf("oracle generator %s imports production classifier %s", entry.Name(), forbidden)
			}
		}
	}
}

func TestCommittedOracleMatchesIndependentCustomerShapeTruth(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", "scenarios", "wrkr", "customer-execution-truth", "oracle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var committed Oracle
	if err := json.Unmarshal(payload, &committed); err != nil {
		t.Fatal(err)
	}
	want := CustomerOracle()
	gotBytes, _ := json.Marshal(committed)
	wantBytes, _ := json.Marshal(want)
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("committed oracle drifted from independently authored shape\ngot=%s\nwant=%s", gotBytes, wantBytes)
	}
}

func TestScaleMultipliersPreserveSemanticOracle(t *testing.T) {
	for _, count := range []int{CustomerRepoCount, 384, 674} {
		root := filepath.Join(t.TempDir(), "twin")
		oracle, err := Materialize(root, count)
		if err != nil {
			t.Fatalf("materialize %d: %v", count, err)
		}
		if oracle.Repositories != count || oracle.JenkinsCallers != CustomerJenkinsCallers || oracle.APISpecFiles != CustomerAPISpecs || oracle.APIOperations != CustomerAPIOperations {
			t.Fatalf("scale %d changed semantic truth: %+v", count, oracle)
		}
	}
}

func TestOracleOrderingIsCanonicalAndContainsNoCustomerMaterial(t *testing.T) {
	oracle := CustomerOracle()
	seen := map[string]struct{}{}
	for _, stage := range oracle.ExpectedStages {
		if _, ok := seen[stage.StageID]; ok || stage.StageID == "" || stage.Unit == "" || stage.Count < 0 {
			t.Fatalf("oracle stages must remain unique and valid: %+v", oracle.ExpectedStages)
		}
		seen[stage.StageID] = struct{}{}
	}
	payload, _ := json.Marshal(oracle)
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"activity", "guardium", "agentic", "service mesh", "/users/", "private_key_value"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("oracle contains forbidden customer-derived material %q", forbidden)
		}
	}
}
