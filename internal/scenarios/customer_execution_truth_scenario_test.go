//go:build scenario

package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/nonhumanidentity"
	"github.com/Clyra-AI/wrkr/core/detect/openapi"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/customertwin"
)

func TestScenarioCustomerExecutionTruthTwin(t *testing.T) {
	root := filepath.Join(t.TempDir(), "customer-twin")
	oracle, err := customertwin.MaterializeCustomerShape(root)
	if err != nil {
		t.Fatalf("materialize customer twin: %v", err)
	}

	endpointFindings := 0
	for index := 1; index <= oracle.APISpecFiles; index++ {
		repoRoot := filepath.Join(root, customertwin.RepoName(index))
		findings, detectErr := openapi.New().Detect(context.Background(), detect.Scope{Org: "synthetic", Repo: customertwin.RepoName(index), Root: repoRoot}, detect.Options{})
		if detectErr != nil {
			t.Fatalf("detect OpenAPI repo %d: %v", index, detectErr)
		}
		for _, finding := range findings {
			if finding.FindingType == "openapi_endpoint" {
				endpointFindings++
			}
		}
	}
	if endpointFindings != oracle.APIOperations {
		t.Fatalf("OpenAPI oracle mismatch: got %d operations, want %d", endpointFindings, oracle.APIOperations)
	}

	schemaRepo := filepath.Join(root, customertwin.RepoName(2))
	identityFindings, err := nonhumanidentity.New().Detect(context.Background(), detect.Scope{Org: "synthetic", Repo: customertwin.RepoName(2), Root: schemaRepo}, detect.Options{})
	if err != nil {
		t.Fatalf("detect schema identity contamination: %v", err)
	}
	for _, finding := range identityFindings {
		if finding.Location == "schemas/credential-example.json" {
			t.Fatalf("schema declaration created an identity claim: %+v", finding)
		}
	}

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	topologyPath := filepath.Join(root, "execution-topology.yaml")
	runScenarioCommandJSONRaw(t, []string{"scan", "--path", root, "--execution-topology", topologyPath, "--state", statePath, "--quiet", "--json"})

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read twin state: %v", err)
	}
	var state struct {
		Findings                  []model.Finding     `json:"findings"`
		ScanQuality               *scanquality.Report `json:"scan_quality"`
		ExecutionTopologyDigest   string              `json:"execution_topology_digest"`
		ExecutionTopologyMappings int                 `json:"execution_topology_mappings"`
	}
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		t.Fatalf("parse twin state: %v", err)
	}
	if state.ScanQuality == nil || state.ScanQuality.ScanQualityVersion != "2" || state.ScanQuality.ReconciliationLedger == nil || !state.ScanQuality.ReconciliationLedger.Valid {
		t.Fatalf("expected valid scan-quality v2 ledger: %+v", state.ScanQuality)
	}
	if state.ExecutionTopologyDigest == "" || state.ExecutionTopologyMappings != 2 {
		t.Fatalf("expected Jenkins and API topology mappings in state, got digest=%q mappings=%d", state.ExecutionTopologyDigest, state.ExecutionTopologyMappings)
	}
	assertCustomerTwinFindingTruth(t, state.Findings, oracle)
	jenkinsFiles, resolved, unresolved := 0, 0, 0
	for _, receipt := range state.ScanQuality.SurfaceCoverage {
		if receipt.Surface == "ci_workflow:jenkins" {
			jenkinsFiles += receipt.Discovered
			resolved += receipt.Resolved
			unresolved += receipt.Unresolved
		}
	}
	if jenkinsFiles != oracle.JenkinsCallers || resolved != oracle.SharedLibraryCallers-oracle.UnmappedLibraryCallers || unresolved != oracle.UnmappedLibraryCallers+oracle.DynamicRelationships {
		t.Fatalf("Jenkins oracle mismatch: files=%d resolved=%d unresolved=%d oracle=%+v", jenkinsFiles, resolved, unresolved, oracle)
	}

	firstMD := filepath.Join(tmp, "first.md")
	secondMD := filepath.Join(tmp, "second.md")
	runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "ciso", "--md", "--md-path", firstMD, "--json"})
	runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "ciso", "--md", "--md-path", secondMD, "--json"})
	first, _ := os.ReadFile(firstMD)
	second, _ := os.ReadFile(secondMD)
	if !bytes.Equal(first, second) {
		t.Fatal("customer-twin report is not byte deterministic")
	}
	if !strings.Contains(string(first), "Evidence receipt:") {
		t.Fatalf("expected compact evidence receipt in report")
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := cli.Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify twin proof: code=%d stderr=%s", code, verifyErr.String())
	}
}

func TestScenarioCustomerExecutionTruthScale384(t *testing.T) {
	runCustomerTwinScaleScenario(t, 384)
}

func TestScenarioCustomerExecutionTruthScale674(t *testing.T) {
	runCustomerTwinScaleScenario(t, 674)
}

func runCustomerTwinScaleScenario(t *testing.T, repoCount int) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "customer-twin")
	oracle, err := customertwin.Materialize(root, repoCount)
	if err != nil {
		t.Fatalf("materialize %d-repository twin: %v", repoCount, err)
	}
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	started := time.Now()
	stopHeapSampler := make(chan struct{})
	heapReceipt := make(chan [2]uint64, 1)
	go samplePeakHeap(stopHeapSampler, heapReceipt)
	runScenarioCommandJSONRaw(t, []string{"scan", "--path", root, "--execution-topology", filepath.Join(root, "execution-topology.yaml"), "--state", statePath, "--quiet", "--json"})
	close(stopHeapSampler)
	heap := <-heapReceipt
	maxHeapAlloc, maxHeapSys := heap[0], heap[1]
	elapsed := time.Since(started)
	snapshot, err := state.LoadRaw(statePath)
	if err != nil {
		t.Fatalf("load %d-repository state: %v", repoCount, err)
	}
	if snapshot.ScanQuality == nil || snapshot.ScanQuality.ReconciliationLedger == nil || !snapshot.ScanQuality.ReconciliationLedger.Valid {
		t.Fatalf("invalid %d-repository reconciliation: %+v", repoCount, snapshot.ScanQuality)
	}
	assertCustomerTwinFindingTruth(t, snapshot.Findings, oracle)

	firstMD := filepath.Join(tmp, "first.md")
	secondMD := filepath.Join(tmp, "second.md")
	runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "design-partner-summary", "--share-profile", "design-partner", "--md", "--md-path", firstMD, "--json"})
	runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "design-partner-summary", "--share-profile", "design-partner", "--md", "--md-path", secondMD, "--json"})
	first, err := os.ReadFile(firstMD)
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(secondMD)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("%d-repository buyer report is not byte deterministic", repoCount)
	}
	lines := strings.Count(string(first), "\n") + 1
	if len(first) > 64*1024 || lines > 1500 {
		t.Fatalf("%d-repository report exceeded budget: bytes=%d lines=%d", repoCount, len(first), lines)
	}
	for _, forbidden := range []string{"plain_source_code", "unknown_durable", "approval approval", "private_key_value"} {
		if strings.Contains(strings.ToLower(string(first)), forbidden) {
			t.Fatalf("%d-repository buyer report leaked internal or unsafe text %q", repoCount, forbidden)
		}
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := cli.Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify %d-repository proof: code=%d stderr=%s", repoCount, code, verifyErr.String())
	}
	if maxHeapAlloc == 0 || maxHeapSys == 0 {
		t.Fatal("expected progress heap receipts for scale run")
	}
	t.Logf("customer twin scale receipt: repos=%d elapsed=%s peak_heap_alloc=%d peak_heap_sys=%d findings=%d state_bytes=%d report_bytes=%d report_lines=%d", repoCount, elapsed.Round(time.Millisecond), maxHeapAlloc, maxHeapSys, len(snapshot.Findings), fileSize(t, statePath), len(first), lines)
}

func samplePeakHeap(stop <-chan struct{}, receipt chan<- [2]uint64) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var maxAlloc, maxSys uint64
	for {
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		if stats.Alloc > maxAlloc {
			maxAlloc = stats.Alloc
		}
		if stats.HeapSys > maxSys {
			maxSys = stats.HeapSys
		}
		select {
		case <-stop:
			receipt <- [2]uint64{maxAlloc, maxSys}
			return
		case <-ticker.C:
		}
	}
}

func assertCustomerTwinFindingTruth(t *testing.T, findings []model.Finding, oracle customertwin.Oracle) {
	t.Helper()
	credentialRefs := map[string]struct{}{}
	relationships := map[string]model.ExecutionRelationship{}
	parserSources := map[string]struct{}{}
	generatedSpec, apiGenerator, apiConsumer, apiRuntime := false, false, false, false
	falseIdentitySources := map[string]struct{}{}
	for _, finding := range findings {
		if finding.ParseError != nil {
			parserSources[finding.Repo+"|"+finding.Location] = struct{}{}
		}
		if finding.FindingType == "secret_presence" {
			for _, evidence := range finding.Evidence {
				if evidence.Key != "workflow_secret_refs" {
					continue
				}
				for _, ref := range strings.Split(evidence.Value, ",") {
					if strings.TrimSpace(ref) != "" {
						credentialRefs[finding.Repo+"|"+finding.Location+"|"+strings.TrimSpace(ref)] = struct{}{}
					}
				}
			}
		}
		if finding.FindingType == "non_human_identity" && (finding.Location == "twin-manifest.json" || finding.Location == "schemas/credential-example.json") {
			falseIdentitySources[finding.Repo+"|"+finding.Location] = struct{}{}
		}
		if finding.Location == "build/api/service-38.json" && finding.FindingType == "openapi_specification" {
			for _, evidence := range finding.Evidence {
				generatedSpec = generatedSpec || (evidence.Key == "spec_origin" && evidence.Value == "generated_selected")
			}
		}
		for _, relationship := range finding.ExecutionRelationships {
			key := strings.Join([]string{relationship.Kind, relationship.Caller, relationship.Callee}, "|")
			if previous, ok := relationships[key]; ok && previous.ResolutionState != relationship.ResolutionState {
				t.Fatalf("contradictory relationship states for %s: %s and %s", key, previous.ResolutionState, relationship.ResolutionState)
			}
			relationships[key] = relationship
			apiGenerator = apiGenerator || relationship.Kind == "api_spec_generator"
			apiConsumer = apiConsumer || relationship.Kind == "api_spec_consumer"
			apiRuntime = apiRuntime || relationship.Kind == "api_runtime"
		}
	}
	if len(credentialRefs) != oracle.DirectCredentialRefs+oracle.InheritedCredentialRefs {
		t.Fatalf("credential-reference reconciliation: got %d want direct=%d inherited=%d", len(credentialRefs), oracle.DirectCredentialRefs, oracle.InheritedCredentialRefs)
	}
	if len(parserSources) != oracle.ParserFailures {
		t.Fatalf("canonical parser-source reconciliation: got %d want %d (%v)", len(parserSources), oracle.ParserFailures, parserSources)
	}
	if len(falseIdentitySources) != 0 {
		t.Fatalf("schema or oracle manifest created identity claims: %v", falseIdentitySources)
	}
	if !generatedSpec || !apiGenerator || !apiConsumer || !apiRuntime {
		t.Fatalf("missing generated/generator/consumer/runtime relationship truth: generated=%v generator=%v consumer=%v runtime=%v relationships=%+v", generatedSpec, apiGenerator, apiConsumer, apiRuntime, relationships)
	}
	jenkinsResolved, jenkinsUnresolved, dynamic := 0, 0, 0
	kindCounts := map[string]int{}
	for _, relationship := range relationships {
		kindCounts[relationship.Kind]++
		if relationship.Kind == "jenkins_shared_library" && relationship.ResolutionState == "resolved_declared" {
			jenkinsResolved++
		}
		if relationship.Kind == "jenkins_shared_library" && relationship.ResolutionState == "unresolved_external" {
			jenkinsUnresolved++
		}
		if relationship.ResolutionState == "unsupported_dynamic" {
			dynamic++
		}
	}
	if jenkinsResolved != oracle.SharedLibraryCallers-oracle.UnmappedLibraryCallers || jenkinsUnresolved != oracle.UnmappedLibraryCallers || dynamic < oracle.DynamicRelationships {
		t.Fatalf("typed relationship reconciliation failed: resolved=%d unresolved=%d dynamic=%d oracle=%+v", jenkinsResolved, jenkinsUnresolved, dynamic, oracle)
	}
	for kind, want := range map[string]int{"github_reusable_workflow": oracle.GitHubReusableCallers, "github_composite_action": oracle.GitHubCompositeCalls, "gitlab_include": oracle.GitLabIncludeCallers, "azure_template": oracle.AzureTemplateCallers, "api_spec_generator": oracle.APIGenerators} {
		if kindCounts[kind] != want {
			t.Fatalf("typed relationship %s: got %d want %d; relationships=%+v", kind, kindCounts[kind], want, relationships)
		}
	}
	for _, index := range []int{71, 72} {
		key := customertwin.RepoName(index) + "|.github/workflows/release.yml|REPO_" + fmt.Sprintf("%03d", index) + "_RELEASE_REF"
		if _, ok := credentialRefs[key]; !ok {
			t.Fatalf("missing repository-scoped duplicate-path reference %s", key)
		}
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}
