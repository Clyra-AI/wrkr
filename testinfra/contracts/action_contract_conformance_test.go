package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/export/actioncontracts"
	"github.com/Clyra-AI/wrkr/core/report"
)

func TestActionContractConformanceExactBytesRegenerateFromWrkr(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	command := exec.Command("bash", filepath.Join(repoRoot, "scripts", "generate_action_contract_conformance.sh"), "--check")
	command.Dir = repoRoot
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("real-pipeline Action Contract fixtures must regenerate byte-identically: %v\n%s", err, output)
	}
}

func TestActionContractConformanceMissingExternalConsumersReturnsDependencyMissing(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	command := exec.Command("bash", filepath.Join(repoRoot, "scripts", "test_action_contract_interop.sh"))
	command.Dir = repoRoot
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "WRKR_GAIT_ACTION_CONTRACT_CONSUMER=") || strings.HasPrefix(value, "WRKR_AXYM_ACTION_CONTRACT_CONSUMER=") {
			continue
		}
		command.Env = append(command.Env, value)
	}
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 7 {
		t.Fatalf("missing external consumers must exit 7: err=%v output=%s", err, output)
	}
	if !strings.Contains(string(output), "dependency_missing") {
		t.Fatalf("missing-consumer result must be machine-readable dependency_missing: %s", output)
	}
}

func TestActionContractConformanceManifestPinsNineVerifiedScenarios(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	manifestPath := filepath.Join(repoRoot, "scenarios", "cross-product", "action-contract-interop", "expected", "fixture-manifest.json")
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read conformance manifest: %v", err)
	}
	var manifest struct {
		FixtureVersion string `json:"fixture_version"`
		Producer       struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"producer"`
		Schemas struct {
			Artifact string `json:"artifact"`
			Contract string `json:"contract"`
			Packet   string `json:"packet"`
		} `json:"schemas"`
		Scenarios []struct {
			ScenarioID             string   `json:"scenario_id"`
			ArtifactPath           string   `json:"artifact_path"`
			ArtifactSHA256         string   `json:"artifact_sha256"`
			PacketJSONPath         string   `json:"packet_json_path"`
			PacketJSONSHA256       string   `json:"packet_json_sha256"`
			PacketMarkdownPath     string   `json:"packet_markdown_path"`
			PacketMarkdownSHA256   string   `json:"packet_markdown_sha256"`
			ArtifactID             string   `json:"artifact_id"`
			CanonicalContentDigest string   `json:"canonical_content_digest"`
			ContractID             string   `json:"contract_id"`
			ContractFamilyID       string   `json:"contract_family_id"`
			Revision               int      `json:"revision"`
			ConsumerEntrypoints    []string `json:"consumer_entrypoints"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("parse conformance manifest: %v", err)
	}
	if manifest.FixtureVersion != "1" || manifest.Producer.Name != "wrkr" || manifest.Producer.Version == "" || manifest.Schemas.Artifact != "1" || manifest.Schemas.Contract != "3" || manifest.Schemas.Packet != "1" {
		t.Fatalf("unexpected manifest producer/schema contract: %+v", manifest)
	}
	want := map[string]bool{
		"customer-data-to-egress": false, "workflow-to-deploy": false, "secret-to-network": false,
		"package-to-release": false, "excessive-child-authority": false, "failed-effect-validation": false,
		"approval-expiry": false, "compensation": false, "supersession": false,
	}
	if len(manifest.Scenarios) != len(want) {
		t.Fatalf("expected nine conformance scenarios, got %d", len(manifest.Scenarios))
	}
	for _, scenario := range manifest.Scenarios {
		if _, ok := want[scenario.ScenarioID]; !ok {
			t.Fatalf("unexpected conformance scenario %q", scenario.ScenarioID)
		}
		want[scenario.ScenarioID] = true
		for _, path := range []string{scenario.ArtifactPath, scenario.PacketJSONPath, scenario.PacketMarkdownPath} {
			if filepath.IsAbs(path) || strings.Contains(filepath.ToSlash(path), "..") {
				t.Fatalf("manifest path must remain repo-relative: %q", path)
			}
		}
		artifactPayload := mustReadConformanceBytes(t, repoRoot, scenario.ArtifactPath, scenario.ArtifactSHA256)
		packetPayload := mustReadConformanceBytes(t, repoRoot, scenario.PacketJSONPath, scenario.PacketJSONSHA256)
		_ = mustReadConformanceBytes(t, repoRoot, scenario.PacketMarkdownPath, scenario.PacketMarkdownSHA256)
		var artifact actioncontracts.Artifact
		if err := json.Unmarshal(artifactPayload, &artifact); err != nil {
			t.Fatalf("parse artifact for %s: %v", scenario.ScenarioID, err)
		}
		if err := actioncontracts.VerifyArtifact(artifact); err != nil {
			t.Fatalf("verify artifact for %s: %v", scenario.ScenarioID, err)
		}
		assertActionContractConformanceScenarioSemantics(t, scenario.ScenarioID, artifact)
		var packet report.ActionContractPacket
		if err := json.Unmarshal(packetPayload, &packet); err != nil {
			t.Fatalf("parse packet for %s: %v", scenario.ScenarioID, err)
		}
		if artifact.ArtifactID != scenario.ArtifactID || artifact.CanonicalContentDigest != scenario.CanonicalContentDigest || artifact.ContractID != scenario.ContractID || artifact.ContractFamilyID != scenario.ContractFamilyID || artifact.Revision != scenario.Revision {
			t.Fatalf("manifest identity mismatch for %s: scenario=%+v artifact=%+v", scenario.ScenarioID, scenario, artifact)
		}
		if packet.Identity.ArtifactID != artifact.ArtifactID || packet.Identity.ContractID != artifact.ContractID {
			t.Fatalf("packet identity mismatch for %s: packet=%+v artifact=%+v", scenario.ScenarioID, packet.Identity, artifact)
		}
		if len(scenario.ConsumerEntrypoints) != 2 || !strings.Contains(strings.Join(scenario.ConsumerEntrypoints, "|"), "WRKR_GAIT_ACTION_CONTRACT_CONSUMER") || !strings.Contains(strings.Join(scenario.ConsumerEntrypoints, "|"), "WRKR_AXYM_ACTION_CONTRACT_CONSUMER") {
			t.Fatalf("scenario %s missing explicit external consumer entrypoints: %v", scenario.ScenarioID, scenario.ConsumerEntrypoints)
		}
	}
	for scenarioID, seen := range want {
		if !seen {
			t.Fatalf("missing conformance scenario %s", scenarioID)
		}
	}
}

func TestActionContractConformanceTamperedBytesFailDigestAndManifest(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	manifest := mustReadJSON(t, filepath.Join(repoRoot, "scenarios", "cross-product", "action-contract-interop", "expected", "fixture-manifest.json"))
	scenarios, _ := manifest["scenarios"].([]any)
	first := scenarios[0].(map[string]any)
	artifactPath := filepath.Join(repoRoot, first["artifact_path"].(string))
	payload, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	tampered := append([]byte(nil), payload...)
	for index := range tampered {
		if tampered[index] == 'w' {
			tampered[index] = 'x'
			break
		}
	}
	if actionContractConformanceSHA256(tampered) == first["artifact_sha256"] {
		t.Fatal("tampered bytes must invalidate the pinned manifest digest")
	}
	var artifact actioncontracts.Artifact
	if err := json.Unmarshal(tampered, &artifact); err == nil {
		if err := actioncontracts.VerifyArtifact(artifact); err == nil {
			t.Fatal("tampered parseable artifact must fail canonical verification")
		}
	}
}

func TestActionContractConformanceStaleManifestDigestFails(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	manifest := mustReadJSON(t, filepath.Join(repoRoot, "scenarios", "cross-product", "action-contract-interop", "expected", "fixture-manifest.json"))
	scenarios, _ := manifest["scenarios"].([]any)
	first := scenarios[0].(map[string]any)
	payload, err := os.ReadFile(filepath.Join(repoRoot, first["artifact_path"].(string)))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	if err := verifyActionContractConformanceDigest(payload, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("a stale manifest digest must fail before consumer handoff")
	}
}

func mustReadConformanceBytes(t *testing.T, repoRoot, relativePath, expectedDigest string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(relativePath)))
	if err != nil {
		t.Fatalf("read conformance fixture %s: %v", relativePath, err)
	}
	if err := verifyActionContractConformanceDigest(payload, expectedDigest); err != nil {
		t.Fatalf("conformance fixture digest mismatch for %s: %v", relativePath, err)
	}
	return payload
}

func verifyActionContractConformanceDigest(payload []byte, expectedDigest string) error {
	got := actionContractConformanceSHA256(payload)
	if got != expectedDigest {
		return errors.New("got=" + got + " want=" + expectedDigest)
	}
	return nil
}

func assertActionContractConformanceScenarioSemantics(t *testing.T, scenarioID string, artifact actioncontracts.Artifact) {
	t.Helper()
	contract := artifact.Contract
	switch scenarioID {
	case "excessive-child-authority":
		if contract.MaximumDelegationDepth != 4 || contract.AuthorityReadinessState != "blocked_by_contradiction" || !containsConformanceString(contract.ReasonCodes, "delegation:excessive_child_authority") {
			t.Fatalf("excessive-child-authority mutation is missing: %+v", contract)
		}
	case "failed-effect-validation":
		matched := false
		for _, precondition := range contract.Preconditions {
			if precondition.Kind == "effect_contract" && precondition.ObservedResult == "failed" && precondition.EvidenceState == "contradictory" {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("failed-effect-validation mutation is missing: %+v", contract.Preconditions)
		}
	case "approval-expiry":
		if contract.ApprovalRequirement == nil || contract.ApprovalRequirement.FreshnessState != "expired" || !containsConformanceString(contract.ApprovalRequirement.ReasonCodes, "approval:expired") {
			t.Fatalf("approval-expiry mutation is missing: %+v", contract.ApprovalRequirement)
		}
	case "compensation":
		if !contract.CompensationRequired || contract.CompensationRequirement == nil || !contract.CompensationRequirement.Required || contract.CompensationRequirement.ProcedureRef != "compensation:rollback-release" {
			t.Fatalf("compensation mutation is missing: %+v", contract.CompensationRequirement)
		}
	case "supersession":
		if artifact.Revision != 2 || contract.Revision != 2 || strings.TrimSpace(contract.SupersedesRef) == "" {
			t.Fatalf("supersession mutation is missing: %+v", contract)
		}
	}
}

func containsConformanceString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func actionContractConformanceSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}
