package actioncontracts

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildActionContractArtifactsIsDeterministicAndSensitiveToContent(t *testing.T) {
	t.Parallel()
	first, err := Build(testSnapshot(), BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build first collection: %v", err)
	}
	second, err := Build(testSnapshot(), BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build second collection: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same saved input must export identical artifacts\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first.Artifacts) != 1 || first.Artifacts[0].ArtifactID == "" || first.Artifacts[0].CanonicalContentDigest == "" {
		t.Fatalf("expected one identified artifact, got %+v", first)
	}
	if got, err := canonicalContentDigest(first.Artifacts[0]); err != nil || got != first.Artifacts[0].CanonicalContentDigest {
		t.Fatalf("artifact digest must be JCS reproducible: got %q err=%v want %q", got, err, first.Artifacts[0].CanonicalContentDigest)
	}

	changed := testSnapshot()
	changed.RiskReport.ComposedActionPaths[0].EvidenceRefs = append(changed.RiskReport.ComposedActionPaths[0].EvidenceRefs, "proof:changed")
	changed.RiskReport.ComposedActionPaths[0].ProposedActionContract = risk.BuildProposedActionContract(changed.RiskReport.ComposedActionPaths[0])
	third, err := Build(changed, BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build changed collection: %v", err)
	}
	if first.Artifacts[0].ArtifactID == third.Artifacts[0].ArtifactID {
		t.Fatalf("material evidence change must create a new artifact identity: %+v", third.Artifacts[0])
	}
}

func TestWriteActionContractArtifactsIsAtomicAndRejectsCollisions(t *testing.T) {
	t.Parallel()
	collection, err := Build(testSnapshot(), BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build collection: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "artifacts")
	paths, err := Write(collection, dir)
	if err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected artifact plus manifest, got %v", paths)
	}
	if _, err := os.Stat(filepath.Join(dir, Filename(collection.Artifacts[0]))); err != nil {
		t.Fatalf("expected atomic artifact file: %v", err)
	}
	if _, err := Write(collection, dir); err == nil {
		t.Fatal("expected collision to fail closed")
	}
}

func TestWriteActionContractArtifactsPreflightsManifestBeforeArtifacts(t *testing.T) {
	t.Parallel()
	collection, err := Build(testSnapshot(), BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build collection: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "artifacts")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write colliding manifest: %v", err)
	}
	if _, err := Write(collection, dir); err == nil {
		t.Fatal("expected manifest collision to fail closed")
	}
	if _, err := os.Stat(filepath.Join(dir, Filename(collection.Artifacts[0]))); !os.IsNotExist(err) {
		t.Fatalf("artifact file must not be written after manifest preflight failure, stat err=%v", err)
	}
}

func TestWriteActionContractArtifactsRejectsSymlinkDirectory(t *testing.T) {
	t.Parallel()
	collection, err := Build(testSnapshot(), BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build collection: %v", err)
	}
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Write(collection, link); err == nil {
		t.Fatal("expected symlink output directory to be rejected")
	}
}

func TestBuildActionContractArtifactsMatchesSelectorBeforeRedaction(t *testing.T) {
	t.Parallel()
	snapshot := testSnapshot()
	snapshot.RiskReport.ComposedActionPaths[0].ResolutionKey = "acme/private|release.yml"
	snapshot.RiskReport.ComposedActionPaths[0].TargetIdentity = "acme/private"
	snapshot.RiskReport.ComposedActionPaths[0].ProposedActionContract = risk.BuildProposedActionContract(snapshot.RiskReport.ComposedActionPaths[0])
	internal, err := Build(snapshot, BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build internal artifact: %v", err)
	}
	selector := internal.Artifacts[0].ContractID
	redacted, err := Build(snapshot, BuildOptions{
		ShareProfile: report.ShareProfileCustomerRedacted,
		ContractID:   selector,
	})
	if err != nil {
		t.Fatalf("build selected redacted artifact with saved contract id: %v", err)
	}
	if len(redacted.Artifacts) != 1 {
		t.Fatalf("expected one selected redacted artifact, got %+v", redacted)
	}
	if redacted.Artifacts[0].ContractID == selector || !redacted.Artifacts[0].Variant.Redacted {
		t.Fatalf("expected selected export to emit redacted identity, got selector=%s artifact=%+v", selector, redacted.Artifacts[0])
	}
}

func TestBuildActionContractArtifactsRedactedExportKeepsAllSavedContracts(t *testing.T) {
	t.Parallel()
	const contractCount = 12
	collection, err := Build(testSnapshotWithContracts(contractCount), BuildOptions{ShareProfile: report.ShareProfileCustomerRedacted})
	if err != nil {
		t.Fatalf("build redacted collection: %v", err)
	}
	if len(collection.Artifacts) != contractCount {
		t.Fatalf("redacted artifact export must not inherit report caps, got %d artifacts", len(collection.Artifacts))
	}
}

func TestBuildActionContractArtifactsRedactsBeforeAssigningVariantIdentity(t *testing.T) {
	t.Parallel()
	snapshot := testSnapshot()
	snapshot.RiskReport.ComposedActionPaths[0].ResolutionKey = "acme/private|release.yml"
	snapshot.RiskReport.ComposedActionPaths[0].TargetIdentity = "acme/private"
	snapshot.RiskReport.ComposedActionPaths[0].ProposedActionContract = risk.BuildProposedActionContract(snapshot.RiskReport.ComposedActionPaths[0])
	internal, err := Build(snapshot, BuildOptions{ShareProfile: report.ShareProfileInternal})
	if err != nil {
		t.Fatalf("build internal artifact: %v", err)
	}
	redacted, err := Build(snapshot, BuildOptions{ShareProfile: report.ShareProfileCustomerRedacted})
	if err != nil {
		t.Fatalf("build redacted artifact: %v", err)
	}
	if internal.Artifacts[0].ArtifactID == redacted.Artifacts[0].ArtifactID || !redacted.Artifacts[0].Variant.Redacted {
		t.Fatalf("redacted variant requires a distinct identity: internal=%+v redacted=%+v", internal.Artifacts[0], redacted.Artifacts[0])
	}
	if strings.Contains(redacted.Artifacts[0].ResolutionKey, "acme/private") || strings.Contains(redacted.Artifacts[0].Contract.CompositionRef, "acme/private") {
		t.Fatalf("redacted artifact leaked private composition material: %+v", redacted.Artifacts[0])
	}
}

func testSnapshot() state.Snapshot {
	composition := risk.ComposedActionPath{
		CompositionID:        "cap-1a2b3c4d",
		ResolutionKey:        "rk-release",
		OutcomeKey:           "outcome:release",
		DurableOutcomeKey:    "outcome:release",
		OutcomeClass:         "release_publish",
		TargetIdentity:       "release:stable",
		TargetClass:          risk.TargetClassReleaseAdjacent,
		Environment:          "production",
		EvidenceState:        risk.EvidenceStateVerified,
		FreshnessState:       evidencepolicy.FreshnessStateFresh,
		PolicyCoverageStatus: risk.PolicyCoverageStatusRuntimeProven,
		RecommendedControl:   risk.RecommendedControlApprovalRequired,
		EvidenceRefs:         []string{"validation:release", "effect:publish", "check:tests", "producer:gait_policy", "sandbox:release", "compensation:rollback"},
		SourceDecisionRefs:   []string{"policy:release", "sha256:policy"},
		ProofRefs:            []string{"proof:risk-assessment"},
		Stages: []risk.CompositionStage{
			{StageID: "stage-source", Role: risk.CompositionStageRoleSource, ParentAuthorityRef: "authority:root"},
			{StageID: "stage-sink", Role: risk.CompositionStageRoleDestructiveSink},
		},
		Transitions: []risk.CompositionTransition{{TransitionID: "transition-1", FromStageID: "stage-source", ToStageID: "stage-sink"}},
	}
	composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
	composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	return state.Snapshot{Version: state.SnapshotVersion, RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}
}

func testSnapshotWithContracts(count int) state.Snapshot {
	out := testSnapshot()
	compositions := make([]risk.ComposedActionPath, 0, count)
	for idx := 0; idx < count; idx++ {
		composition := testSnapshot().RiskReport.ComposedActionPaths[0]
		composition.CompositionID = fmt.Sprintf("cap-%08x", idx+1)
		composition.ResolutionKey = fmt.Sprintf("acme/private-%02d|release.yml", idx)
		composition.OutcomeKey = fmt.Sprintf("outcome:release:%02d", idx)
		composition.DurableOutcomeKey = fmt.Sprintf("outcome:release:%02d", idx)
		composition.TargetIdentity = fmt.Sprintf("acme/private-%02d", idx)
		composition.AffectedAsset = fmt.Sprintf("service-%02d", idx)
		composition.EvidenceRefs = append(append([]string(nil), composition.EvidenceRefs...), fmt.Sprintf("evidence:%02d", idx))
		composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
		composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
		compositions = append(compositions, composition)
	}
	out.RiskReport.ComposedActionPaths = compositions
	return out
}
