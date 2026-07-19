package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/export/actioncontracts"
	"github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

type fixtureSpec struct {
	FixtureVersion    string                  `json:"fixture_version"`
	BaseScanRoot      string                  `json:"base_scan_root"`
	Scenarios         []scenarioSpec          `json:"scenarios"`
	ExternalConsumers map[string]consumerSpec `json:"external_consumers"`
}

type scenarioSpec struct {
	ScenarioID string `json:"scenario_id"`
	PatternID  string `json:"pattern_id"`
	Mutation   string `json:"mutation"`
}

type consumerSpec struct {
	CommandEnv string `json:"command_env"`
	Receipt    string `json:"receipt"`
}

type fixtureManifest struct {
	FixtureVersion    string                  `json:"fixture_version"`
	Producer          manifestProducer        `json:"producer"`
	Schemas           manifestSchemas         `json:"schemas"`
	ExternalConsumers map[string]consumerSpec `json:"external_consumers"`
	Scenarios         []manifestScenario      `json:"scenarios"`
}

type manifestProducer struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type manifestSchemas struct {
	Artifact string `json:"artifact"`
	Contract string `json:"contract"`
	Packet   string `json:"packet"`
}

type manifestScenario struct {
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
}

var safeFixtureScenarioID = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: action_contract_conformance prepare|finalize [flags]")
	}
	var err error
	switch os.Args[1] {
	case "prepare":
		err = runPrepare(os.Args[2:])
	case "finalize":
		err = runFinalize(os.Args[2:])
	default:
		err = fmt.Errorf("unsupported command %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func runPrepare(args []string) error {
	fs := flag.NewFlagSet("prepare", flag.ContinueOnError)
	statePath := fs.String("state", "", "completed Wrkr scan state")
	specPath := fs.String("spec", "", "scenario spec")
	outputDir := fs.String("output-dir", "", "scenario state output directory")
	indexPath := fs.String("index", "", "TSV scenario index")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*statePath) == "" || strings.TrimSpace(*specPath) == "" || strings.TrimSpace(*outputDir) == "" || strings.TrimSpace(*indexPath) == "" {
		return errors.New("prepare requires --state, --spec, --output-dir, and --index")
	}
	spec, err := loadSpec(*specPath)
	if err != nil {
		return err
	}
	base, err := state.Load(*statePath)
	if err != nil {
		return fmt.Errorf("load scanned state: %w", err)
	}
	if base.RiskReport == nil || len(base.RiskReport.ComposedActionPaths) == 0 {
		return errors.New("real scan produced no composed Action Contracts")
	}
	if err := os.MkdirAll(*outputDir, 0o750); err != nil {
		return fmt.Errorf("create scenario state directory: %w", err)
	}

	candidates := append([]risk.ComposedActionPath(nil), base.RiskReport.ComposedActionPaths...)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].PatternID+"|"+candidates[i].CompositionID < candidates[j].PatternID+"|"+candidates[j].CompositionID
	})
	patternCursor := map[string]int{}
	var index strings.Builder
	for _, scenario := range spec.Scenarios {
		candidate, next, err := selectScenarioComposition(candidates, scenario.PatternID, patternCursor[scenario.PatternID])
		if err != nil {
			return fmt.Errorf("scenario %s: %w", scenario.ScenarioID, err)
		}
		patternCursor[scenario.PatternID] = next
		composition, err := cloneComposition(candidate)
		if err != nil {
			return fmt.Errorf("clone scenario %s: %w", scenario.ScenarioID, err)
		}
		if composition.ProposedActionContract == nil {
			return fmt.Errorf("scenario %s selected a composition without a v3 contract", scenario.ScenarioID)
		}
		if err := applyScenarioMutation(&composition, scenario); err != nil {
			return err
		}
		composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
		scenarioState := state.Snapshot{Version: state.SnapshotVersion, RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}
		path := filepath.Join(*outputDir, scenario.ScenarioID+".json")
		if err := state.Save(path, scenarioState); err != nil {
			return fmt.Errorf("save scenario state %s: %w", scenario.ScenarioID, err)
		}
		_, _ = fmt.Fprintf(&index, "%s\t%s\t%s\n", scenario.ScenarioID, path, composition.ProposedActionContract.ContractID)
	}
	if err := os.WriteFile(*indexPath, []byte(index.String()), 0o600); err != nil {
		return fmt.Errorf("write scenario index: %w", err)
	}
	return nil
}

func runFinalize(args []string) error {
	fs := flag.NewFlagSet("finalize", flag.ContinueOnError)
	specPath := fs.String("spec", "", "scenario spec")
	generatedDir := fs.String("generated-dir", "", "generated expected tree")
	manifestRoot := fs.String("manifest-root", "", "repo-relative committed expected root")
	outputPath := fs.String("output", "", "manifest output path")
	producerVersion := fs.String("producer-version", "devel", "Wrkr producer version")
	repoRoot := fs.String("repo-root", ".", "Wrkr repository root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*specPath) == "" || strings.TrimSpace(*generatedDir) == "" || strings.TrimSpace(*manifestRoot) == "" || strings.TrimSpace(*outputPath) == "" {
		return errors.New("finalize requires --spec, --generated-dir, --manifest-root, and --output")
	}
	if strings.TrimSpace(*producerVersion) == "" {
		return errors.New("finalize requires a non-empty producer version")
	}
	cleanRoot, err := cleanManifestRoot(*manifestRoot)
	if err != nil {
		return err
	}
	spec, err := loadSpec(*specPath)
	if err != nil {
		return err
	}
	manifest := fixtureManifest{
		FixtureVersion: spec.FixtureVersion,
		Producer:       manifestProducer{Name: actioncontracts.Producer, Version: strings.TrimSpace(*producerVersion)},
		Schemas: manifestSchemas{
			Artifact: actioncontracts.SchemaVersion,
			Contract: risk.ProposedActionContractVersionV3,
			Packet:   report.ActionContractPacketSchemaVersion,
		},
		ExternalConsumers: spec.ExternalConsumers,
		Scenarios:         make([]manifestScenario, 0, len(spec.Scenarios)),
	}
	for _, scenario := range spec.Scenarios {
		item, err := finalizeScenario(*repoRoot, *generatedDir, cleanRoot, scenario, spec.ExternalConsumers)
		if err != nil {
			return fmt.Errorf("scenario %s: %w", scenario.ScenarioID, err)
		}
		manifest.Scenarios = append(manifest.Scenarios, item)
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fixture manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*outputPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write fixture manifest: %w", err)
	}
	return nil
}

func selectScenarioComposition(values []risk.ComposedActionPath, pattern string, cursor int) (risk.ComposedActionPath, int, error) {
	matches := make([]risk.ComposedActionPath, 0)
	for _, value := range values {
		if strings.TrimSpace(value.PatternID) == strings.TrimSpace(pattern) && value.ProposedActionContract != nil {
			matches = append(matches, value)
		}
	}
	if len(matches) == 0 {
		return risk.ComposedActionPath{}, cursor, fmt.Errorf("real scan has no composition for pattern %q", pattern)
	}
	selected := matches[cursor%len(matches)]
	return selected, cursor + 1, nil
}

func applyScenarioMutation(composition *risk.ComposedActionPath, scenario scenarioSpec) error {
	contract := composition.ProposedActionContract
	if contract == nil {
		return fmt.Errorf("scenario %s has no contract", scenario.ScenarioID)
	}
	switch scenario.Mutation {
	case "none":
	case "excessive_child_authority":
		contract.MaximumDelegationDepth = 4
		for index := range contract.AuthorityRequirements {
			if contract.AuthorityRequirements[index].Kind == "delegation_root" {
				contract.AuthorityRequirements[index].EvidenceState = risk.EvidenceStateContradictory
				contract.AuthorityRequirements[index].ReasonCodes = uniqueSorted(append(contract.AuthorityRequirements[index].ReasonCodes, "authority:excessive_child_scope"))
			}
		}
		contract.AuthorityReadinessState = "blocked_by_contradiction"
		contract.ReadinessState = risk.ActionContractReadinessBlockedContradict
		contract.ReasonCodes = uniqueSorted(append(contract.ReasonCodes, "delegation:excessive_child_authority"))
	case "failed_effect_validation":
		for index := range contract.Preconditions {
			if contract.Preconditions[index].Kind == "effect_contract" {
				contract.Preconditions[index].ObservedResult = "failed"
				contract.Preconditions[index].EvidenceState = risk.EvidenceStateContradictory
				contract.Preconditions[index].ReasonCodes = uniqueSorted(append(contract.Preconditions[index].ReasonCodes, "precondition:effect_contract:failed"))
			}
		}
		contract.ReadinessState = risk.ActionContractReadinessBlockedContradict
		contract.ReasonCodes = uniqueSorted(append(contract.ReasonCodes, "effect_validation:failed"))
	case "approval_expiry":
		if contract.ApprovalRequirement == nil {
			return errors.New("approval-expiry scenario requires approval requirement")
		}
		contract.ApprovalRequirement.EvidenceState = risk.EvidenceStateUnknown
		contract.ApprovalRequirement.FreshnessState = evidencepolicy.FreshnessStateExpired
		contract.ApprovalRequirement.ReasonCodes = uniqueSorted(append(contract.ApprovalRequirement.ReasonCodes, "approval:expired"))
		contract.ReadinessState = "needs_evidence"
	case "compensation":
		if contract.CompensationRequirement == nil {
			return errors.New("compensation scenario requires compensation requirement")
		}
		contract.CompensationRequired = true
		contract.CompensationRequirement.Required = true
		contract.CompensationRequirement.Kind = "documented_recovery"
		contract.CompensationRequirement.ProcedureRef = "compensation:rollback-release"
		contract.CompensationRequirement.Target = firstNonEmpty(contract.CompensationRequirement.Target, "release:stable")
		contract.CompensationRequirement.ExecutionWindow = "PT15M"
		contract.CompensationRequirement.VerificationRequired = true
		contract.CompensationRequirement.EvidenceState = risk.EvidenceStateVerified
		contract.CompensationRequirement.FreshnessState = evidencepolicy.FreshnessStateFresh
		contract.CompensationRequirement.EvidenceRefs = uniqueSorted(append(contract.CompensationRequirement.EvidenceRefs, "compensation:rollback-release"))
	case "supersession":
		predecessor := risk.CloneProposedActionContract(contract)
		observations := scenarioLifecycleObservations(scenario.ScenarioID)
		successor, err := risk.BuildProposedActionContractRevision(*composition, predecessor, observations)
		if err != nil {
			return fmt.Errorf("build supersession revision: %w", err)
		}
		composition.ProposedActionContract = successor
		return nil
	default:
		return fmt.Errorf("scenario %s uses unsupported mutation %q", scenario.ScenarioID, scenario.Mutation)
	}
	risk.RefreshProposedActionContractIdentity(contract)
	contract.LifecycleObservations = risk.NormalizeProposedActionLifecycleObservations(scenarioLifecycleObservations(scenario.ScenarioID))
	return nil
}

func scenarioLifecycleObservations(scenarioID string) []risk.ProposedActionLifecycleObservation {
	kind := risk.LifecycleObservationProposalCreation
	producer := "wrkr"
	stateValue := risk.EvidenceStateVerified
	freshness := evidencepolicy.FreshnessStateFresh
	switch scenarioID {
	case "excessive-child-authority":
		kind, producer = risk.LifecycleObservationRejection, "gait"
	case "failed-effect-validation":
		kind, producer, stateValue = risk.LifecycleObservationEffect, "gait", risk.EvidenceStateContradictory
	case "approval-expiry":
		kind, producer, stateValue, freshness = risk.LifecycleObservationActivationRequest, "gait", risk.EvidenceStateUnknown, evidencepolicy.FreshnessStateExpired
	case "compensation":
		kind, producer = risk.LifecycleObservationAxymVerification, "axym"
	case "supersession":
		kind, producer = risk.LifecycleObservationSupersession, "gait"
	}
	return []risk.ProposedActionLifecycleObservation{{
		Kind: kind, Producer: producer, EvidenceState: stateValue, FreshnessState: freshness,
		ObservedAt: "2026-07-19T00:00:00Z", EvidenceRefs: []string{"interop:" + scenarioID}, ProofRefs: []string{"proof:interop:" + scenarioID},
	}}
}

func finalizeScenario(repoRoot, generatedDir, manifestRoot string, scenario scenarioSpec, consumers map[string]consumerSpec) (manifestScenario, error) {
	generatedRoot, err := os.OpenRoot(generatedDir)
	if err != nil {
		return manifestScenario{}, fmt.Errorf("open generated fixture root: %w", err)
	}
	defer func() {
		_ = generatedRoot.Close()
	}()

	scenarioDir := scenario.ScenarioID
	artifactManifestPayload, err := generatedRoot.ReadFile(filepath.Join(scenarioDir, "manifest.json"))
	if err != nil {
		return manifestScenario{}, fmt.Errorf("read exporter manifest: %w", err)
	}
	var exporterManifest struct {
		Artifacts []actioncontracts.ManifestItem `json:"artifacts"`
	}
	if err := json.Unmarshal(artifactManifestPayload, &exporterManifest); err != nil || len(exporterManifest.Artifacts) != 1 {
		return manifestScenario{}, fmt.Errorf("parse exporter manifest with one artifact: %w", err)
	}
	artifactFilename := exporterManifest.Artifacts[0].Filename
	if strings.TrimSpace(artifactFilename) == "" || filepath.IsAbs(artifactFilename) || filepath.Base(artifactFilename) != artifactFilename || strings.Contains(artifactFilename, `\`) {
		return manifestScenario{}, fmt.Errorf("unsafe exporter artifact filename %q", artifactFilename)
	}
	artifactPayload, err := generatedRoot.ReadFile(filepath.Join(scenarioDir, artifactFilename))
	if err != nil {
		return manifestScenario{}, fmt.Errorf("read artifact: %w", err)
	}
	var artifact actioncontracts.Artifact
	if err := json.Unmarshal(artifactPayload, &artifact); err != nil {
		return manifestScenario{}, fmt.Errorf("parse artifact: %w", err)
	}
	if err := actioncontracts.VerifyArtifact(artifact); err != nil {
		return manifestScenario{}, fmt.Errorf("verify artifact digest: %w", err)
	}
	exporterItem := exporterManifest.Artifacts[0]
	if exporterItem.ArtifactID != artifact.ArtifactID || exporterItem.ContractID != artifact.ContractID || exporterItem.CanonicalContentDigest != artifact.CanonicalContentDigest {
		return manifestScenario{}, errors.New("exporter manifest identity does not match artifact bytes")
	}
	packetJSONPayload, err := generatedRoot.ReadFile(filepath.Join(scenarioDir, "packet.json"))
	if err != nil {
		return manifestScenario{}, fmt.Errorf("read packet JSON: %w", err)
	}
	var packet report.ActionContractPacket
	if err := json.Unmarshal(packetJSONPayload, &packet); err != nil {
		return manifestScenario{}, fmt.Errorf("parse packet JSON: %w", err)
	}
	if packet.Identity.ArtifactID != artifact.ArtifactID || packet.Identity.ContractID != artifact.ContractID || packet.Identity.CanonicalContentDigest != artifact.CanonicalContentDigest {
		return manifestScenario{}, errors.New("packet identity does not match exact artifact bytes")
	}
	packetMarkdownPayload, err := generatedRoot.ReadFile(filepath.Join(scenarioDir, "packet.md"))
	if err != nil {
		return manifestScenario{}, fmt.Errorf("read packet Markdown: %w", err)
	}
	if !strings.Contains(string(packetMarkdownPayload), artifact.ContractID) {
		return manifestScenario{}, errors.New("packet Markdown does not reference selected contract")
	}
	if err := validateSchemas(repoRoot, artifactPayload, packetJSONPayload); err != nil {
		return manifestScenario{}, err
	}
	entrypoints := make([]string, 0, len(consumers))
	for _, name := range sortedConsumerNames(consumers) {
		entrypoints = append(entrypoints, consumers[name].CommandEnv+" {artifact_path}")
	}
	root := filepath.ToSlash(manifestRoot)
	return manifestScenario{
		ScenarioID:   scenario.ScenarioID,
		ArtifactPath: root + "/" + scenario.ScenarioID + "/" + artifactFilename, ArtifactSHA256: sha256Digest(artifactPayload),
		PacketJSONPath: root + "/" + scenario.ScenarioID + "/packet.json", PacketJSONSHA256: sha256Digest(packetJSONPayload),
		PacketMarkdownPath: root + "/" + scenario.ScenarioID + "/packet.md", PacketMarkdownSHA256: sha256Digest(packetMarkdownPayload),
		ArtifactID: artifact.ArtifactID, CanonicalContentDigest: artifact.CanonicalContentDigest,
		ContractID: artifact.ContractID, ContractFamilyID: artifact.ContractFamilyID, Revision: artifact.Revision,
		ConsumerEntrypoints: entrypoints,
	}, nil
}

func validateSchemas(repoRoot string, artifactPayload, packetPayload []byte) error {
	repo, err := os.OpenRoot(repoRoot)
	if err != nil {
		return fmt.Errorf("open repo root: %w", err)
	}
	defer func() {
		_ = repo.Close()
	}()
	v3Path := filepath.Join("schemas", "v1", "proposed-action-contract-v3.schema.json")
	artifactPath := filepath.Join("schemas", "v1", "proposed-action-contract-artifact.schema.json")
	packetPath := filepath.Join("schemas", "v1", "report", "action-contract-packet.schema.json")
	compiler := jsonschema.NewCompiler()
	for uri, path := range map[string]string{
		"https://wrkr.dev/schemas/v1/proposed-action-contract-v3.schema.json": v3Path,
		artifactPath: artifactPath,
		packetPath:   packetPath,
	} {
		payload, err := repo.ReadFile(path)
		if err != nil {
			return fmt.Errorf("open schema %s: %w", path, err)
		}
		if err := compiler.AddResource(uri, strings.NewReader(string(payload))); err != nil {
			return fmt.Errorf("add schema resource %s: %w", path, err)
		}
	}
	for path, payload := range map[string][]byte{artifactPath: artifactPayload, packetPath: packetPayload} {
		compiled, err := compiler.Compile(path)
		if err != nil {
			return fmt.Errorf("compile schema %s: %w", path, err)
		}
		var document any
		if err := json.Unmarshal(payload, &document); err != nil {
			return fmt.Errorf("parse schema document: %w", err)
		}
		if err := compiled.Validate(document); err != nil {
			return fmt.Errorf("schema validation %s: %w", path, err)
		}
	}
	return nil
}

func loadSpec(path string) (fixtureSpec, error) {
	cleanPath := filepath.Clean(path)
	specRoot, err := os.OpenRoot(filepath.Dir(cleanPath))
	if err != nil {
		return fixtureSpec{}, fmt.Errorf("open fixture spec root: %w", err)
	}
	defer func() {
		_ = specRoot.Close()
	}()
	payload, err := specRoot.ReadFile(filepath.Base(cleanPath))
	if err != nil {
		return fixtureSpec{}, fmt.Errorf("read fixture spec: %w", err)
	}
	var spec fixtureSpec
	if err := json.Unmarshal(payload, &spec); err != nil {
		return fixtureSpec{}, fmt.Errorf("parse fixture spec: %w", err)
	}
	if spec.FixtureVersion != "1" || len(spec.Scenarios) != 9 {
		return fixtureSpec{}, fmt.Errorf("fixture spec requires version 1 and exactly nine scenarios")
	}
	seen := map[string]struct{}{}
	for _, scenario := range spec.Scenarios {
		if !safeFixtureScenarioID.MatchString(strings.TrimSpace(scenario.ScenarioID)) || strings.TrimSpace(scenario.PatternID) == "" {
			return fixtureSpec{}, errors.New("fixture scenario id and pattern are required")
		}
		if _, ok := seen[scenario.ScenarioID]; ok {
			return fixtureSpec{}, fmt.Errorf("duplicate fixture scenario %q", scenario.ScenarioID)
		}
		seen[scenario.ScenarioID] = struct{}{}
		switch scenario.Mutation {
		case "none", "excessive_child_authority", "failed_effect_validation", "approval_expiry", "compensation", "supersession":
		default:
			return fixtureSpec{}, fmt.Errorf("fixture scenario %q uses unsupported mutation %q", scenario.ScenarioID, scenario.Mutation)
		}
	}
	wantConsumers := map[string]string{
		"gait": "WRKR_GAIT_ACTION_CONTRACT_CONSUMER",
		"axym": "WRKR_AXYM_ACTION_CONTRACT_CONSUMER",
	}
	if len(spec.ExternalConsumers) != len(wantConsumers) {
		return fixtureSpec{}, errors.New("fixture spec requires exactly the Gait and Axym external consumers")
	}
	for name, commandEnv := range wantConsumers {
		consumer, ok := spec.ExternalConsumers[name]
		if !ok || consumer.CommandEnv != commandEnv || strings.TrimSpace(consumer.Receipt) == "" {
			return fixtureSpec{}, fmt.Errorf("fixture spec has invalid %s consumer contract", name)
		}
	}
	return spec, nil
}

func cleanManifestRoot(value string) (string, error) {
	raw := strings.TrimSpace(value)
	root := strings.Trim(raw, "/")
	if root == "" || strings.Contains(root, `\`) || path.IsAbs(raw) || filepath.IsAbs(raw) || path.Clean(root) != root || root == ".." || strings.HasPrefix(root, "../") {
		return "", fmt.Errorf("manifest root must be a clean repo-relative slash path: %q", value)
	}
	return root, nil
}

func cloneComposition(in risk.ComposedActionPath) (risk.ComposedActionPath, error) {
	payload, err := json.Marshal(in)
	if err != nil {
		return risk.ComposedActionPath{}, err
	}
	var out risk.ComposedActionPath
	if err := json.Unmarshal(payload, &out); err != nil {
		return risk.ComposedActionPath{}, err
	}
	return out, nil
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func sortedConsumerNames(values map[string]consumerSpec) []string {
	out := make([]string, 0, len(values))
	for name := range values {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func sha256Digest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "action-contract-conformance: "+format+"\n", args...)
	os.Exit(1)
}
