package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
	"github.com/Clyra-AI/wrkr/internal/managedmarker"
	"gopkg.in/yaml.v3"
)

type BuildInput struct {
	StatePath   string
	Frameworks  []string
	OutputDir   string
	GeneratedAt time.Time
}

type BuildResult struct {
	OutputDir         string                     `json:"output_dir"`
	Frameworks        []string                   `json:"frameworks"`
	ManifestPath      string                     `json:"manifest_path"`
	ChainPath         string                     `json:"chain_path"`
	FrameworkCoverage map[string]float64         `json:"framework_coverage"`
	ControlEvidence   []ControlEvidence          `json:"control_evidence,omitempty"`
	CoverageNote      CoverageNote               `json:"coverage_note"`
	ReportArtifacts   []string                   `json:"report_artifacts"`
	SourcePrivacy     *sourceprivacy.Contract    `json:"source_privacy,omitempty"`
	RuntimeEvidence   *ingest.Summary            `json:"runtime_evidence,omitempty"`
	AgentActionBOM    *reportcore.AgentActionBOM `json:"agent_action_bom,omitempty"`
}

type ControlEvidence struct {
	ControlID     string   `json:"control_id"`
	BacklogItemID string   `json:"backlog_item_id"`
	AgentID       string   `json:"agent_id,omitempty"`
	Status        string   `json:"status"`
	ExistingProof []string `json:"existing_proof,omitempty"`
	MissingProof  []string `json:"missing_proof,omitempty"`
	RecordIDs     []string `json:"record_ids,omitempty"`
}

type CoverageNote struct {
	Basis              string   `json:"basis"`
	LowCoverageMeans   string   `json:"low_coverage_means"`
	Message            string   `json:"message"`
	RecommendedActions []string `json:"recommended_actions"`
}

const outputDirMarkerFile = ".wrkr-evidence-managed"
const outputDirMarkerContent = "managed by wrkr evidence build\n"
const outputDirMarkerKind = "evidence_output"

type ErrorClass string

const (
	ErrorClassInvalidInput           ErrorClass = "invalid_input"
	ErrorClassRuntimeFailure         ErrorClass = "runtime_failure"
	ErrorClassUnsafeOperationBlocked ErrorClass = "unsafe_operation_blocked"
)

type classifiedError struct {
	class ErrorClass
	err   error
}

func (e *classifiedError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *classifiedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func classifyError(class ErrorClass, err error) error {
	if err == nil {
		return nil
	}
	return &classifiedError{class: class, err: err}
}

func classifyErrorf(class ErrorClass, format string, args ...any) error {
	return &classifiedError{class: class, err: fmt.Errorf(format, args...)}
}

func ClassifyBuildError(err error) ErrorClass {
	var target *classifiedError
	if errors.As(err, &target) {
		return target.class
	}
	return ErrorClassRuntimeFailure
}

type outputDirSafetyError struct {
	message string
}

func (e *outputDirSafetyError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func newOutputDirSafetyError(format string, args ...any) error {
	return &outputDirSafetyError{message: fmt.Sprintf(format, args...)}
}

func isOutputDirSafetyError(err error) bool {
	var target *outputDirSafetyError
	return errors.As(err, &target)
}

func verifyProofChainPrerequisite(statePath string, chainPath string) error {
	var (
		result verifycore.Result
		err    error
	)
	if publicKey, keyErr := proofemit.LoadVerifierKey(statePath); keyErr == nil {
		result, err = verifycore.ChainWithPublicKey(chainPath, publicKey)
	} else {
		result, err = verifycore.Chain(chainPath)
	}
	if err != nil {
		return err
	}
	if result.Intact {
		return nil
	}

	reason := strings.TrimSpace(result.Reason)
	if reason == "" {
		reason = "proof chain is not intact"
	}
	if result.BreakIndex >= 0 {
		if breakPoint := strings.TrimSpace(result.BreakPoint); breakPoint != "" {
			return fmt.Errorf("%s at index %d (%s)", reason, result.BreakIndex, breakPoint)
		}
		return fmt.Errorf("%s at index %d", reason, result.BreakIndex)
	}
	return fmt.Errorf("%s", reason)
}

func Build(in BuildInput) (BuildResult, error) {
	resolvedStatePath := state.ResolvePath(strings.TrimSpace(in.StatePath))
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load state snapshot: %w", err)
	}
	chainPath := proofemit.ChainPath(resolvedStatePath)
	if _, err := os.Stat(chainPath); err != nil {
		if os.IsNotExist(err) {
			return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load proof chain: proof chain file does not exist: %s", chainPath)
		}
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load proof chain: stat chain file: %w", err)
	}
	if err := verifyProofChainPrerequisite(resolvedStatePath, chainPath); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "verify proof chain: %w", err)
	}
	chain, err := proofemit.LoadChain(chainPath)
	if err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load proof chain: %w", err)
	}
	if !hasScanEvidenceRecords(chain.Records) {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load proof chain: proof chain has no scan evidence records")
	}
	frameworks := normalizeFrameworks(in.Frameworks)
	if len(frameworks) == 0 {
		return BuildResult{}, classifyErrorf(ErrorClassInvalidInput, "at least one framework is required")
	}
	if err := validateSnapshot(snapshot); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	complianceSummary, err := compliance.BuildRollupSummary(snapshot.Findings, chain)
	if err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "build compliance summary: %w", err)
	}
	outputDir := strings.TrimSpace(in.OutputDir)
	if outputDir == "" {
		outputDir = "wrkr-evidence"
	}
	targetOutputDir := outputDir
	if err := validateOutputDirTargetWithState(targetOutputDir, resolvedStatePath); err != nil {
		if isOutputDirSafetyError(err) {
			return BuildResult{}, classifyError(ErrorClassUnsafeOperationBlocked, err)
		}
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	stageDir, err := createOutputStageDir(targetOutputDir, resolvedStatePath)
	if err != nil {
		if isOutputDirSafetyError(err) {
			return BuildResult{}, classifyError(ErrorClassUnsafeOperationBlocked, err)
		}
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	stagePublished := false
	defer func() {
		if stagePublished {
			return
		}
		_ = os.RemoveAll(stageDir)
	}()
	outputDir = stageDir

	generatedAt := in.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC().Truncate(time.Second)
	} else {
		generatedAt = generatedAt.UTC().Truncate(time.Second)
	}

	if err := writeJSON(filepath.Join(outputDir, "inventory.json"), snapshot.Inventory); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeYAML(filepath.Join(outputDir, "inventory.yaml"), snapshot.Inventory); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSON(filepath.Join(outputDir, "inventory-snapshot.json"), snapshot.Inventory); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if snapshot.Target.Mode == "my_setup" {
		if err := writeJSON(filepath.Join(outputDir, "personal-inventory-snapshot.json"), map[string]any{
			"target":    snapshot.Target,
			"inventory": snapshot.Inventory,
		}); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
	}
	if err := writeJSON(filepath.Join(outputDir, "risk-report.json"), snapshot.RiskReport); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if snapshot.RiskReport != nil {
		if err := writeJSON(filepath.Join(outputDir, "attack-paths.json"), snapshot.RiskReport.AttackPaths); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
	}
	if err := writeJSON(filepath.Join(outputDir, "profile-compliance.json"), snapshot.Profile); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSON(filepath.Join(outputDir, "compliance-summary.json"), complianceSummary); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	controlEvidence := BuildControlEvidence(snapshot, chain)
	if err := writeJSON(filepath.Join(outputDir, "control-evidence.json"), controlEvidence); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	runtimeEvidence, runtimeBundle, hasRuntimeEvidence, runtimeErr := buildRuntimeEvidence(snapshot, resolvedStatePath)
	if runtimeErr != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load runtime evidence: %w", runtimeErr)
	}
	if hasRuntimeEvidence {
		if err := writeJSON(filepath.Join(outputDir, "runtime-evidence.json"), runtimeBundle); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
		if err := writeJSON(filepath.Join(outputDir, "runtime-evidence-correlation.json"), runtimeEvidence); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
	}
	if err := writeJSON(filepath.Join(outputDir, "posture-score.json"), snapshot.PostureScore); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSON(filepath.Join(outputDir, "scan-metadata.json"), map[string]any{
		"generated_at":   generatedAt.Format(time.RFC3339),
		"frameworks":     frameworks,
		"state_path":     resolvedStatePath,
		"source_privacy": snapshot.SourcePrivacy,
	}); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	reportArtifacts := []string{}
	summary, err := reportcore.BuildSummary(reportcore.BuildInput{
		StatePath:    resolvedStatePath,
		Snapshot:     snapshot,
		Top:          5,
		Template:     reportcore.TemplateAudit,
		ShareProfile: reportcore.ShareProfileInternal,
	})
	if err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "build deterministic report summary: %w", err)
	}
	reportsDir := filepath.Join(outputDir, "reports")
	if err := os.MkdirAll(reportsDir, 0o750); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "mkdir reports dir: %w", err)
	}
	auditReportPath := filepath.Join(reportsDir, "audit-summary.md")
	if err := os.WriteFile(auditReportPath, []byte(reportcore.RenderMarkdown(summary)), 0o600); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "write deterministic report summary: %w", err)
	}
	reportArtifacts = append(reportArtifacts, auditReportPath)
	if summary.AgentActionBOM != nil {
		agentActionBOMPath := filepath.Join(reportsDir, "agent-action-bom.json")
		if err := writeJSON(agentActionBOMPath, summary.AgentActionBOM); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
		reportArtifacts = append(reportArtifacts, agentActionBOMPath)
	}
	mcpCatalog := reportcore.BuildMCPList(snapshot, generatedAt, "", false)
	if len(mcpCatalog.Rows) > 0 {
		if err := writeJSON(filepath.Join(outputDir, "mcp-catalog.json"), mcpCatalog); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
	}

	proofRecordsDir := filepath.Join(outputDir, "proof-records")
	if err := os.MkdirAll(proofRecordsDir, 0o750); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "mkdir proof-records dir: %w", err)
	}
	if err := writeJSON(filepath.Join(proofRecordsDir, "chain.json"), chain); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "scan-findings.jsonl"), filterRecords(chain.Records, "scan_finding", "")); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "risk-assessments.jsonl"), filterRecords(chain.Records, "risk_assessment", "")); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "approvals.jsonl"), filterRecords(chain.Records, "approval", "")); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	if err := writeJSONL(filepath.Join(proofRecordsDir, "lifecycle-transitions.jsonl"), filterRecords(chain.Records, "decision", "lifecycle_transition")); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}

	mappingsDir := filepath.Join(outputDir, "mappings")
	gapsDir := filepath.Join(outputDir, "gaps")
	if err := os.MkdirAll(mappingsDir, 0o750); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "mkdir mappings dir: %w", err)
	}
	if err := os.MkdirAll(gapsDir, 0o750); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "mkdir gaps dir: %w", err)
	}

	coverage := map[string]float64{}
	for _, frameworkID := range frameworks {
		framework, err := proof.LoadFramework(frameworkID)
		if err != nil {
			return BuildResult{}, classifyErrorf(ErrorClassInvalidInput, "load framework %s: %w", frameworkID, err)
		}
		result, err := compliance.Evaluate(compliance.Input{Framework: framework, Chain: chain})
		if err != nil {
			return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "evaluate framework %s: %w", frameworkID, err)
		}
		coverage[frameworkID] = result.Coverage
		if err := writeJSON(filepath.Join(mappingsDir, frameworkID+".json"), result); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
		if err := writeJSON(filepath.Join(gapsDir, frameworkID+".json"), map[string]any{
			"framework_id":     result.FrameworkID,
			"coverage_percent": result.Coverage,
			"gaps":             result.Gaps,
		}); err != nil {
			return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
		}
	}

	signingKeyPath := proofemit.SigningKeyPath(resolvedStatePath)
	if !proofemit.HasEnvSigningKey() {
		if _, err := os.Stat(signingKeyPath); err != nil {
			if os.IsNotExist(err) {
				return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load signing material: signing key file does not exist: %s", signingKeyPath)
			}
			return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load signing material: stat signing key file: %w", err)
		}
	}
	signingMaterial, signingErr := proofemit.LoadSigningMaterial(resolvedStatePath)
	if signingErr != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "load signing material: %w", signingErr)
	}
	if err := os.MkdirAll(filepath.Join(outputDir, "signatures"), 0o750); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "mkdir signatures dir: %w", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(signingMaterial.Public)
	if err := os.WriteFile(filepath.Join(outputDir, "signatures", "public-key.base64"), []byte(publicKeyBase64+"\n"), 0o600); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "write public key: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "signatures", "key-id.txt"), []byte(strings.TrimSpace(signingMaterial.KeyID)+"\n"), 0o600); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "write key id: %w", err)
	}

	entries, err := buildManifestEntries(outputDir)
	if err != nil {
		if isOutputDirSafetyError(err) {
			return BuildResult{}, classifyError(ErrorClassUnsafeOperationBlocked, err)
		}
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}
	manifest := proof.BundleManifest{
		Files:  entries,
		AlgoID: "sha256",
		SaltID: "wrkr-evidence-v1",
	}
	if err := writeJSON(filepath.Join(outputDir, "manifest.json"), manifest); err != nil {
		return BuildResult{}, classifyError(ErrorClassRuntimeFailure, err)
	}

	if _, err := proof.SignBundleFile(outputDir, signingMaterial); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "sign bundle manifest: %w", err)
	}
	if _, err := proof.VerifyBundle(outputDir, proof.BundleVerifyOpts{}); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "verify bundle integrity: %w", err)
	}
	if err := publishStagedOutput(stageDir, targetOutputDir); err != nil {
		return BuildResult{}, classifyErrorf(ErrorClassRuntimeFailure, "publish evidence bundle: %w", err)
	}
	stagePublished = true
	reportArtifacts = rebaseArtifactPaths(reportArtifacts, stageDir, targetOutputDir)

	return BuildResult{
		OutputDir:         targetOutputDir,
		Frameworks:        frameworks,
		ManifestPath:      filepath.Join(targetOutputDir, "manifest.json"),
		ChainPath:         chainPath,
		FrameworkCoverage: coverage,
		ControlEvidence:   controlEvidence,
		CoverageNote:      defaultCoverageNote(),
		ReportArtifacts:   reportArtifacts,
		SourcePrivacy:     snapshot.SourcePrivacy,
		RuntimeEvidence:   runtimeEvidence,
		AgentActionBOM:    summary.AgentActionBOM,
	}, nil
}

func buildRuntimeEvidence(snapshot state.Snapshot, statePath string) (*ingest.Summary, ingest.Bundle, bool, error) {
	bundle, artifactPath, err := ingest.LoadOptional(statePath)
	if err != nil {
		return nil, ingest.Bundle{}, false, err
	}
	if strings.TrimSpace(artifactPath) == "" {
		return nil, ingest.Bundle{}, false, nil
	}
	summary := ingest.Correlate(snapshot, artifactPath, bundle)
	return &summary, bundle, true, nil
}

func defaultCoverageNote() CoverageNote {
	return CoverageNote{
		Basis:            "evidenced_controls_only",
		LowCoverageMeans: "evidence_gap",
		Message:          "framework_coverage reflects only controls evidenced in the current scanned state; low or zero first-run coverage indicates evidence gaps rather than unsupported framework parsing.",
		RecommendedActions: []string{
			"Run wrkr report --top 5 --json to prioritize missing controls and approvals.",
			"Remediate the highest-priority gaps and rerun wrkr scan, wrkr evidence, and wrkr report with the same deterministic inputs.",
		},
	}
}

func BuildControlEvidence(snapshot state.Snapshot, chain *proof.Chain) []ControlEvidence {
	statuses := reportcore.BuildControlProofStatus(snapshot, chain)
	if len(statuses) == 0 {
		return nil
	}
	out := make([]ControlEvidence, 0, len(statuses))
	for _, item := range statuses {
		out = append(out, ControlEvidence{
			ControlID:     strings.TrimSpace(item.ControlID),
			BacklogItemID: strings.TrimSpace(item.BacklogItemID),
			AgentID:       strings.TrimSpace(item.AgentID),
			Status:        strings.TrimSpace(item.Status),
			ExistingProof: append([]string(nil), item.ExistingProof...),
			MissingProof:  append([]string(nil), item.MissingProof...),
			RecordIDs:     append([]string(nil), item.RecordIDs...),
		})
	}
	return out
}

func normalizeFrameworks(in []string) []string {
	set := map[string]struct{}{}
	for _, value := range in {
		for _, part := range strings.Split(value, ",") {
			trimmed := normalizeFrameworkID(part)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeFrameworkID(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return ""
	}
	replacer := strings.NewReplacer("_", "-", " ", "-", "eu-ai-act", "eu-ai-act", "pci-dss", "pci-dss")
	trimmed = replacer.Replace(trimmed)
	switch trimmed {
	case "euaiact":
		return "eu-ai-act"
	case "pcidss":
		return "pci-dss"
	default:
		return trimmed
	}
}

func validateSnapshot(snapshot state.Snapshot) error {
	missing := make([]string, 0, 4)
	if snapshot.Inventory == nil {
		missing = append(missing, "inventory")
	}
	if snapshot.RiskReport == nil {
		missing = append(missing, "risk_report")
	}
	if snapshot.Profile == nil {
		missing = append(missing, "profile")
	}
	if snapshot.PostureScore == nil {
		missing = append(missing, "posture_score")
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("load state snapshot: missing required sections: %s", strings.Join(missing, ", "))
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir json dir: %w", err)
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeYAML(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir yaml dir: %w", err)
	}
	payload, err := yaml.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeJSONL(path string, records []proof.Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir jsonl dir: %w", err)
	}
	file, err := os.Create(path) // #nosec G304 -- path is a deterministic local evidence output path assembled by wrkr.
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()
	writer := bufio.NewWriter(file)
	for _, record := range records {
		payload, err := json.Marshal(record)
		if err != nil {
			return fmt.Errorf("marshal jsonl record: %w", err)
		}
		if _, err := writer.Write(payload); err != nil {
			return fmt.Errorf("write jsonl record: %w", err)
		}
		if err := writer.WriteByte('\n'); err != nil {
			return fmt.Errorf("write jsonl newline: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush jsonl writer: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func writeOutputDirMarker(statePath string, path string, targetPath string) error {
	markerPath := filepath.Join(path, outputDirMarkerFile)
	payload, err := managedmarker.BuildPayload(statePath, targetPath, outputDirMarkerKind)
	if err != nil {
		return fmt.Errorf("build output dir marker: %w", err)
	}
	if err := os.WriteFile(markerPath, payload, 0o600); err != nil {
		return fmt.Errorf("write output dir marker: %w", err)
	}
	return nil
}

func filterRecords(records []proof.Record, recordType string, eventType string) []proof.Record {
	out := make([]proof.Record, 0)
	for _, record := range records {
		if strings.TrimSpace(record.RecordType) != strings.TrimSpace(recordType) {
			continue
		}
		if strings.TrimSpace(eventType) != "" {
			value, _ := record.Event["event_type"].(string)
			if strings.TrimSpace(value) != strings.TrimSpace(eventType) {
				continue
			}
		}
		out = append(out, record)
	}
	return out
}

func hasScanEvidenceRecords(records []proof.Record) bool {
	for _, record := range records {
		recordType := strings.TrimSpace(record.RecordType)
		if recordType == "scan_finding" || recordType == "risk_assessment" {
			return true
		}
	}
	return false
}

func rebaseArtifactPaths(paths []string, fromRoot string, toRoot string) []string {
	if len(paths) == 0 {
		return nil
	}
	rebased := make([]string, 0, len(paths))
	for _, rawPath := range paths {
		rel, err := filepath.Rel(fromRoot, rawPath)
		if err != nil {
			rebased = append(rebased, rawPath)
			continue
		}
		rebased = append(rebased, filepath.Join(toRoot, rel))
	}
	return rebased
}

func buildManifestEntries(outputDir string) ([]proof.BundleManifestEntry, error) {
	entries := make([]proof.BundleManifestEntry, 0)
	err := filepath.WalkDir(outputDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(outputDir, path)
		if err != nil {
			return err
		}
		normalized := filepath.ToSlash(rel)
		if normalized == "manifest.json" || normalized == outputDirMarkerFile {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return newOutputDirSafetyError("manifest entry is not a regular file: %s", normalized)
		}
		payload, err := os.ReadFile(path) // #nosec G304 -- walk only reads files under deterministic output directory.
		if err != nil {
			return err
		}
		sum := sha256.Sum256(payload)
		entries = append(entries, proof.BundleManifestEntry{Path: normalized, SHA256: "sha256:" + hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("build bundle manifest: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return entries, nil
}
